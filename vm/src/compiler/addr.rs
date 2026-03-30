use crate::{compiler::word::Word, primitives::consts::ADDR_SIZE};
use anyhow::{bail, Result};
use arrayref::array_ref;
use itertools::Itertools;
use p3_air::AirBuilder;
use p3_field::{Field, FieldAlgebra};
use serde::{Deserialize, Serialize};
use std::{
    array::IntoIter,
    convert::TryFrom,
    ops::{Index, IndexMut},
};

#[inline(always)]
pub fn try_u64_to_48bit_addr_limbs(value: u64) -> Result<[u16; 3]> {
    if value >> 48 != 0 {
        bail!("value exceeds 48-bit address range: {value}");
    }
    Ok([
        (value & 0xFFFF) as u16,
        ((value >> 16) & 0xFFFF) as u16,
        ((value >> 32) & 0xFFFF) as u16,
    ])
}

#[inline(always)]
pub fn encode_proof_addr_to_u32_limbs_48(value: u64, context: &str) -> [u32; 3] {
    let limbs = try_u64_to_48bit_addr_limbs(value).unwrap_or_else(|_| {
        panic!("{context} 0x{value:016x} exceeds the frozen 48-bit proof address contract")
    });
    limbs.map(u32::from)
}

/// A 48-bit address represented as 3 u16 limbs.
/// Each limb is 16 bits: limb[0] + limb[1]*2^16 + limb[2]*2^32 = 48-bit address
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(C)]
pub struct Addr<T>(pub [T; ADDR_SIZE]);

impl<T> Addr<T> {
    /// Applies `f` to each element of the address.
    pub fn map<F, S>(self, f: F) -> Addr<S>
    where
        F: FnMut(T) -> S,
    {
        Addr(self.0.map(f))
    }

    /// Returns the internal array.
    pub fn as_array(&self) -> &[T; ADDR_SIZE] {
        &self.0
    }

    /// Extends a variable to an address.
    pub fn extend_var<AB: AirBuilder<Var = T>>(var: T) -> Addr<AB::Expr> {
        Addr([AB::Expr::ZERO + var, AB::Expr::ZERO, AB::Expr::ZERO])
    }
}

impl<T: FieldAlgebra> Addr<T> {
    /// Extends a variable to an address.
    pub fn extend_expr<AB: AirBuilder<Expr = T>>(expr: T) -> Addr<AB::Expr> {
        Addr([AB::Expr::ZERO + expr, AB::Expr::ZERO, AB::Expr::ZERO])
    }

    /// Returns an address with all zero expressions.
    #[must_use]
    pub fn zero<AB: AirBuilder<Expr = T>>() -> Addr<T> {
        Addr([AB::Expr::ZERO, AB::Expr::ZERO, AB::Expr::ZERO])
    }
}

impl<T: Field> Addr<T> {
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(T::is_zero)
    }
}

impl<F: Field> Addr<F> {
    /// Converts an address to a u32.
    /// Only uses the lower 32 bits (limbs 0 and 1).
    pub fn to_u32(&self) -> u32 {
        let limbs: [u16; 2] = [
            self.0[0].to_string().parse::<u16>().unwrap(),
            self.0[1].to_string().parse::<u16>().unwrap(),
        ];
        u32::from(limbs[0]) | (u32::from(limbs[1]) << 16)
    }

    /// Converts an address to a u64.
    /// Assumes the address is stored as 3 u16 limbs (little-endian).
    pub fn to_u64(&self) -> u64 {
        let limbs: [u16; 3] = [
            self.0[0].to_string().parse::<u16>().unwrap(),
            self.0[1].to_string().parse::<u16>().unwrap(),
            self.0[2].to_string().parse::<u16>().unwrap(),
        ];
        u64::from(limbs[0]) | (u64::from(limbs[1]) << 16) | (u64::from(limbs[2]) << 32)
    }
}

impl Addr<u8> {
    pub fn bytes_to_u32(&self) -> u32 {
        u32::from_le_bytes([self.0[0], self.0[1], self.0[2], 0])
    }

    pub fn from_u32(value: u32) -> Self {
        let low = (value & 0xFFFF) as u8;
        let high = (value >> 16) as u8;
        Addr([low, high, 0])
    }

    pub fn try_from_u64(value: u64) -> Result<Self> {
        let [limb0, limb1, limb2] = try_u64_to_48bit_addr_limbs(value)?;
        Ok(Addr([limb0 as u8, limb1 as u8, limb2 as u8]))
    }
}

impl<V: Copy> Addr<V> {
    /// Reduces an address to a single variable.
    /// Uses 3×16-bit limbs: [1, 2^16, 2^32]
    pub fn reduce<AB: AirBuilder<Var = V>>(&self) -> AB::Expr {
        let base = [1u64, 1 << 16, 1 << 32].map(AB::Expr::from_wrapped_u64);
        self.0
            .iter()
            .enumerate()
            .map(|(i, x)| base[i].clone() * *x)
            .sum()
    }

    /// Prove that self + increment = result (e.g., pc + 4 = next_pc)
    pub fn add_limb<AB>(
        &self,
        builder: &mut AB,
        condition: AB::Expr,
        increment: AB::Expr,
        result: Self,
    ) where
        AB: AirBuilder,
        V: Into<AB::Expr>,
    {
        let base_inverse = AB::F::from_canonical_u32(1 << 16).inverse();

        let mut carry = AB::Expr::ZERO;

        for i in 0..4 {
            let lhs: AB::Expr = if i < 3 {
                self[i].into()
            } else {
                AB::Expr::ZERO
            };
            let rhs: AB::Expr = if i < 3 {
                result[i].into()
            } else {
                AB::Expr::ZERO
            };
            let inc = if i == 0 {
                increment.clone()
            } else {
                AB::Expr::ZERO
            };

            carry = (carry.clone() + lhs + inc - rhs) * base_inverse;

            builder.when(condition.clone()).assert_bool(carry.clone());
        }

        builder.when(condition).assert_zero(carry);
    }

    /// Prove that self + increment = result using carry witness columns.
    ///
    /// Unlike `add_limb`, this method uses pre-computed carry columns (Var, degree 1)
    /// instead of algebraic carry expressions (Expr, degree grows). This reduces the
    /// max constraint degree from `deg(condition) + 2` to `deg(condition) + 1`.
    ///
    /// **Caller must** constrain carry columns as boolean (e.g., unconditional `assert_bool`).
    pub fn add_limb_with_carry<AB>(
        &self,
        builder: &mut AB,
        condition: AB::Expr,
        increment: AB::Expr,
        result: Self,
        carry_cols: &[AB::Var],
    ) where
        AB: AirBuilder,
        V: Into<AB::Expr>,
    {
        let base = AB::Expr::from_canonical_u32(1 << 16);

        let mut prev_carry: AB::Expr = AB::Expr::ZERO;

        for i in 0..4 {
            let lhs: AB::Expr = if i < 3 {
                self[i].into()
            } else {
                AB::Expr::ZERO
            };
            let rhs: AB::Expr = if i < 3 {
                result[i].into()
            } else {
                AB::Expr::ZERO
            };
            let inc = if i == 0 {
                increment.clone()
            } else {
                AB::Expr::ZERO
            };

            // carry_cols[i] * base == prev_carry + lhs + inc - rhs
            builder.when(condition.clone()).assert_eq(
                AB::Expr::ZERO + carry_cols[i] * base.clone(),
                prev_carry.clone() + lhs + inc - rhs,
            );

            prev_carry = carry_cols[i].into();
        }

        builder.when(condition).assert_zero(prev_carry);
    }
}

impl<T> Index<usize> for Addr<T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<T> IndexMut<usize> for Addr<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl<F: FieldAlgebra> From<u32> for Addr<F> {
    fn from(value: u32) -> Self {
        let low = (value & 0xFFFF) as u16;
        let high = (value >> 16) as u16;
        Addr([
            F::from_canonical_u16(low),
            F::from_canonical_u16(high),
            F::ZERO,
        ])
    }
}

impl<F: FieldAlgebra> TryFrom<u64> for Addr<F> {
    type Error = anyhow::Error;

    fn try_from(value: u64) -> Result<Self> {
        let [limb0, limb1, limb2] = try_u64_to_48bit_addr_limbs(value)?;
        Ok(Addr([
            F::from_canonical_u16(limb0),
            F::from_canonical_u16(limb1),
            F::from_canonical_u16(limb2),
        ]))
    }
}

impl<T> IntoIterator for Addr<T> {
    type Item = T;
    type IntoIter = IntoIter<T, ADDR_SIZE>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T: Clone> FromIterator<T> for Addr<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let elements = iter.into_iter().take(ADDR_SIZE).collect_vec();

        Addr(array_ref![elements, 0, ADDR_SIZE].clone())
    }
}

/// Convert Addr to Word (zero-extends to 64-bit)
impl<F: FieldAlgebra> From<Addr<F>> for Word<F> {
    fn from(addr: Addr<F>) -> Self {
        Word([addr[0].clone(), addr[1].clone(), addr[2].clone(), F::ZERO])
    }
}
