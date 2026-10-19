use crate::{compiler::word::Word, primitives::consts::ADDR_SIZE};
use anyhow::{bail, Result};
use arrayref::array_ref;
use itertools::Itertools;
use p3_air::AirBuilder;
use p3_field::{Field, PrimeCharacteristicRing};
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

impl<T: PrimeCharacteristicRing> Addr<T> {
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
        let base = [1u64, 1 << 16, 1 << 32].map(AB::Expr::from_u64);
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
        AB::F: Field,
        V: Into<AB::Expr>,
    {
        let base_inverse = AB::F::from_u32(1 << 16).inverse();

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

    /// Prove that self + increment = result using a single carry witness column.
    ///
    /// Unlike `add_limb`, this uses a pre-computed carry column (Var, degree 1) instead of an
    /// algebraic carry expression (Expr, degree grows), which keeps the max constraint degree at
    /// `deg(condition) + 1`.
    ///
    /// Only the *first* limb needs a witness. `increment` is small and a guest address stays
    /// below `0x7800_0000` (the disassembler rejects anything else, see
    /// `riscv/disassembler/elf.rs`), so limb 1 is at most `0x77FF` and absorbing the carry out
    /// of limb 0 cannot make it overflow; limb 2 is zero on both sides. Both of those are
    /// therefore plain equalities, which also means a prover has no witness to lie with.
    ///
    /// Nothing here constrains the carry column's value. **The caller must** pin it to `{0, 1}`
    /// on every row where `condition` is non-zero, by a boolean constraint or by a lookup that
    /// fixes its value (the Cpu chip's `pc_carry` is pinned to the Program table's
    /// `[pc[0] >= 0xFFFC]` by the Program lookup, `riscv_cpu/constraints.rs`).
    pub fn add_limb_with_carry<AB>(
        &self,
        builder: &mut AB,
        condition: AB::Expr,
        increment: AB::Expr,
        result: Self,
        carry: AB::Var,
    ) where
        AB: AirBuilder,
        V: Into<AB::Expr>,
    {
        let base = AB::Expr::from_u32(1 << 16);

        // carry * 2^16 == self[0] + increment - result[0]
        builder.when(condition.clone()).assert_eq(
            AB::Expr::ZERO + carry * base,
            self[0].into() + increment - result[0].into(),
        );

        // result[1] == self[1] + carry, and result[2] == self[2]: no carry can leave either.
        builder
            .when(condition.clone())
            .assert_eq(result[1].into(), self[1].into() + carry);
        builder
            .when(condition)
            .assert_eq(result[2].into(), self[2].into());
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

impl<F: PrimeCharacteristicRing> From<u32> for Addr<F> {
    fn from(value: u32) -> Self {
        let low = (value & 0xFFFF) as u16;
        let high = (value >> 16) as u16;
        Addr([F::from_u16(low), F::from_u16(high), F::ZERO])
    }
}

impl<F: PrimeCharacteristicRing> TryFrom<u64> for Addr<F> {
    type Error = anyhow::Error;

    fn try_from(value: u64) -> Result<Self> {
        let [limb0, limb1, limb2] = try_u64_to_48bit_addr_limbs(value)?;
        Ok(Addr([
            F::from_u16(limb0),
            F::from_u16(limb1),
            F::from_u16(limb2),
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
impl<F: PrimeCharacteristicRing> From<Addr<F>> for Word<F> {
    fn from(addr: Addr<F>) -> Self {
        Word([addr[0].clone(), addr[1].clone(), addr[2].clone(), F::ZERO])
    }
}

/// The number of u16 limbs in a program counter.
pub const PC_SIZE: usize = 2;

/// A program counter as 2 u16 limbs: `limb[0] + limb[1] * 2^16`.
///
/// A guest address stays below `0x7800_0000` (the disassembler rejects anything else, see
/// `riscv/disassembler/elf.rs`), so a pc fits in two limbs; the third limb an [`Addr`] carries
/// is identically zero on every pc and is not materialized. `Addr` remains the type of a memory
/// address.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(C)]
pub struct Pc<T>(pub [T; PC_SIZE]);

impl<V: Copy> Pc<V> {
    /// Reduces a pc to a single expression: `limb[0] + limb[1] * 2^16`.
    ///
    /// Exact as an integer: both limbs are canonical u16 values (the Program table pins them),
    /// so the sum stays below `2^32 < p`.
    pub fn reduce<AB: AirBuilder<Var = V>>(&self) -> AB::Expr {
        let base = [1u64, 1 << 16].map(AB::Expr::from_u64);
        self.0
            .iter()
            .enumerate()
            .map(|(i, x)| base[i].clone() * *x)
            .sum()
    }

    /// Prove that `self + increment = result` for a 3-limb `result` (a jump row's return address
    /// `pc + 4 = op_a`), using a single carry witness column.
    ///
    /// Same argument as [`Addr::add_limb_with_carry`]: only limb 0 can carry, limb 1 absorbs it
    /// without overflowing, and since a pc has no limb 2 the result's limb 2 is pinned to zero
    /// (where the `Addr` version pins it to `self[2]`).
    ///
    /// Nothing here constrains the carry column's value. **The caller must** pin it to `{0, 1}`
    /// on every row where `condition` is non-zero, by a boolean constraint or by a lookup that
    /// fixes its value (the Cpu chip's `pc_carry` is pinned to the Program table's
    /// `[pc[0] >= 0xFFFC]` by the Program lookup, `riscv_cpu/constraints.rs`).
    pub fn add_limb_with_carry<AB>(
        &self,
        builder: &mut AB,
        condition: AB::Expr,
        increment: AB::Expr,
        result: Addr<V>,
        carry: AB::Var,
    ) where
        AB: AirBuilder,
        V: Into<AB::Expr>,
    {
        let base = AB::Expr::from_u32(1 << 16);

        // carry * 2^16 == self[0] + increment - result[0]
        builder.when(condition.clone()).assert_eq(
            AB::Expr::ZERO + carry * base,
            self[0].into() + increment - result[0].into(),
        );

        // result[1] == self[1] + carry, and result[2] == 0: no carry can leave either.
        builder
            .when(condition.clone())
            .assert_eq(result[1].into(), self[1].into() + carry);
        builder.when(condition).assert_zero(result[2].into());
    }
}

impl<T> Index<usize> for Pc<T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<T> IndexMut<usize> for Pc<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl<F: PrimeCharacteristicRing> TryFrom<u64> for Pc<F> {
    type Error = anyhow::Error;

    fn try_from(value: u64) -> Result<Self> {
        if value >> 32 != 0 {
            bail!("pc exceeds the 32-bit program counter range: {value:#x}");
        }
        Ok(Pc([
            F::from_u16((value & 0xFFFF) as u16),
            F::from_u16((value >> 16) as u16),
        ]))
    }
}

impl<T> IntoIterator for Pc<T> {
    type Item = T;
    type IntoIter = IntoIter<T, PC_SIZE>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::{encode_proof_addr_to_u32_limbs_48, try_u64_to_48bit_addr_limbs, Pc};
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    #[test]
    fn pc_try_from_splits_a_guest_address_into_two_limbs() {
        let pc = Pc::<KoalaBear>::try_from(0x77FF_FFFC).unwrap();
        assert_eq!(
            pc.0,
            [KoalaBear::from_u16(0xFFFC), KoalaBear::from_u16(0x77FF)]
        );
    }

    #[test]
    fn pc_try_from_rejects_values_that_need_a_third_limb() {
        assert!(Pc::<KoalaBear>::try_from(1u64 << 32).is_err());
    }

    #[test]
    fn try_u64_to_48bit_addr_limbs_accepts_max_48_bit_value() {
        assert_eq!(
            try_u64_to_48bit_addr_limbs(0xFFFF_FFFF_FFFF).unwrap(),
            [0xFFFF, 0xFFFF, 0xFFFF]
        );
    }

    #[test]
    fn encode_proof_addr_to_u32_limbs_48_accepts_three_limb_address() {
        assert_eq!(
            encode_proof_addr_to_u32_limbs_48(0x0000_ABCD_1234_5678, "test proof address"),
            [0x5678, 0x1234, 0xABCD]
        );
    }

    #[test]
    #[should_panic(expected = "frozen 48-bit proof address contract")]
    fn encode_proof_addr_to_u32_limbs_48_rejects_high_bits() {
        let _ = encode_proof_addr_to_u32_limbs_48(1u64 << 48, "test proof address");
    }
}
