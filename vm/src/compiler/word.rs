use crate::primitives::consts::WORD_SIZE;
use arrayref::array_ref;
use itertools::Itertools;
use p3_air::AirBuilder;
use p3_field::{Field, FieldAlgebra};
use serde::{Deserialize, Serialize};
use std::{
    array::IntoIter,
    ops::{Index, IndexMut},
};

/// A word to represent a 64-bit value including 4 u16 limbs
/// Each limb is 16 bits: limb[0] + limb[1]*2^16 + limb[2]*2^32 + limb[3]*2^48 = u64
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(C)]
pub struct Word<T>(pub [T; WORD_SIZE]);

impl<T> Word<T> {
    /// Applies `f` to each element of the word.
    pub fn map<F, S>(self, f: F) -> Word<S>
    where
        F: FnMut(T) -> S,
    {
        Word(self.0.map(f))
    }

    /// Extends a variable to a word.
    pub fn extend_var<AB: AirBuilder<Var = T>>(var: T) -> Word<AB::Expr> {
        Word([
            AB::Expr::ZERO + var,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
        ])
    }

    /// Extends a half word (2 limbs) to a full word (4 limbs).
    pub fn extend_half<AB: AirBuilder<Var = T>>(half: &[T; 2]) -> Word<AB::Expr>
    where
        T: Clone,
    {
        Word([
            AB::Expr::ZERO + half[0].clone(),
            AB::Expr::ZERO + half[1].clone(),
            AB::Expr::ZERO,
            AB::Expr::ZERO,
        ])
    }
}

impl<T: FieldAlgebra> Word<T> {
    /// Extends a variable to a word.
    pub fn extend_expr<AB: AirBuilder<Expr = T>>(expr: T) -> Word<AB::Expr> {
        Word([
            AB::Expr::ZERO + expr,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
        ])
    }

    /// Returns a word with all zero expressions.
    #[must_use]
    pub fn zero<AB: AirBuilder<Expr = T>>() -> Word<T> {
        Word([
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
            AB::Expr::ZERO,
        ])
    }
}

impl<T: Field> Word<T> {
    pub fn is_zero(&self) -> bool {
        self.0.iter().all(T::is_zero)
    }
}

impl<F: Field> Word<F> {
    /// Converts a word to a u32.
    pub fn to_u32(&self) -> u32 {
        u32::from_le_bytes(self.0.map(|x| x.to_string().parse::<u8>().unwrap()))
    }

    /// Converts a word to a u64.
    /// Assumes the word is stored as 4 u16 limbs (little-endian).
    pub fn to_u64(&self) -> u64 {
        let limbs: [u16; 4] = [
            self.0[0].to_string().parse::<u16>().unwrap(),
            self.0[1].to_string().parse::<u16>().unwrap(),
            self.0[2].to_string().parse::<u16>().unwrap(),
            self.0[3].to_string().parse::<u16>().unwrap(),
        ];
        u64::from(limbs[0])
            | (u64::from(limbs[1]) << 16)
            | (u64::from(limbs[2]) << 32)
            | (u64::from(limbs[3]) << 48)
    }
}

impl Word<u8> {
    pub fn bytes_to_u32(&self) -> u32 {
        u32::from_le_bytes(self.0)
    }

    pub fn from_u32(value: u32) -> Self {
        let low = (value & 0xFFFF) as u8;
        let high = (value >> 16) as u8;
        Word([low, high, 0, 0])
    }

    pub fn from_u64(value: u64) -> Self {
        let limb0 = (value & 0xFFFF) as u8;
        let limb1 = ((value >> 16) & 0xFFFF) as u8;
        let limb2 = ((value >> 32) & 0xFFFF) as u8;
        let limb3 = ((value >> 48) & 0xFFFF) as u8;
        Word([limb0, limb1, limb2, limb3])
    }
}

impl<V: Copy> Word<V> {
    /// Reduces a word to a single variable.
    /// Uses 4×16-bit limbs: [1, 2^16, 2^32, 2^48]
    pub fn reduce<AB: AirBuilder<Var = V>>(&self) -> AB::Expr {
        let base = [1u64, 1 << 16, 1 << 32, 1 << 48].map(AB::Expr::from_wrapped_u64);
        self.0
            .iter()
            .enumerate()
            .map(|(i, x)| base[i].clone() * *x)
            .sum()
    }
}

impl<V: Clone> Word<V> {
    /// Prove that self + increment = result.
    /// For Word (4 limbs × 16 bits = 64 bits)
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

        for i in 0..5 {
            // 5 limbs (check overflow at i=4)
            let lhs: AB::Expr = if i < 4 {
                self[i].clone().into()
            } else {
                AB::Expr::ZERO
            };
            let rhs: AB::Expr = if i < 4 {
                result[i].clone().into()
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
    /// instead of algebraic carry expressions. Max degree = `deg(condition) + 1`.
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

        for i in 0..5 {
            let lhs: AB::Expr = if i < 4 {
                self[i].clone().into()
            } else {
                AB::Expr::ZERO
            };
            let rhs: AB::Expr = if i < 4 {
                result[i].clone().into()
            } else {
                AB::Expr::ZERO
            };
            let inc = if i == 0 {
                increment.clone()
            } else {
                AB::Expr::ZERO
            };

            builder.when(condition.clone()).assert_eq(
                AB::Expr::ZERO + carry_cols[i] * base.clone(),
                prev_carry.clone() + lhs + inc - rhs,
            );

            prev_carry = carry_cols[i].into();
        }

        builder.when(condition).assert_zero(prev_carry);
    }
}

impl<T> Index<usize> for Word<T> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<T> IndexMut<usize> for Word<T> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl<F: FieldAlgebra> From<u32> for Word<F> {
    fn from(value: u32) -> Self {
        let low = (value & 0xFFFF) as u16;
        let high = (value >> 16) as u16;
        Word([
            F::from_canonical_u16(low),
            F::from_canonical_u16(high),
            F::ZERO,
            F::ZERO,
        ])
    }
}

impl<F: FieldAlgebra> From<i32> for Word<F> {
    fn from(value: i32) -> Self {
        Word((value as u32).to_le_bytes().map(F::from_canonical_u8))
    }
}

impl<F: FieldAlgebra> From<u64> for Word<F> {
    fn from(value: u64) -> Self {
        Word([
            F::from_canonical_u16((value & 0xFFFF) as u16),
            F::from_canonical_u16((value >> 16) as u16),
            F::from_canonical_u16((value >> 32) as u16),
            F::from_canonical_u16((value >> 48) as u16),
        ])
    }
}

impl<T> IntoIterator for Word<T> {
    type Item = T;
    type IntoIter = IntoIter<T, WORD_SIZE>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<T: Clone> FromIterator<T> for Word<T> {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let elements = iter.into_iter().take(WORD_SIZE).collect_vec();

        Word(array_ref![elements, 0, WORD_SIZE].clone())
    }
}
