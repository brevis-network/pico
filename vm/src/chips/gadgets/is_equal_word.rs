//! A gadget to check if the input words are equal.

use crate::{
    chips::gadgets::is_zero_word::IsZeroWordGadget, compiler::word::Word,
    machine::builder::ChipBuilder,
};
use p3_field::Field;
use pico_derive::AlignedBorrow;

/// A set of columns needed to compute the equality of two words.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct IsEqualWordGadget<T> {
    /// A gadget to check whether the differences in limbs are all 0 (i.e., `a[0] - b[0]`,
    /// `a[1] - b[1]`, `a[2] - b[2]`, `a[3] - b[3]]`). The result of `IsEqualWordGadget` is
    /// `is_diff_zero.result`.
    pub is_diff_zero: IsZeroWordGadget<T>,
}

impl<F: Field> IsEqualWordGadget<F> {
    pub fn populate(&mut self, a_u64: u64, b_u64: u64) -> u64 {
        // Convert u64 to 4 u16 limbs (matching Word<u64> implementation)
        let a_limbs = [
            (a_u64 & 0xFFFF) as u16,
            ((a_u64 >> 16) & 0xFFFF) as u16,
            ((a_u64 >> 32) & 0xFFFF) as u16,
            ((a_u64 >> 48) & 0xFFFF) as u16,
        ];
        let b_limbs = [
            (b_u64 & 0xFFFF) as u16,
            ((b_u64 >> 16) & 0xFFFF) as u16,
            ((b_u64 >> 32) & 0xFFFF) as u16,
            ((b_u64 >> 48) & 0xFFFF) as u16,
        ];
        let diff = Word([
            F::from_canonical_u16(a_limbs[0]) - F::from_canonical_u16(b_limbs[0]),
            F::from_canonical_u16(a_limbs[1]) - F::from_canonical_u16(b_limbs[1]),
            F::from_canonical_u16(a_limbs[2]) - F::from_canonical_u16(b_limbs[2]),
            F::from_canonical_u16(a_limbs[3]) - F::from_canonical_u16(b_limbs[3]),
        ]);
        self.is_diff_zero.populate_from_field_element(diff);
        (a_u64 == b_u64) as u64
    }

    pub fn eval<CB: ChipBuilder<F>>(
        builder: &mut CB,
        a: Word<CB::Expr>,
        b: Word<CB::Expr>,
        cols: IsEqualWordGadget<CB::Var>,
        is_real: CB::Expr,
    ) {
        builder.assert_bool(is_real.clone());

        // Calculate differences in limbs.
        let diff = Word([
            a[0].clone() - b[0].clone(),
            a[1].clone() - b[1].clone(),
            a[2].clone() - b[2].clone(),
            a[3].clone() - b[3].clone(),
        ]);

        // Check if the difference is 0.
        IsZeroWordGadget::<CB::F>::eval(builder, diff, cols.is_diff_zero, is_real.clone());
    }
}
