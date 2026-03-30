//! Unsigned less-than gadget for Word<T> with u16 limbs.
//!
//! Compares two 64-bit values represented as Word<T> (4 × u16 limbs).
//! Used by MemoryInitializeFinalize to verify address ordering.

use crate::{
    chips::chips::byte::event::ByteRecordBehavior,
    compiler::{riscv::opcode::ByteOpcode, word::Word},
    machine::builder::{ChipBuilder, ChipLookupBuilder, ChipRangeBuilder},
    primitives::consts::{u64_to_u16_limbs, WORD_SIZE},
};
use itertools::izip;
use p3_air::AirBuilder;
use p3_field::{Field, FieldAlgebra};
use pico_derive::AlignedBorrow;

/// Gadget for asserting `a < b` where `a` and `b` are 64-bit values
/// represented as `Word<T>` with 4 × u16 limbs (little-endian).
///
/// Works by finding the most significant limb pair that differs,
/// then verifying the LT relationship on those u16 limbs using
/// the `diff + bit * 2^16` range-check technique.
#[derive(Debug, Clone, Copy, AlignedBorrow)]
#[repr(C)]
pub struct LtWordU16Gadget<T> {
    /// Boolean flags indicating which limb pair is the most-significant differing one.
    /// At most one flag is 1; if all are 0, the values are equal.
    pub u16_flags: [T; WORD_SIZE],

    /// The inverse of (a_limb - b_limb) at the differing position.
    /// Used to prove the selected limbs are actually different.
    /// Zero when values are equal.
    pub not_eq_inv: T,

    /// The two u16 limbs being compared (from the first differing position).
    pub comparison_limbs: [T; 2],

    /// The LT bit: 1 if a_comparison_limb < b_comparison_limb, 0 otherwise.
    /// Used with the u16 range check: diff = a - b + bit * 2^16 must be in [0, 2^16).
    pub bit: T,
}

impl<T: Default + Copy> Default for LtWordU16Gadget<T> {
    fn default() -> Self {
        Self {
            u16_flags: [T::default(); WORD_SIZE],
            not_eq_inv: T::default(),
            comparison_limbs: [T::default(); 2],
            bit: T::default(),
        }
    }
}

impl<F: Field> LtWordU16Gadget<F> {
    /// Populate the gadget columns for asserting `a < b` (both as u64).
    ///
    /// The caller must ensure `a < b` or `a == b` (for the equal case,
    /// no flag is set and constraints will only pass if `is_real` is false).
    pub fn populate(
        &mut self,
        record: &mut impl ByteRecordBehavior,
        a_u64: u64,
        b_u64: u64,
        c_u64: u64,
    ) {
        self.comparison_limbs[0] = F::ZERO;
        self.comparison_limbs[1] = F::ZERO;
        self.not_eq_inv = F::ZERO;
        self.u16_flags = [F::ZERO; 4];

        let a_limbs = u64_to_u16_limbs(a_u64);
        let b_limbs = u64_to_u16_limbs(b_u64);
        let c_limbs = u64_to_u16_limbs(c_u64);

        let a_u16 = a_limbs[0] as u16;

        let mut comparison_limbs = [0u16; 2];
        for (b_limb, c_limb, flag) in izip!(
            b_limbs.iter().rev(),
            c_limbs.iter().rev(),
            self.u16_flags.iter_mut().rev()
        ) {
            if b_limb != c_limb {
                *flag = F::ONE;
                comparison_limbs[0] = *b_limb;
                comparison_limbs[1] = *c_limb;
                let b_limb = F::from_canonical_u16(*b_limb);
                let c_limb = F::from_canonical_u16(*c_limb);
                self.not_eq_inv = (b_limb - c_limb).inverse();
                self.comparison_limbs = [b_limb, c_limb];
                break;
            }
        }

        {
            self.bit = F::from_canonical_u16(a_u16);
            let diff = comparison_limbs[0].wrapping_sub(comparison_limbs[1]);
            record.add_u16_range_check(diff);
        }
    }

    /// Evaluate constraints for `a < b` where both are Word<T> with u16 limbs.
    ///
    /// When `is_real` is true, constrains that either:
    /// - Exactly one flag is set (a < b), OR
    /// - No flags are set (a >= b)
    ///
    /// Accepts `Word<CB::Expr>` so callers can pass expressions (e.g. `Expr::ZERO`
    /// for unused limbs) without requiring a concrete `Var`.
    pub fn eval<CB>(
        builder: &mut CB,
        b: Word<CB::Expr>,
        c: Word<CB::Expr>,
        cols: LtWordU16Gadget<CB::Var>,
        is_real: CB::Expr,
    ) where
        CB: ChipBuilder<F> + ChipRangeBuilder<F> + ChipLookupBuilder<F>,
    {
        builder.assert_bool(is_real.clone());

        // Verify that the limb equality flags are set correctly, i.e. all are boolean and only
        // at most a single flag is set to one.
        let sum_flags =
            cols.u16_flags[0] + cols.u16_flags[1] + cols.u16_flags[2] + cols.u16_flags[3];
        builder.assert_bool(cols.u16_flags[0]);
        builder.assert_bool(cols.u16_flags[1]);
        builder.assert_bool(cols.u16_flags[2]);
        builder.assert_bool(cols.u16_flags[3]);
        builder.assert_bool(sum_flags.clone());

        let is_comp_eq = CB::Expr::ONE - sum_flags;

        // A flag to indicate whether an equality check is necessary.
        // This is for all limbs from most significant until the first inequality.
        let mut is_inequality_visited = CB::Expr::ZERO;

        // Iterate over the limbs in reverse order and select the differing limbs using the limb
        // flag columns values.
        let mut b_comparison_limb = CB::Expr::ZERO;
        let mut c_comparison_limb = CB::Expr::ZERO;
        for (b_limb, c_limb, &flag) in izip!(
            b.0.iter().rev(),
            c.0.iter().rev(),
            cols.u16_flags.iter().rev()
        ) {
            // Once the byte flag was set to one, we turn off the equality check flag.
            // We can do this by calculating the sum of the flags since only one is set to `1`.
            is_inequality_visited = is_inequality_visited.clone() + flag.into();

            // If inequality is not visited, assert that the limbs are equal.
            builder
                .when(is_real.clone() - is_inequality_visited.clone())
                .assert_eq(b_limb.clone(), c_limb.clone());

            b_comparison_limb = b_comparison_limb.clone() + b_limb.clone() * flag.into();
            c_comparison_limb = c_comparison_limb.clone() + c_limb.clone() * flag.into();
        }

        let (b_comp_limb, c_comp_limb) = (cols.comparison_limbs[0], cols.comparison_limbs[1]);
        builder.assert_eq(b_comparison_limb, b_comp_limb);
        builder.assert_eq(c_comparison_limb, c_comp_limb);

        // Using the values above, we can constrain the `is_comp_eq` flag. We already asserted
        // in the loop that when `is_comp_eq == 1` then all limbs are equal. It is left to
        // verify that when `is_comp_eq == 0` the comparison limbs are indeed not equal.
        // This is done using the inverse hint `not_eq_inv`, when `is_real` is true.
        builder.when_not(is_comp_eq).assert_eq(
            cols.not_eq_inv * (b_comp_limb - c_comp_limb),
            is_real.clone(),
        );

        {
            let a = b_comp_limb.into();
            let b = c_comp_limb.into();

            // Constrain that `is_real` is boolean.
            builder.assert_bool(is_real.clone());
            // Constrain that `cols.bit` is boolean.
            builder.assert_bool(cols.bit);
            let base = CB::Expr::from_canonical_u32(1 << 16);
            let diff = a - b + cols.bit * base;
            // Since `a, b` are both u16, `a - b` will be in `(-2^16, 2^16)`.
            // If `a < b`, then `bit` must be one for `diff` to be in `[0, 2^16)`.
            // If `a >= b`, then `bit` must be zero for `diff` to be in `[0, 2^16)`.
            // With correct `bit`, the `diff` value will be in u16 range.
            builder.looking_rangecheck(
                ByteOpcode::U16Range,
                diff,
                CB::Expr::ZERO,
                CB::Expr::ZERO,
                CB::Expr::ZERO,
                is_real.clone(),
            );
        }
    }
}
