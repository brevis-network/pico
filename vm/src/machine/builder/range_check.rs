//! Range check associating builder functions

use super::{ChipBuilder, ChipLookupBuilder};
use crate::compiler::riscv::opcode::ByteOpcode;
use p3_air::AirBuilder;
use p3_field::{Field, FieldAlgebra};

pub trait ChipRangeBuilder<F: Field>: ChipBuilder<F> {
    /// Check that each limb of the given slice is a u8.
    fn slice_range_check_u8(
        &mut self,
        input: &[impl Into<Self::Expr> + Clone],
        mult: impl Into<Self::Expr> + Clone,
    ) {
        for pair in input.chunks(2) {
            let b = pair[0].clone();
            let c = pair
                .get(1)
                .cloned()
                .map(Into::into)
                .unwrap_or(Self::Expr::ZERO);
            self.looking_rangecheck(
                ByteOpcode::U8Range,
                Self::Expr::ZERO,
                Self::Expr::ZERO,
                b,
                c,
                mult.clone(),
            );
        }
    }

    /// Check that each limb of the given slice is a u16.
    fn slice_range_check_u16(
        &mut self,
        input: &[impl Into<Self::Expr> + Copy],
        mult: impl Into<Self::Expr> + Clone,
    ) {
        input.iter().for_each(|limb| {
            self.looking_rangecheck(
                ByteOpcode::U16Range,
                *limb,
                Self::Expr::ZERO,
                Self::Expr::ZERO,
                Self::Expr::ZERO,
                mult.clone(),
            );
        });
    }

    /// Verifies the inputted value is within 24 bits.
    ///
    /// This method verifies that the inputted is less than 2^24 by doing a 16 bit and 8 bit range
    /// check on it's limbs.  It will also verify that the limbs are correct.  This method is needed
    /// since the memory access timestamp check (see [Self::verify_mem_access_ts]) needs to assume
    /// the clk is within 24 bits.
    fn range_check_u24(
        &mut self,
        value: impl Into<Self::Expr>,
        limb_16: impl Into<Self::Expr> + Clone,
        limb_8: impl Into<Self::Expr> + Clone,
        do_check: impl Into<Self::Expr> + Clone,
    ) {
        // Verify that value = limb_16 + limb_8 * 2^16.
        self.when(do_check.clone()).assert_eq(
            value,
            limb_16.clone().into()
                + limb_8.clone().into() * Self::Expr::from_canonical_u32(1 << 16),
        );

        // Send the range checks for the limbs.
        self.looking_rangecheck(
            ByteOpcode::U16Range,
            limb_16,
            Self::Expr::ZERO,
            Self::Expr::ZERO,
            Self::Expr::ZERO,
            do_check.clone(),
        );
        self.looking_rangecheck(
            ByteOpcode::U8Range,
            Self::Expr::ZERO,
            Self::Expr::ZERO,
            limb_8,
            Self::Expr::ZERO,
            do_check,
        );
    }
}
