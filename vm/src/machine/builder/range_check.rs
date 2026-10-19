//! Range check associating builder functions

use super::{ChipBuilder, ChipLookupBuilder};
use crate::compiler::riscv::opcode::ByteOpcode;
use p3_air::AirBuilder;
use p3_field::{Field, PrimeCharacteristicRing};

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
        input: &[impl Into<Self::Expr> + Clone],
        mult: impl Into<Self::Expr> + Clone,
    ) {
        input.iter().for_each(|limb| {
            self.looking_rangecheck(
                ByteOpcode::U16Range,
                limb.clone(),
                Self::Expr::ZERO,
                Self::Expr::ZERO,
                Self::Expr::ZERO,
                mult.clone(),
            );
        });
    }

    /// Verifies the inputted value is within 25 bits, with a 16 + 9 limb decomposition:
    /// `value = limb_16 + hi9 * 2^16`, `limb_16` U16Range-checked and `hi9` BitRange(9)-checked.
    ///
    /// The 25-bit budget is what the memory access timestamp check compares against
    /// (see [`RiscVMemoryBuilder::eval_memory_access_timestamp`]): a chunk holds up to 2^23
    /// instructions, so the max chunk clk is 4xCHUNK_SIZE = 2^25, and every compared value has
    /// to be checked to that same budget.
    fn range_check_u25_16_9(
        &mut self,
        value: impl Into<Self::Expr>,
        limb_16: impl Into<Self::Expr> + Clone,
        hi9: impl Into<Self::Expr> + Clone,
        do_check: impl Into<Self::Expr> + Clone,
    ) {
        // Verify that value = limb_16 + hi9 * 2^16.
        self.when(do_check.clone()).assert_eq(
            value,
            limb_16.clone().into() + hi9.clone().into() * Self::Expr::from_u32(1 << 16),
        );

        self.range_check_u25_16_9_limbs(limb_16, hi9, do_check);
    }

    /// The two limb lookups of [`Self::range_check_u25_16_9`] without the decomposition
    /// equation: `limb_16` U16Range-checked and `hi9` BitRange(9)-checked, both with
    /// multiplicity `do_check`.
    ///
    /// For callers that do not commit the 25-bit value but *define* it from the limbs
    /// (`RiscVMemoryBuilder::eval_memory_access_lite`: `prev_clk := clk - (limb_16 + hi9 * 2^16)
    /// - 1`). There the equation is an identity, and the two lookups alone pin the difference to
    /// `[0, 2^25)`.
    fn range_check_u25_16_9_limbs(
        &mut self,
        limb_16: impl Into<Self::Expr> + Clone,
        hi9: impl Into<Self::Expr> + Clone,
        do_check: impl Into<Self::Expr> + Clone,
    ) {
        self.looking_rangecheck(
            ByteOpcode::U16Range,
            limb_16,
            Self::Expr::ZERO,
            Self::Expr::ZERO,
            Self::Expr::ZERO,
            do_check.clone(),
        );
        self.looking_byte(
            Self::Expr::from_u8(ByteOpcode::BitRange as u8),
            hi9,
            Self::Expr::from_u8(9),
            Self::Expr::ZERO,
            do_check,
        );
    }
}
