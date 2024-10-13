//! Range check associating builder functions

use super::{ChipBuilder, ChipLookupBuilder};
use crate::{
    compiler::riscv::opcode::ByteOpcode,
    machine::lookup::{LookupType, SymbolicLookup},
};
use p3_air::AirBuilder;
use p3_field::{AbstractField, Field};

pub trait ChipRangeBuilder<F: Field>: ChipBuilder<F> {
    /// Check that each limb of the given slice is a u8.
    fn slice_range_check_u8(
        &mut self,
        input: &[impl Into<Self::Expr> + Clone],
        chunk: impl Into<Self::Expr> + Clone,
        channel: impl Into<Self::Expr> + Clone,
        mult: impl Into<Self::Expr> + Clone,
    ) {
        let mut index = 0;
        while index + 1 < input.len() {
            self.looking_byte(
                Self::Expr::from_canonical_u8(ByteOpcode::U8Range as u8),
                Self::Expr::zero(),
                input[index].clone(),
                input[index + 1].clone(),
                chunk.clone(),
                channel.clone(),
                mult.clone(),
            );
            index += 2;
        }
        if index < input.len() {
            self.looking_byte(
                Self::Expr::from_canonical_u8(ByteOpcode::U8Range as u8),
                Self::Expr::zero(),
                input[index].clone(),
                Self::Expr::zero(),
                chunk.clone(),
                channel.clone(),
                mult.clone(),
            );
        }
    }

    /// Check that each limb of the given slice is a u16.
    fn slice_range_check_u16(
        &mut self,
        input: &[impl Into<Self::Expr> + Copy],
        chunk: impl Into<Self::Expr> + Clone,
        channel: impl Into<Self::Expr> + Clone,
        mult: impl Into<Self::Expr> + Clone,
    ) {
        input.iter().for_each(|limb| {
            self.looking_byte(
                Self::Expr::from_canonical_u8(ByteOpcode::U16Range as u8),
                *limb,
                Self::Expr::zero(),
                Self::Expr::zero(),
                chunk.clone(),
                channel.clone(),
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
        chunk: impl Into<Self::Expr> + Clone,
        channel: impl Into<Self::Expr> + Clone,
        do_check: impl Into<Self::Expr> + Clone,
    ) {
        // Verify that value = limb_16 + limb_8 * 2^16.
        self.when(do_check.clone()).assert_eq(
            value,
            limb_16.clone().into()
                + limb_8.clone().into() * Self::Expr::from_canonical_u32(1 << 16),
        );

        // Send the range checks for the limbs.
        self.looking_byte(
            Self::Expr::from_canonical_u8(ByteOpcode::U16Range as u8),
            limb_16,
            Self::Expr::zero(),
            Self::Expr::zero(),
            chunk.clone(),
            channel.clone(),
            do_check.clone(),
        );
        self.looking_byte(
            Self::Expr::from_canonical_u8(ByteOpcode::U8Range as u8),
            Self::Expr::zero(),
            Self::Expr::zero(),
            limb_8,
            chunk.clone(),
            channel.clone(),
            do_check,
        )
    }

    /// Looking a range check operation to be processed.
    fn recursion_looking_range_check(
        &mut self,
        range_check_opcode: impl Into<Self::Expr>,
        val: impl Into<Self::Expr>,
        is_real: impl Into<Self::Expr>,
    ) {
        self.looking(SymbolicLookup::new(
            vec![range_check_opcode.into(), val.into()],
            is_real.into(),
            LookupType::Range,
        ));
    }

    /// Looked a range check operation to be processed.
    fn recursion_looked_range_check(
        &mut self,
        range_check_opcode: impl Into<Self::Expr>,
        val: impl Into<Self::Expr>,
        is_real: impl Into<Self::Expr>,
    ) {
        self.looked(SymbolicLookup::new(
            vec![range_check_opcode.into(), val.into()],
            is_real.into(),
            LookupType::Range,
        ));
    }
}
