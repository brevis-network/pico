//! The gadget for the addition of two words (Uint64)

use crate::{
    chips::chips::byte::event::ByteRecordBehavior,
    compiler::word::Word,
    machine::builder::{ChipBuilder, ChipRangeBuilder},
    primitives::consts::{u64_to_u16_limbs, WORD_SIZE},
};
use p3_air::AirBuilder;
use p3_field::{Field, FieldAlgebra};
use pico_derive::AlignedBorrow;

/// A set of columns needed to compute the add of two words.
#[derive(AlignedBorrow, Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct AddGadget<T> {
    /// The result of `a + b`.
    pub value: Word<T>,
}

impl<F: Field> AddGadget<F> {
    pub fn populate(
        &mut self,
        record: &mut impl ByteRecordBehavior,
        a_u64: u64,
        b_u64: u64,
    ) -> u64 {
        let expected = a_u64.wrapping_add(b_u64);
        self.value = Word::from(expected);
        // Range check
        record.add_u16_range_checks(&u64_to_u16_limbs(expected));
        expected
    }

    pub fn eval<AB: ChipBuilder<F>>(
        builder: &mut AB,
        a: Word<AB::Var>,
        b: Word<AB::Var>,
        cols: AddGadget<AB::Var>,
        is_real: AB::Expr,
    ) {
        builder.assert_bool(is_real.clone());

        let base = AB::F::from_canonical_u32(1 << 16);
        let mut builder_is_real = builder.when(is_real.clone());
        let mut carry = AB::Expr::ZERO;

        // The set of constraints are
        //  - carry is initialized to zero
        //  - 2^16 * carry_next + value[i] = a[i] + b[i] + carry
        //  - carry is boolean
        //  - 0 <= value[i] < 2^16
        for i in 0..WORD_SIZE {
            carry = (a[i] + b[i] - cols.value[i] + carry) * base.inverse();
            builder_is_real.assert_bool(carry.clone());
        }

        // Range check each limb.
        builder.slice_range_check_u16(&cols.value.0, is_real);
    }
}
