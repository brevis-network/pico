use crate::{
    chips::chips::rangecheck::event::RangeRecordBehavior,
    compiler::word::Word,
    machine::builder::{ChipLookupBuilder, ChipRangeBuilder},
    primitives::consts::WORD_SIZE,
};
use p3_air::AirBuilder;
use p3_field::Field;
use pico_derive::AlignedBorrow;

/// A set of columns needed to compute the not of a word.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct NotOperation<T> {
    /// The result of `!x`.
    pub value: Word<T>,
}

impl<F: Field> NotOperation<F> {
    pub fn populate(&mut self, record: &mut impl RangeRecordBehavior, chunk: u32, x: u32) -> u32 {
        let expected = !x;
        let x_bytes = x.to_le_bytes();
        for i in 0..WORD_SIZE {
            self.value[i] = F::from_canonical_u8(!x_bytes[i]);
        }
        record.add_u8_range_checks(x_bytes, Some(chunk));
        expected
    }

    #[allow(unused_variables)]
    pub fn eval<CB: ChipLookupBuilder<F>>(
        builder: &mut CB,
        a: Word<CB::Var>,
        cols: NotOperation<CB::Var>,
        chunk: impl Into<CB::Expr> + Copy,
        is_real: impl Into<CB::Expr> + Copy,
    ) {
        for i in (0..WORD_SIZE).step_by(2) {
            builder.slice_range_check_u8(&[a[i], a[i + 1]], chunk, is_real);
        }

        // For any byte b, b + !b = 0xFF.
        for i in 0..WORD_SIZE {
            builder
                .when(is_real)
                .assert_eq(cols.value[i] + a[i], CB::F::from_canonical_u8(u8::MAX));
        }
    }
}
