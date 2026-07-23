use crate::{
    chips::chips::byte::event::ByteRecordBehavior,
    machine::builder::{ChipBuilder, ChipRangeBuilder},
    primitives::consts::u32_to_u16_limbs,
};
use p3_air::AirBuilder;
use p3_field::{Field, FieldAlgebra};
use pico_derive::AlignedBorrow;

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct AddU32Gadget<T> {
    pub value: [T; 2],
}

impl<F: Field> AddU32Gadget<F> {
    pub fn populate(
        &mut self,
        record: &mut impl ByteRecordBehavior,
        a_u32: u32,
        b_u32: u32,
    ) -> u32 {
        let expected = a_u32.wrapping_add(b_u32);
        let expected_limbs = u32_to_u16_limbs(expected);
        self.value = [
            F::from_canonical_u16(expected_limbs[0]),
            F::from_canonical_u16(expected_limbs[1]),
        ];
        record.add_u16_range_checks(&expected_limbs);
        expected
    }

    pub fn eval<CB: ChipBuilder<F>>(
        builder: &mut CB,
        a: [CB::Expr; 2],
        b: [CB::Expr; 2],
        cols: AddU32Gadget<CB::Var>,
        is_real: CB::Var,
    ) {
        builder.assert_bool(is_real);

        let base = CB::F::from_canonical_u32(1 << 16);
        let mut builder_is_real = builder.when(is_real);
        let mut carry = CB::Expr::ZERO;

        for i in 0..2 {
            carry = (a[i].clone() + b[i].clone() - cols.value[i] + carry) * base.inverse();
            builder_is_real.assert_bool(carry.clone());
        }

        builder.slice_range_check_u16(&cols.value, is_real);
    }
}
