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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::folder::SymbolicConstraintFolder;
    use p3_koala_bear::KoalaBear;
    use p3_matrix::Matrix;
    use pico_derive::AlignedBorrow;
    use std::borrow::Borrow;
    use p3_air::AirBuilder;
    use std::mem::size_of;

    #[derive(AlignedBorrow, Clone, Copy)]
    #[repr(C)]
    struct TestCols<T> {
        a: [T; 2],
        b: [T; 2],
        add_u32: AddU32Gadget<T>,
        is_real: T,
    }

    #[test]
    fn test_add_u32_gadget_simple_eval() {
        let width = size_of::<TestCols<u8>>();
        let mut builder = SymbolicConstraintFolder::new(0, width);
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &TestCols<_> = (*local).borrow();

        AddU32Gadget::<KoalaBear>::eval(
            &mut builder,
            local.a.map(|v| v.into()),
            local.b.map(|v| v.into()),
            local.add_u32,
            local.is_real,
        );
    }
}
