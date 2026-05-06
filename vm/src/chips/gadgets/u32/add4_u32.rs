use crate::{
    chips::chips::byte::event::ByteRecordBehavior,
    machine::builder::{ChipBuilder, ChipRangeBuilder},
    primitives::consts::{u32_to_half_word, u32_to_u16_limbs},
};
use p3_field::{Field, FieldAlgebra};
use pico_derive::AlignedBorrow;

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct Add4U32Gadget<T> {
    pub value: [T; 2],
}

impl<F: Field> Add4U32Gadget<F> {
    #[allow(clippy::too_many_arguments)]
    pub fn populate(
        &mut self,
        record: &mut impl ByteRecordBehavior,
        a_u32: u32,
        b_u32: u32,
        c_u32: u32,
        d_u32: u32,
    ) -> u32 {
        let expected = a_u32
            .wrapping_add(b_u32)
            .wrapping_add(c_u32)
            .wrapping_add(d_u32);
        let expected_limbs = u32_to_u16_limbs(expected);
        self.value = u32_to_half_word(expected);
        let a = u32_to_u16_limbs(a_u32);
        let b = u32_to_u16_limbs(b_u32);
        let c = u32_to_u16_limbs(c_u32);
        let d = u32_to_u16_limbs(d_u32);

        let base = 1u32 << 16;
        let mut carry_limbs = [0u8; 2];
        let mut carry = 0;
        for i in 0..2 {
            carry = ((a[i] as u32) + (b[i] as u32) + (c[i] as u32) + (d[i] as u32) + carry
                - expected_limbs[i] as u32)
                / base;
            carry_limbs[i] = carry as u8;
        }

        // Range check.
        record.add_u16_range_checks(&expected_limbs);
        record.add_u8_range_checks(carry_limbs);
        expected
    }

    #[allow(clippy::too_many_arguments)]
    pub fn eval<CB: ChipBuilder<F>>(
        builder: &mut CB,
        a: [CB::Expr; 2],
        b: [CB::Expr; 2],
        c: [CB::Expr; 2],
        d: [CB::Expr; 2],
        is_real: CB::Var,
        cols: Add4U32Gadget<CB::Var>,
    ) {
        builder.assert_bool(is_real);

        let base = CB::F::from_canonical_u32(1 << 16);
        let mut carry_limbs = [CB::Expr::ZERO, CB::Expr::ZERO];
        let mut carry = CB::Expr::ZERO; // Initialize carry to zero

        // The set of constraints are
        //  - carry is initialized to zero
        //  - 2^16 * carry_next + value[i] = a[i] + b[i] + c[i] + d[i] + carry
        //  - 0 <= carry < 2^8
        //  - 0 <= value[i] < 2^16
        // Since the carries are bounded by 2^8, no field overflows are possible.
        // The maximum carry possible is less than 2^8, so the circuit is complete.
        for i in 0..2 {
            carry = (a[i].clone() + b[i].clone() + c[i].clone() + d[i].clone() - cols.value[i]
                + carry)
                * base.inverse();
            carry_limbs[i] = carry.clone();
        }
        // Range check each limb.
        builder.slice_range_check_u16(&cols.value, is_real);
        builder.slice_range_check_u8(&carry_limbs, is_real);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::{builder::PublicValuesBuilder, folder::SymbolicConstraintFolder};
    use p3_air::AirBuilder;
    use p3_koala_bear::KoalaBear;
    use p3_matrix::Matrix;
    use pico_derive::AlignedBorrow;
    use std::{borrow::Borrow, mem::size_of};

    #[derive(AlignedBorrow, Clone, Copy)]
    #[repr(C)]
    struct TestCols<T> {
        a: [T; 2],
        b: [T; 2],
        c: [T; 2],
        d: [T; 2],
        add4_u32: Add4U32Gadget<T>,
        is_real: T,
    }

    #[test]
    fn test_add4_u32_gadget_simple_eval() {
        let width = size_of::<TestCols<u8>>();
        let mut builder = SymbolicConstraintFolder::new(0, width);
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &TestCols<_> = (*local).borrow();

        Add4U32Gadget::<KoalaBear>::eval(
            &mut builder,
            local.a.map(|v| v.into()),
            local.b.map(|v| v.into()),
            local.c.map(|v| v.into()),
            local.d.map(|v| v.into()),
            local.is_real,
            local.add4_u32,
        );

        assert_eq!(builder.num_constraints(), 1);
        assert_eq!(builder.public_values().len(), 119);
        assert_eq!(builder.num_lookups(), 3);
    }
}
