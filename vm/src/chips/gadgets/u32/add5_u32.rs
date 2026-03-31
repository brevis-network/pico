use crate::{
    chips::chips::byte::event::ByteRecordBehavior,
    machine::builder::{ChipLookupBuilder, ChipRangeBuilder},
    primitives::consts::{u32_to_half_word, u32_to_u16_limbs},
};
use p3_field::{Field, FieldAlgebra};
use pico_derive::AlignedBorrow;

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct Add5U32Gadget<T> {
    pub value: [T; 2],
}

impl<F: Field> Add5U32Gadget<F> {
    #[allow(clippy::too_many_arguments)]
    pub fn populate(
        &mut self,
        record: &mut impl ByteRecordBehavior,
        a_u32: u32,
        b_u32: u32,
        c_u32: u32,
        d_u32: u32,
        e_u32: u32,
    ) -> u32 {
        let expected = a_u32
            .wrapping_add(b_u32)
            .wrapping_add(c_u32)
            .wrapping_add(d_u32)
            .wrapping_add(e_u32);
        let expected_limbs = u32_to_u16_limbs(expected);
        self.value = u32_to_half_word(expected);
        let a = u32_to_u16_limbs(a_u32);
        let b = u32_to_u16_limbs(b_u32);
        let c = u32_to_u16_limbs(c_u32);
        let d = u32_to_u16_limbs(d_u32);
        let e = u32_to_u16_limbs(e_u32);
        let base = 1u32 << 16;
        let mut carry = 0;
        let mut carry_limbs = [0u8; 2];
        for i in 0..2 {
            carry = ((a[i] as u32)
                + (b[i] as u32)
                + (c[i] as u32)
                + (d[i] as u32)
                + (e[i] as u32)
                + carry
                - expected_limbs[i] as u32)
                / base;
            carry_limbs[i] = carry as u8;
        }

        // Range check.
        record.add_u16_range_checks(&expected_limbs);
        record.add_u8_range_checks(carry_limbs);
        expected
    }

    #[allow(clippy::assign_op_pattern)]
    pub fn eval<CB: ChipLookupBuilder<F> + ChipRangeBuilder<F>>(
        builder: &mut CB,
        words: &[[CB::Expr; 2]; 5],
        is_real: CB::Var,
        cols: Add5U32Gadget<CB::Var>,
    ) {
        builder.assert_bool(is_real);

        let base = CB::F::from_canonical_u32(1 << 16);
        let mut carry_limbs = [CB::Expr::ZERO, CB::Expr::ZERO];
        let mut carry = CB::Expr::ZERO; // Initialize carry to zero

        // The set of constraints are
        //  - carry is initialized to zero
        //  - 2^16 * carry_next + value[i] = sum(word[i]) + carry
        //  - 0 <= carry < 2^8
        //  - 0 <= value[i] < 2^16
        // Since the carries are bounded by 2^8, no field overflows are possible.
        // The maximum carry possible is less than 2^8, so the circuit is complete.
        for i in 0..2 {
            carry = (words[0][i].clone()
                + words[1][i].clone()
                + words[2][i].clone()
                + words[3][i].clone()
                + words[4][i].clone()
                - cols.value[i]
                + carry.clone())
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
        w0: [T; 2],
        w1: [T; 2],
        w2: [T; 2],
        w3: [T; 2],
        w4: [T; 2],
        add5_u32: Add5U32Gadget<T>,
        is_real: T,
    }

    #[test]
    fn test_add5_u32_gadget_simple_eval() {
        let width = size_of::<TestCols<u8>>();
        let mut builder = SymbolicConstraintFolder::new(0, width);
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &TestCols<_> = (*local).borrow();

        let words = [
            local.w0.map(|v| v.into()),
            local.w1.map(|v| v.into()),
            local.w2.map(|v| v.into()),
            local.w3.map(|v| v.into()),
            local.w4.map(|v| v.into()),
        ];
        Add5U32Gadget::<KoalaBear>::eval(
            &mut builder,
            &words,
            local.is_real,
            local.add5_u32,
        );
    }
}
