//! The gadget for adding two addresses (u48).

use crate::{
    chips::chips::byte::event::ByteRecordBehavior,
    compiler::word::Word,
    machine::builder::{ChipBuilder, ChipRangeBuilder},
    primitives::consts::{u64_to_u16_limbs, ADDR_SIZE, WORD_SIZE},
};
use p3_air::AirBuilder;
use p3_field::{Field, FieldAlgebra};
use pico_derive::AlignedBorrow;

/// A set of columns needed to compute the addition of two addresses (u48).
#[derive(AlignedBorrow, Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct AddrAddGadget<T> {
    /// The result of `a + b` in u48 (three u16 limbs).
    pub value: [T; ADDR_SIZE],
}

impl<F: Field> AddrAddGadget<F> {
    /// Populate the gadget with concrete values.
    pub fn populate(
        &mut self,
        record: &mut impl ByteRecordBehavior,
        a_u64: u64,
        b_u64: u64,
    ) -> u64 {
        let expected = a_u64.wrapping_add(b_u64);
        // Assert that the result fits in 48 bits
        assert!(
            expected >> 48 == 0,
            "AddrAddGadget: result exceeds 48 bits: {}",
            expected
        );

        self.value = [
            F::from_canonical_u16((expected & 0xFFFF) as u16),
            F::from_canonical_u16(((expected >> 16) & 0xFFFF) as u16),
            F::from_canonical_u16(((expected >> 32) & 0xFFFF) as u16),
        ];

        // Range check
        record.add_u16_range_checks(&u64_to_u16_limbs(expected)[..3]);
        expected
    }

    /// Evaluate the add operation constraints.
    /// Assumes that `a`, `b` are valid Words.
    /// Constrains that `is_real` is boolean.
    /// If `is_real` is true, `value` is constrained to be a valid u48 address `a + b`.
    #[allow(clippy::clone_on_copy, clippy::useless_conversion)]
    pub fn eval<CB: ChipBuilder<F>>(
        builder: &mut CB,
        a: Word<CB::Expr>,
        b: Word<CB::Expr>,
        cols: AddrAddGadget<CB::Var>,
        is_real: CB::Expr,
    ) {
        builder.assert_bool(is_real.clone());

        let base = CB::F::from_canonical_u32(1 << 16);
        let mut builder_is_real = builder.when(is_real.clone());
        let mut carry: CB::Expr = CB::Expr::ZERO;

        // The set of constraints are
        //  - carry is initialized to zero
        //  - 2^16 * carry_next + value[i] = a[i] + b[i] + carry
        //  - carry is boolean
        //  - 0 <= value[i] < 2^16
        for i in 0..WORD_SIZE {
            let value_limb: CB::Expr = if i < ADDR_SIZE {
                cols.value[i].into()
            } else {
                CB::Expr::ZERO
            };
            let a_limb: CB::Expr = a.0[i].clone().into();
            let b_limb: CB::Expr = b.0[i].clone().into();

            // carry_next * 2^16 + value = a + b + carry
            carry = (a_limb + b_limb + carry - value_limb) * base.inverse();
            builder_is_real.assert_bool(carry.clone() as CB::Expr);
        }

        // Range check each limb.
        builder.slice_range_check_u16(&cols.value, is_real);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::{builder::PublicValuesBuilder, folder::SymbolicConstraintFolder};
    use p3_koala_bear::KoalaBear;
    use p3_matrix::Matrix;
    use pico_derive::AlignedBorrow;
    use std::{borrow::Borrow, mem::size_of};

    #[derive(AlignedBorrow, Clone, Copy)]
    #[repr(C)]
    struct TestCols<T> {
        a: Word<T>,
        b: Word<T>,
        addr_add: AddrAddGadget<T>,
        is_real: T,
    }

    #[test]
    fn test_addr_add_gadget_simple_eval() {
        let width = size_of::<TestCols<u8>>();
        let mut builder = SymbolicConstraintFolder::new(0, width);
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &TestCols<_> = (*local).borrow();

        AddrAddGadget::<KoalaBear>::eval(
            &mut builder,
            local.a.map(|v| v.into()),
            local.b.map(|v| v.into()),
            local.addr_add,
            local.is_real.into(),
        );

        assert_eq!(builder.num_constraints(), 5);
        assert_eq!(builder.public_values().len(), 119);
        assert_eq!(builder.num_lookups(), 3);
    }
}
