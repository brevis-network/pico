use crate::{
    chips::{chips::byte::event::ByteRecordBehavior, gadgets::msb::U16MSBGadget},
    compiler::word::Word,
    machine::builder::{ChipBuilder, ChipRangeBuilder},
    primitives::consts::{u64_to_u16_limbs, WORD_SIZE},
};
use p3_air::AirBuilder;
use p3_field::{Field, FieldAlgebra};
use pico_derive::AlignedBorrow;
use std::num::Wrapping;

/// support u64
/// A set of columns needed to compute the sub of two words.
#[derive(AlignedBorrow, Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct SubwGadget<T> {
    /// The result of the SUBW gadget.
    pub value: [T; WORD_SIZE / 2],
    /// The msb of the result.
    pub msb: U16MSBGadget<T>,
}

impl<F: Field> SubwGadget<F> {
    pub fn populate(&mut self, record: &mut impl ByteRecordBehavior, a_u64: u64, b_u64: u64) {
        let value = (Wrapping(a_u64 as i32) - Wrapping(b_u64 as i32)).0 as i64 as u64;
        let limbs = u64_to_u16_limbs(value);
        self.value = [
            F::from_canonical_u16(limbs[0]),
            F::from_canonical_u16(limbs[1]),
        ];

        // Range check
        record.add_u16_range_checks(&limbs[..WORD_SIZE / 2]);
        self.msb.populate(record, limbs[1]);
    }

    /// Evaluate the subw gadget.
    /// Assumes that `a`, `b` are valid `Word`s of u16 limbs.
    /// Constrains that `is_real` is boolean.
    /// If `is_real` is true, the `value` is constrained to a the lower u32 of the SUBW result.
    /// Also, the `msb` will be constrained to equal the most significant bit of the `value`.
    pub fn eval<AB: ChipBuilder<F>>(
        builder: &mut AB,
        a: Word<AB::Var>, //TODO should use AB::Expr
        b: Word<AB::Var>,
        cols: SubwGadget<AB::Var>,
        is_real: AB::Expr,
    ) {
        builder.assert_bool(is_real.clone());

        let base = AB::F::from_canonical_u32(1 << 16);
        let mut builder_is_real = builder.when(is_real.clone());
        let mut carry = AB::Expr::ONE;
        let one = AB::Expr::ONE;

        // Use the same logic as addition, for (a + (2^32 - b)).
        // This by using `2^16 - 1 - b[i]` as the added limb, and initializing the carry to 1.
        for i in 0..WORD_SIZE / 2 {
            carry = (a[i] + base - one.clone() - b[i] - cols.value[i] + carry) * base.inverse();
            builder_is_real.assert_bool(carry.clone());
        }

        // Range check each limb.
        builder.slice_range_check_u16(&cols.value, is_real.clone());

        U16MSBGadget::<AB::F>::eval(builder, cols.value[1].into(), cols.msb, is_real.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::folder::SymbolicConstraintFolder;
    use crate::machine::builder::PublicValuesBuilder;
    use p3_koala_bear::KoalaBear;
    use p3_matrix::Matrix;
    use pico_derive::AlignedBorrow;
    use std::borrow::Borrow;
    use std::mem::size_of;

    #[derive(AlignedBorrow, Clone, Copy)]
    #[repr(C)]
    struct TestCols<T> {
        a: Word<T>,
        b: Word<T>,
        subw: SubwGadget<T>,
        is_real: T,
    }

    #[test]
    fn test_subw_gadget_simple_eval() {
        let width = size_of::<TestCols<u8>>();
        let mut builder = SymbolicConstraintFolder::new(0, width);
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &TestCols<_> = (*local).borrow();

        SubwGadget::<KoalaBear>::eval(
            &mut builder,
            local.a,
            local.b,
            local.subw,
            local.is_real.into(),
        );
    
        assert_eq!(builder.num_constraints(), 5);
        assert_eq!(builder.public_values().len(), 119);
        assert_eq!(builder.num_lookups(), 3);
    }
}
