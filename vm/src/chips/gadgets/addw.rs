use crate::{
    chips::{chips::byte::event::ByteRecordBehavior, gadgets::msb::U16MSBGadget},
    compiler::word::Word,
    machine::builder::{ChipBuilder, ChipRangeBuilder},
    primitives::consts::{u32_to_u16_limbs, WORD_SIZE},
};
use p3_air::AirBuilder;
use p3_field::{Field, FieldAlgebra};
use pico_derive::AlignedBorrow;

/// support u64
/// A set of columns needed to compute the add of two words.
#[derive(AlignedBorrow, Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct AddwGadget<T> {
    /// The result of the ADDW gadget.
    pub value: [T; WORD_SIZE / 2],
    /// The msb of the result.
    pub msb: U16MSBGadget<T>,
}

impl<F: Field> AddwGadget<F> {
    pub fn populate(&mut self, record: &mut impl ByteRecordBehavior, a_u64: u64, b_u64: u64) {
        let value = (a_u64 as u32).wrapping_add(b_u64 as u32);
        let limbs = u32_to_u16_limbs(value);
        self.value = [
            F::from_canonical_u16(limbs[0]),
            F::from_canonical_u16(limbs[1]),
        ];
        // Range check
        record.add_u16_range_checks(&limbs);
        self.msb.populate(record, limbs[1]);
    }

    /// Evaluate the addw gadget.
    /// Assumes that `a`, `b` are valid `Word`s of u16 limbs.
    /// Constrains that `is_real` is boolean.
    /// If `is_real` is true, the `value` is constrained to a the lower u32 of the ADDW result.
    /// Also, the `msb` will be constrained to equal the most significant bit of the `value`.
    pub fn eval<AB: ChipBuilder<F>>(
        builder: &mut AB,
        a: Word<AB::Expr>,
        b: Word<AB::Expr>,
        cols: AddwGadget<AB::Var>,
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
        for i in 0..WORD_SIZE / 2 {
            carry = (a[i].clone() + b[i].clone() - cols.value[i] + carry) * base.inverse();
            builder_is_real.assert_bool(carry.clone());
        }

        // Range check each limb.
        builder.slice_range_check_u16(&cols.value, is_real.clone());

        U16MSBGadget::<AB::F>::eval(builder, cols.value[1].into(), cols.msb, is_real.clone());
    }
}
