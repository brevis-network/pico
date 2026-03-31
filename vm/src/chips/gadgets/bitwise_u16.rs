//! A gadget for bitwise operations (XOR, OR, AND) on u64 values represented as 4 u16 limbs.
//!

use super::{bitwise::BitWiseGadget, u16_to_u8::U16ToU8Gadget};
use crate::{
    chips::chips::byte::event::ByteRecordBehavior,
    compiler::{riscv::opcode::Opcode, word::Word},
    machine::builder::ChipLookupBuilder,
};
use p3_field::Field;
use pico_derive::AlignedBorrow;

/// A set of columns needed to compute the bitwise operation over Word of u16 limbs.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct BitWiseU16Gadget<T> {
    /// Lower byte of the limbs of `b`.
    pub b_low_bytes: U16ToU8Gadget<T>,

    /// Lower byte of the limbs of `c`.
    pub c_low_bytes: U16ToU8Gadget<T>,

    /// The bitwise operation over bytes.
    pub bitwise: BitWiseGadget<T>,
}

impl<F: Field> BitWiseU16Gadget<F> {
    /// Populate the gadget from the given operands and opcode.
    pub fn populate(
        &mut self,
        record: &mut impl ByteRecordBehavior,
        a_u64: u64,
        b_u64: u64,
        c_u64: u64,
        opcode: Opcode,
    ) {
        self.b_low_bytes.populate_u16_to_u8_unsafe(b_u64);
        self.c_low_bytes.populate_u16_to_u8_unsafe(c_u64);

        // Populate the bitwise operation directly
        // The bitwise gadget will handle the byte conversions internally
        self.bitwise.populate(record, a_u64, b_u64, c_u64, opcode);
    }

    /// Evaluate the bitwise operation over two Words of u16 limbs.
    /// Assumes that the two words are valid Words of u16 limbs.
    /// Assumes that `opcode` is a valid byte opcode.
    /// Constrains that `is_real` is boolean.
    /// If `is_real` is true, the return value is constrained to be correct.
    pub fn eval<CB: ChipLookupBuilder<F>>(
        builder: &mut CB,
        b: Word<CB::Expr>,
        c: Word<CB::Expr>,
        cols: BitWiseU16Gadget<CB::Var>,
        opcode: CB::Expr,
        is_real: CB::Expr,
    ) -> Word<CB::Expr> {
        // Constrain that `is_real` is boolean.
        builder.assert_bool(is_real.clone());

        let b_bytes = U16ToU8Gadget::eval_u16_to_u8_unsafe(builder, b.0, cols.b_low_bytes);
        let c_bytes = U16ToU8Gadget::eval_u16_to_u8_unsafe(builder, c.0, cols.c_low_bytes);

        // Evaluate the bitwise operation
        BitWiseGadget::<F>::eval(
            builder,
            b_bytes,
            c_bytes,
            cols.bitwise,
            opcode,
            is_real.clone(),
        );

        // Combine the byte results into u16 limbs.
        let result_limb0 =
            cols.bitwise.result[0] + cols.bitwise.result[1] * CB::F::from_canonical_u32(256);
        let result_limb1 =
            cols.bitwise.result[2] + cols.bitwise.result[3] * CB::F::from_canonical_u32(256);
        let result_limb2 =
            cols.bitwise.result[4] + cols.bitwise.result[5] * CB::F::from_canonical_u32(256);
        let result_limb3 =
            cols.bitwise.result[6] + cols.bitwise.result[7] * CB::F::from_canonical_u32(256);
        Word([result_limb0, result_limb1, result_limb2, result_limb3])
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
        b: Word<T>,
        c: Word<T>,
        bitwise_u16: BitWiseU16Gadget<T>,
        opcode: T,
        is_real: T,
    }

    #[test]
    fn test_bitwise_u16_gadget_simple_eval() {
        let width = size_of::<TestCols<u8>>();
        let mut builder = SymbolicConstraintFolder::new(0, width);
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &TestCols<_> = (*local).borrow();

        BitWiseU16Gadget::<KoalaBear>::eval(
            &mut builder,
            local.b.map(|v| v.into()),
            local.c.map(|v| v.into()),
            local.bitwise_u16,
            local.opcode.into(),
            local.is_real.into(),
        );
    }
}
