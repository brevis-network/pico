//! A gadget for bitwise operations (XOR, OR, AND) on bytes.
//!

use crate::{
    chips::chips::byte::event::{ByteLookupEvent, ByteRecordBehavior},
    compiler::riscv::opcode::{ByteOpcode, Opcode},
    machine::builder::ChipLookupBuilder,
    primitives::consts::WORD_BYTE_SIZE,
};
use p3_field::Field;
use pico_derive::AlignedBorrow;

/// A set of columns needed to compute the bitwise operation over u64s in byte form.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct BitWiseGadget<T> {
    /// The result of the bitwise operation in bytes.
    pub result: [T; WORD_BYTE_SIZE],
}

impl<F: Field> BitWiseGadget<F> {
    /// Populate the gadget from the given operands and opcode.
    pub fn populate(
        &mut self,
        record: &mut impl ByteRecordBehavior,
        a_u64: u64,
        b_u64: u64,
        c_u64: u64,
        opcode: Opcode,
    ) {
        let a = a_u64.to_le_bytes();
        let b = b_u64.to_le_bytes();
        let c = c_u64.to_le_bytes();

        // Set result to the output value (a)
        self.result = a.map(|x| F::from_canonical_u8(x));

        // Generate byte lookup events
        for ((b_a, b_b), b_c) in a.into_iter().zip(b).zip(c) {
            let byte_event = ByteLookupEvent {
                opcode: ByteOpcode::from(opcode),
                a1: b_a as u16,
                a2: 0,
                b: b_b,
                c: b_c,
            };
            record.add_byte_lookup_event(byte_event);
        }
    }

    /// Evaluate the bitwise operation over two u64s in byte form.
    /// Assumes that `is_real` is boolean.
    /// If `is_real` is true, constrains that the inputs are valid bytes.
    /// If `is_real` is true, constrains that the `result` is the correct result.
    pub fn eval<CB: ChipLookupBuilder<F>>(
        builder: &mut CB,
        a: [CB::Expr; WORD_BYTE_SIZE],
        b: [CB::Expr; WORD_BYTE_SIZE],
        cols: BitWiseGadget<CB::Var>,
        opcode: CB::Expr,
        is_real: CB::Expr,
    ) {
        // The byte table will constrain that, if `is_real` is true:
        // - `a[i], b[i]` are bytes
        // - `result[i] = op(a[i], b[i])`
        for i in 0..WORD_BYTE_SIZE {
            builder.looking_byte(
                opcode.clone(),
                cols.result[i],
                a[i].clone(),
                b[i].clone(),
                is_real.clone(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::machine::folder::SymbolicConstraintFolder;
    use crate::primitives::consts::WORD_BYTE_SIZE;
    use p3_koala_bear::KoalaBear;
    use p3_matrix::Matrix;
    use pico_derive::AlignedBorrow;
    use std::borrow::Borrow;
    use p3_air::AirBuilder;
    use std::mem::size_of;

    #[derive(AlignedBorrow, Clone, Copy)]
    #[repr(C)]
    struct TestCols<T> {
        a: [T; WORD_BYTE_SIZE],
        b: [T; WORD_BYTE_SIZE],
        bitwise: BitWiseGadget<T>,
        opcode: T,
        is_real: T,
    }

    #[test]
    fn test_bitwise_gadget_simple_eval() {
        let width = size_of::<TestCols<u8>>();
        let mut builder = SymbolicConstraintFolder::new(0, width);
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &TestCols<_> = (*local).borrow();

        BitWiseGadget::<KoalaBear>::eval(
            &mut builder,
            local.a.map(|v| v.into()),
            local.b.map(|v| v.into()),
            local.bitwise,
            local.opcode.into(),
            local.is_real.into(),
        );
    }
}
