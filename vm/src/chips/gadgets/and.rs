use crate::{
    chips::chips::byte::event::{ByteLookupEvent, ByteRecordBehavior},
    compiler::{riscv::opcode::ByteOpcode, word::Word},
    machine::builder::ChipLookupBuilder,
    primitives::consts::WORD_SIZE,
};
use p3_field::Field;
use pico_derive::AlignedBorrow;

/// A set of columns needed to compute the and of two words.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct AndOperation<T> {
    /// The result of `x & y`.
    pub value: Word<T>,
}

impl<F: Field> AndOperation<F> {
    pub fn populate(
        &mut self,
        record: &mut impl ByteRecordBehavior,
        chunk: u32,
        x: u32,
        y: u32,
    ) -> u32 {
        let expected = x & y;
        let x_bytes = x.to_le_bytes();
        let y_bytes = y.to_le_bytes();
        for i in 0..WORD_SIZE {
            let and = x_bytes[i] & y_bytes[i];
            self.value[i] = F::from_canonical_u8(and);

            let byte_event = ByteLookupEvent {
                chunk,
                opcode: ByteOpcode::AND,
                a1: and as u16,
                a2: 0,
                b: x_bytes[i],
                c: y_bytes[i],
            };
            record.add_byte_lookup_event(byte_event);
        }
        expected
    }

    #[allow(unused_variables)]
    pub fn eval<CB: ChipLookupBuilder<F>>(
        builder: &mut CB,
        a: Word<CB::Var>,
        b: Word<CB::Var>,
        cols: AndOperation<CB::Var>,
        chunk: CB::Var,
        is_real: CB::Var,
    ) {
        for i in 0..WORD_SIZE {
            builder.looking_byte(
                CB::F::from_canonical_u32(ByteOpcode::AND as u32),
                cols.value[i],
                a[i],
                b[i],
                is_real,
            );
        }
    }
}
