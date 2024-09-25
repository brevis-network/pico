use core::borrow::Borrow;

use p3_air::{Air, BaseAir};
use p3_field::{AbstractField, Field};
use p3_matrix::Matrix;

use pico_compiler::opcode::ByteOpcode;

use super::{
    columns::{ByteMultCols, BytePreprocessedCols, NUM_BYTE_MULT_COLS},
    ByteChip, NUM_BYTE_LOOKUP_CHANNELS,
};

use pico_machine::{
    builder::{ChipBuilder, ChipLookupBuilder},
    lookup::{LookupType, SymbolicLookup},
};

impl<F: Field> BaseAir<F> for ByteChip<F> {
    fn width(&self) -> usize {
        NUM_BYTE_MULT_COLS
    }
}

impl<F: Field, CB: ChipBuilder<F>> Air<CB> for ByteChip<F>
where
    CB::Var: Sized,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local_mult = main.row_slice(0);
        let local_mult: &ByteMultCols<CB::Var> = (*local_mult).borrow();

        let prep = builder.preprocessed();
        let prep = prep.row_slice(0);
        let local: &BytePreprocessedCols<CB::Var> = (*prep).borrow();

        for channel in 0..NUM_BYTE_LOOKUP_CHANNELS {
            let channel_f = CB::F::from_canonical_u8(channel);
            let channel = channel as usize;
            for (i, opcode) in ByteOpcode::all().iter().enumerate() {
                let field_op = opcode.as_field::<CB::F>();
                let mult = local_mult.mult_channels[channel].multiplicities[i];
                let chunk = local_mult.chunk;
                match opcode {
                    ByteOpcode::AND => builder.looked_byte(
                        field_op, local.and, local.b, local.c, chunk, channel_f, mult,
                    ),
                    ByteOpcode::OR => builder
                        .looked_byte(field_op, local.or, local.b, local.c, chunk, channel_f, mult),
                    ByteOpcode::XOR => builder.looked_byte(
                        field_op, local.xor, local.b, local.c, chunk, channel_f, mult,
                    ),
                    ByteOpcode::SLL => builder.looked_byte(
                        field_op, local.sll, local.b, local.c, chunk, channel_f, mult,
                    ),
                    ByteOpcode::U8Range => builder.looked_byte(
                        field_op,
                        CB::F::zero(),
                        local.b,
                        local.c,
                        chunk,
                        channel_f,
                        mult,
                    ),
                    ByteOpcode::ShrCarry => builder.looked_byte_pair(
                        field_op,
                        local.shr,
                        local.shr_carry,
                        local.b,
                        local.c,
                        chunk,
                        channel_f,
                        mult,
                    ),
                    ByteOpcode::LTU => builder.looked_byte(
                        field_op, local.ltu, local.b, local.c, chunk, channel_f, mult,
                    ),
                    ByteOpcode::MSB => builder.looked_byte(
                        field_op,
                        local.msb,
                        local.b,
                        CB::F::zero(),
                        chunk,
                        channel_f,
                        mult,
                    ),
                    ByteOpcode::U16Range => builder.looked_byte(
                        field_op,
                        local.value_u16,
                        CB::F::zero(),
                        CB::F::zero(),
                        chunk,
                        channel_f,
                        mult,
                    ),
                }
            }
        }
    }
}
