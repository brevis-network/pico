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
    builder::ChipBuilder,
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
                    ByteOpcode::AND => self.looked_byte(
                        builder, field_op, local.and, local.b, local.c, chunk, channel_f, mult,
                    ),
                    ByteOpcode::OR => self.looked_byte(
                        builder, field_op, local.or, local.b, local.c, chunk, channel_f, mult,
                    ),
                    ByteOpcode::XOR => self.looked_byte(
                        builder, field_op, local.xor, local.b, local.c, chunk, channel_f, mult,
                    ),
                    ByteOpcode::SLL => self.looked_byte(
                        builder, field_op, local.sll, local.b, local.c, chunk, channel_f, mult,
                    ),
                    ByteOpcode::U8Range => self.looked_byte(
                        builder,
                        field_op,
                        CB::F::zero(),
                        local.b,
                        local.c,
                        chunk,
                        channel_f,
                        mult,
                    ),
                    ByteOpcode::ShrCarry => self.looked_byte_pair(
                        builder,
                        field_op,
                        local.shr,
                        local.shr_carry,
                        local.b,
                        local.c,
                        chunk,
                        channel_f,
                        mult,
                    ),
                    ByteOpcode::LTU => self.looked_byte(
                        builder, field_op, local.ltu, local.b, local.c, chunk, channel_f, mult,
                    ),
                    ByteOpcode::MSB => self.looked_byte(
                        builder,
                        field_op,
                        local.msb,
                        local.b,
                        CB::F::zero(),
                        chunk,
                        channel_f,
                        mult,
                    ),
                    ByteOpcode::U16Range => self.looked_byte(
                        builder,
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

impl<F: Field> ByteChip<F> {
    /// Receives a byte operation to be processed.
    #[allow(clippy::too_many_arguments)]
    fn looked_byte<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        opcode: impl Into<CB::Expr>,
        a: impl Into<CB::Expr>,
        b: impl Into<CB::Expr>,
        c: impl Into<CB::Expr>,
        chunk: impl Into<CB::Expr>,
        channel: impl Into<CB::Expr>,
        multiplicity: impl Into<CB::Expr>,
    ) {
        self.looked_byte_pair(
            builder,
            opcode,
            a,
            CB::Expr::zero(),
            b,
            c,
            chunk,
            channel,
            multiplicity,
        );
    }

    /// Receives a byte operation with two outputs to be processed.
    #[allow(clippy::too_many_arguments)]
    fn looked_byte_pair<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        opcode: impl Into<CB::Expr>,
        a1: impl Into<CB::Expr>,
        a2: impl Into<CB::Expr>,
        b: impl Into<CB::Expr>,
        c: impl Into<CB::Expr>,
        chunk: impl Into<CB::Expr>,
        channel: impl Into<CB::Expr>,
        multiplicity: impl Into<CB::Expr>,
    ) {
        builder.looked(SymbolicLookup::new(
            vec![
                opcode.into(),
                a1.into(),
                a2.into(),
                b.into(),
                c.into(),
                chunk.into(),
                channel.into(),
            ],
            multiplicity.into(),
            LookupType::Byte,
        ));
    }
}
