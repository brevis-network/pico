use super::{
    columns::{ByteMultCols, BytePreprocessedCols, NUM_BYTE_MULT_COLS},
    ByteChip,
};
use crate::{
    compiler::riscv::opcode::ByteOpcode,
    machine::builder::{ChipBuilder, ChipLookupBuilder},
};
use core::borrow::Borrow;
use p3_air::{Air, BaseAir};
use p3_field::Field;
use p3_matrix::Matrix;

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

        for (i, opcode) in ByteOpcode::all().iter().enumerate() {
            let field_op = opcode.as_field::<CB::F>();
            let mult = local_mult.multiplicities[i];
            match opcode {
                ByteOpcode::AND => builder.looked_byte(field_op, local.and, local.b, local.c, mult),
                ByteOpcode::OR => builder.looked_byte(field_op, local.or, local.b, local.c, mult),
                ByteOpcode::XOR => builder.looked_byte(field_op, local.xor, local.b, local.c, mult),
                ByteOpcode::SLL => builder.looked_byte(field_op, local.sll, local.b, local.c, mult),
                ByteOpcode::ShrCarry => builder.looked_byte_pair(
                    field_op,
                    local.shr,
                    local.shr_carry,
                    local.b,
                    local.c,
                    mult,
                ),
                ByteOpcode::LTU => builder.looked_byte(field_op, local.ltu, local.b, local.c, mult),
                ByteOpcode::MSB => {
                    builder.looked_byte(field_op, local.msb, local.b, CB::F::ZERO, mult)
                }
            }
        }
    }
}
