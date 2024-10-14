use super::{
    columns::{BitwiseCols, NUM_BITWISE_COLS},
    BitwiseChip,
};
use crate::{
    compiler::riscv::opcode::{ByteOpcode, Opcode},
    machine::builder::{ChipBuilder, ChipLookupBuilder},
};
use core::borrow::Borrow;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, Field};
use p3_matrix::Matrix;

impl<F: Field> BaseAir<F> for BitwiseChip<F> {
    fn width(&self) -> usize {
        NUM_BITWISE_COLS
    }
}

impl<F: Field, CB: ChipBuilder<F>> Air<CB> for BitwiseChip<F>
where
    CB::Var: Sized,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &BitwiseCols<CB::Var> = (*local).borrow();
        let next = main.row_slice(1);
        let next: &BitwiseCols<CB::Var> = (*next).borrow();

        // Constrain the incrementing nonce.
        builder.when_first_row().assert_zero(local.nonce);
        builder
            .when_transition()
            .assert_eq(local.nonce + CB::Expr::one(), next.nonce);

        // Get the opcode for the operation.
        let opcode = local.is_xor * ByteOpcode::XOR.as_field::<CB::F>()
            + local.is_or * ByteOpcode::OR.as_field::<CB::F>()
            + local.is_and * ByteOpcode::AND.as_field::<CB::F>();

        let is_real = local.is_xor + local.is_or + local.is_and;
        for ((a, b), c) in local.a.into_iter().zip(local.b).zip(local.c) {
            builder.looking_byte(
                opcode.clone(),
                a,
                b,
                c,
                local.chunk,
                local.channel,
                is_real.clone(),
            );
        }

        // Get the cpu opcode, which corresponds to the opcode being sent in the CPU table.
        let cpu_opcode = local.is_xor * Opcode::XOR.as_field::<CB::F>()
            + local.is_or * Opcode::OR.as_field::<CB::F>()
            + local.is_and * Opcode::AND.as_field::<CB::F>();

        // Looked the ALU arguments.
        builder.looked_alu(
            cpu_opcode,
            local.a,
            local.b,
            local.c,
            local.chunk,
            local.channel,
            CB::Expr::zero(), // local.nonce,
            is_real.clone(),
        );

        builder.assert_bool(local.is_xor);
        builder.assert_bool(local.is_or);
        builder.assert_bool(local.is_and);
        builder.assert_bool(is_real);
    }
}
