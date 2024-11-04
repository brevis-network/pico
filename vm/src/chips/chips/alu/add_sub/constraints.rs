use crate::{
    chips::{
        chips::alu::add_sub::{columns::AddSubCols, AddSubChip},
        gadgets::add::AddGadget,
    },
    compiler::riscv::opcode::Opcode,
    machine::builder::{ChipBuilder, ChipLookupBuilder},
};
use p3_air::{Air, AirBuilder};
use p3_field::{AbstractField, Field};
use p3_matrix::Matrix;
use std::borrow::Borrow;

impl<F: Field, CB: ChipBuilder<F>> Air<CB> for AddSubChip<F>
where
    CB::Var: Sized,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &AddSubCols<CB::Var> = (*local).borrow();
        let next = main.row_slice(1);
        let next: &AddSubCols<CB::Var> = (*next).borrow();

        // Constrain the incrementing nonce.
        builder.when_first_row().assert_zero(local.nonce);
        builder
            .when_transition()
            .assert_eq(local.nonce + CB::Expr::one(), next.nonce);

        // Evaluate the addition operation.
        AddGadget::<CB::F>::eval(
            builder,
            local.operand_1,
            local.operand_2,
            local.add_operation,
            local.chunk,
            local.channel,
            local.is_add + local.is_sub,
        );

        let opcode = local.is_add * Opcode::ADD.as_field::<CB::F>()
            + local.is_sub * Opcode::SUB.as_field::<CB::F>();

        // Receive the arguments.  There are seperate receives for ADD and SUB.
        // For add, `add_operation.value` is `a`, `operand_1` is `b`, and `operand_2` is `c`.
        builder.looked_alu(
            opcode.clone(),
            local.add_operation.value,
            local.operand_1,
            local.operand_2,
            local.chunk,
            local.channel,
            local.nonce,
            local.is_add,
        );
        // For sub, `operand_1` is `a`, `add_operation.value` is `b`, and `operand_2` is `c`.
        builder.looked_alu(
            opcode,
            local.operand_1,
            local.add_operation.value,
            local.operand_2,
            local.chunk,
            local.channel,
            local.nonce,
            local.is_sub,
        );

        let is_real = local.is_add + local.is_sub;
        builder.assert_bool(local.is_add);
        builder.assert_bool(local.is_sub);
        builder.assert_bool(is_real);
    }
}
