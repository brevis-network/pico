use super::super::{columns::CpuCols, CpuChip};
use crate::{
    compiler::{riscv::opcode::Opcode, word::Word},
    machine::builder::{ChipBuilder, ChipLookupBuilder},
};
use p3_field::{FieldAlgebra, PrimeField32};

impl<F: PrimeField32> CpuChip<F> {
    pub(crate) fn eval_auipc<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &CpuCols<CB::Var>,
    ) {
        let pc_as_word = Word([
            local.pc[0].into(),
            local.pc[1].into(),
            local.pc[2].into(),
            F::ZERO.into(),
        ]);

        // Verify that op_a == pc + op_b.
        //
        // Same rule as the ALU dispatch -- when the destination is `x0` the register file pins
        // `op_a_val()` to zero, so dispatching would ask the Add chip for `(ADD, 0, pc, imm)`
        // while `populate_auipc` supplies `(ADD, pc + imm, pc, imm)`. Gate both sides off.
        builder.assert_eq(
            local.is_auipc_not_x0,
            local.opcode_selector.is_auipc * (CB::Expr::ONE - local.instruction.op_a_0),
        );
        builder.looking_alu(
            CB::Expr::from_canonical_u32(Opcode::ADD as u32),
            local.op_a_val(),
            pc_as_word,
            local.op_b_val(),
            local.is_auipc_not_x0,
        );
    }
}
