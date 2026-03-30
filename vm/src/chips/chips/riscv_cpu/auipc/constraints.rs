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
        builder.looking_alu(
            CB::Expr::from_canonical_u32(Opcode::ADD as u32),
            local.op_a_val(),
            pc_as_word,
            local.op_b_val(),
            local.opcode_selector.is_auipc,
        );
    }
}
