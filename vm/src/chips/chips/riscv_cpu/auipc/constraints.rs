use super::super::{columns::CpuCols, CpuChip};
use crate::{
    chips::gadgets::baby_bear::word_range::BabyBearWordRangeChecker,
    compiler::riscv::opcode::Opcode,
    machine::builder::{ChipBuilder, ChipLookupBuilder},
};
use p3_air::AirBuilder;
use p3_field::{AbstractField, PrimeField32};

impl<F: PrimeField32> CpuChip<F> {
    /// Constraints related to the AUIPC opcode.
    pub(crate) fn eval_auipc<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &CpuCols<CB::Var>,
    ) {
        // Get the auipc specific columns.
        let auipc_columns = local.opcode_specific.auipc();

        // Verify that the word form of local.pc is correct.
        builder
            .when(local.opcode_selector.is_auipc)
            .assert_eq(auipc_columns.pc.reduce::<CB>(), local.pc);

        // Range check the pc.
        BabyBearWordRangeChecker::<CB::F>::range_check(
            builder,
            auipc_columns.pc,
            auipc_columns.pc_range_checker,
            local.opcode_selector.is_auipc.into(),
        );

        // Verify that op_a == pc + op_b.
        builder.looking_alu(
            CB::Expr::from_canonical_u32(Opcode::ADD as u32),
            local.op_a_val(),
            auipc_columns.pc,
            local.op_b_val(),
            local.chunk,
            local.channel,
            CB::Expr::zero(), // auipc_columns.auipc_nonce,
            local.opcode_selector.is_auipc,
        );
    }
}
