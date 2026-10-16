use super::super::{columns::CpuCols, CpuChip};
use crate::{
    compiler::{addr::Pc, word::Word},
    emulator::riscv::public_values::PublicValues,
    machine::builder::{ChipBuilder, ChipWordBuilder},
};
use p3_air::AirBuilder;
use p3_field::Field;

impl<F: Field> CpuChip<F> {
    /// Constraints related to the public values.
    pub(crate) fn eval_public_values<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &CpuCols<CB::Var>,
        public_values: &PublicValues<Word<CB::Expr>, CB::Expr>,
    ) {
        // No chunk equation: the chip has no committed chunk column. Every lookup message that
        // names the chunk carries `public_values.execution_chunk` itself (`eval_registers`, the
        // memory dispatch, `eval_ecall`).

        // PV start_pc/next_pc are [T; 3] u16 limbs while a `Pc` has two: the low two limbs are
        // pinned to the row's pc and the third is pinned to zero. The recursion circuit sums all
        // three PV limbs (`mle/compiler/recursion/lowering.rs`), so the PV shape stays [T; 3].
        {
            let pv_start_pc = Pc([
                public_values.start_pc[0].clone(),
                public_values.start_pc[1].clone(),
            ]);
            builder.when_first_row().assert_pc_eq(pv_start_pc, local.pc);
            builder
                .when_first_row()
                .assert_zero(public_values.start_pc[2].clone());

            let pv_next_pc = Pc([
                public_values.next_pc[0].clone(),
                public_values.next_pc[1].clone(),
            ]);
            // The last real row hands its `next_pc` to the public values. That row is named by
            // the `is_last` column, which the row chain defines as the end of the real-row
            // prefix (`eval_row_chain`: N4 on transition rows, N5 on the last row), so exactly
            // one real row carries it. Because that definition is split across the two row
            // selectors, this hand-off relies on `is_transition + is_last_row == 1` holding on
            // every evaluator; `eval_row_chain` names where each one guarantees it.
            builder
                .when(local.is_last)
                .assert_pc_eq(pv_next_pc, local.next_pc);
            builder
                .when(local.is_last)
                .assert_zero(public_values.next_pc[2].clone());
        }
    }
}
