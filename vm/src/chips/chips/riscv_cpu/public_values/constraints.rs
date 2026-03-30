use super::super::{columns::CpuCols, CpuChip};
use crate::{
    compiler::{addr::Addr, word::Word},
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
        next: &CpuCols<CB::Var>,
        public_values: &PublicValues<Word<CB::Expr>, CB::Expr>,
    ) {
        // Verify the public value's chunk.
        builder
            .when(local.is_real)
            .assert_eq(public_values.execution_chunk.clone(), local.chunk);

        // PV start_pc/next_pc are [T; 3] u16 limbs — construct Addr directly.
        {
            let pv_start_pc = Addr([
                public_values.start_pc[0].clone(),
                public_values.start_pc[1].clone(),
                public_values.start_pc[2].clone(),
            ]);
            builder
                .when_first_row()
                .assert_addr_eq(pv_start_pc, local.pc);

            let pv_next_pc = Addr([
                public_values.next_pc[0].clone(),
                public_values.next_pc[1].clone(),
                public_values.next_pc[2].clone(),
            ]);
            // If the last real row is a transition row, verify the public value's next pc.
            builder
                .when_transition()
                .when(local.is_real - next.is_real)
                .assert_addr_eq(pv_next_pc.clone(), local.next_pc);

            // If the last real row is the last row, verify the public value's next pc.
            builder
                .when_last_row()
                .when(local.is_real)
                .assert_addr_eq(pv_next_pc, local.next_pc);
        }
    }
}
