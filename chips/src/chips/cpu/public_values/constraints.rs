use crate::{
    chips::cpu::{columns::CpuCols, CpuChip},
    utils::word::Word,
};
use p3_air::AirBuilder;
use p3_field::Field;
use pico_machine::builder::ChipBuilder;

/* TODO: Enable after adding public values.
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
            .assert_eq(public_values.emulation_chunk.clone(), local.chunk);

        // Verify the public value's start pc.
        builder
            .when_first_row()
            .assert_eq(public_values.start_pc.clone(), local.pc);

        // Verify the public value's next pc.  We need to handle two cases:
        // 1. The last real row is a transition row.
        // 2. The last real row is the last row.

        // If the last real row is a transition row, verify the public value's next pc.
        builder
            .when_transition()
            .when(local.is_real - next.is_real)
            .assert_eq(public_values.next_pc.clone(), local.next_pc);

        // If the last real row is the last row, verify the public value's next pc.
        builder
            .when_last_row()
            .when(local.is_real)
            .assert_eq(public_values.next_pc.clone(), local.next_pc);
    }
}
*/
