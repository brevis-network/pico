use crate::{
    chips::cpu::{columns::CpuCols, CpuChip},
    gadgets::baby_bear_word::BabyBearWordRangeChecker,
};
use p3_air::AirBuilder;
use p3_field::Field;
use pico_machine::builder::ChipBuilder;

impl<F: Field> CpuChip<F> {
    /// Constraints related to jump operations.
    pub(crate) fn eval_jump_ops<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &CpuCols<CB::Var>,
        next: &CpuCols<CB::Var>,
    ) {
        // Get the jump specific columns
        let jump_columns = local.opcode_specific.jump();

        let is_jump_instruction = local.opcode_selector.is_jal + local.opcode_selector.is_jalr;

        /* TODO: Enable after adding memory read write chip.
                // Verify that the local.pc + 4 is saved in op_a for both jump instructions.
                // When op_a is set to register X0, the RISC-V spec states that the jump instruction will
                // not have a return destination address (it is effectively a GOTO command).  In this case,
                // we shouldn't verify the return address.
                builder
                    .when(is_jump_instruction.clone())
                    .when_not(local.instruction.op_a_0)
                    .assert_eq(
                        local.op_a_val().reduce::<CB>(),
                        local.pc + CB::F::from_canonical_u8(4),
                    );
        */

        // Verify that the word form of local.pc is correct for JAL instructions.
        builder
            .when(local.opcode_selector.is_jal)
            .assert_eq(jump_columns.pc.reduce::<CB>(), local.pc);

        // Verify that the word form of next.pc is correct for both jump instructions.
        builder
            .when_transition()
            .when(next.is_real)
            .when(is_jump_instruction.clone())
            .assert_eq(jump_columns.next_pc.reduce::<CB>(), next.pc);

        // When the last row is real and it's a jump instruction, assert that local.next_pc <==>
        // jump_column.next_pc
        builder
            .when(local.is_real)
            .when(is_jump_instruction.clone())
            .assert_eq(jump_columns.next_pc.reduce::<CB>(), local.next_pc);

        /* TODO: Enable after adding memory read write chip.
                // Range check op_a, pc, and next_pc.
                BabyBearWordRangeChecker::<CB::F>::range_check(
                    builder,
                    local.op_a_val(),
                    jump_columns.op_a_range_checker,
                    is_jump_instruction.clone(),
                );
        */

        BabyBearWordRangeChecker::<CB::F>::range_check(
            builder,
            jump_columns.pc,
            jump_columns.pc_range_checker,
            local.opcode_selector.is_jal.into(),
        );
        BabyBearWordRangeChecker::<CB::F>::range_check(
            builder,
            jump_columns.next_pc,
            jump_columns.next_pc_range_checker,
            is_jump_instruction.clone(),
        );

        /* TODO: Enable after lookup integration.
                // Verify that the new pc is calculated correctly for JAL instructions.
                builder.send_alu(
                    CB::Expr::from_canonical_u32(Opcode::ADD as u32),
                    jump_columns.next_pc,
                    jump_columns.pc,
                    local.op_b_val(),
                    local.shard,
                    local.channel,
                    jump_columns.jal_nonce,
                    local.opcode_selector.is_jal,
                );

                // Verify that the new pc is calculated correctly for JALR instructions.
                builder.send_alu(
                    CB::Expr::from_canonical_u32(Opcode::ADD as u32),
                    jump_columns.next_pc,
                    local.op_b_val(),
                    local.op_c_val(),
                    local.shard,
                    local.channel,
                    jump_columns.jalr_nonce,
                    local.opcode_selector.is_jalr,
                );
        */
    }
}
