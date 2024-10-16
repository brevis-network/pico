use super::super::{columns::CpuCols, CpuChip};
use crate::{
    emulator::riscv::events::MemoryAccessPosition,
    machine::builder::{ChipBuilder, ChipRangeBuilder, ChipWordBuilder, RiscVMemoryBuilder},
};
use p3_field::{AbstractField, Field};

impl<F: Field> CpuChip<F> {
    /// Computes whether the opcode is a branch instruction.
    pub(crate) fn eval_registers<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &CpuCols<CB::Var>,
        is_branch_instruction: CB::Expr,
    ) {
        // Load immediates into b and c, if the immediate flags are on.
        builder
            .when(local.opcode_selector.imm_b)
            .assert_word_eq(local.op_b_val(), local.instruction.op_b);
        builder
            .when(local.opcode_selector.imm_c)
            .assert_word_eq(local.op_c_val(), local.instruction.op_c);

        // If they are not immediates, read `b` and `c` from memory.
        builder.eval_memory_access(
            local.chunk,
            local.channel,
            local.clk + CB::F::from_canonical_u32(MemoryAccessPosition::B as u32),
            local.instruction.op_b[0],
            &local.op_b_access,
            CB::Expr::one() - local.opcode_selector.imm_b,
        );

        builder.eval_memory_access(
            local.chunk,
            local.channel,
            local.clk + CB::F::from_canonical_u32(MemoryAccessPosition::C as u32),
            local.instruction.op_c[0],
            &local.op_c_access,
            CB::Expr::one() - local.opcode_selector.imm_c,
        );

        // If we are writing to register 0, then the new value should be zero.
        builder
            .when(local.instruction.op_a_0)
            .assert_word_zero(local.op_a_access.access.value);

        // Write the `a` or the result to the first register described in the instruction unless
        // we are performing a branch or a store.
        builder.eval_memory_access(
            local.chunk,
            local.channel,
            local.clk + CB::F::from_canonical_u32(MemoryAccessPosition::A as u32),
            local.instruction.op_a[0],
            &local.op_a_access,
            local.is_real,
        );

        // Always range check the word value in `op_a`, as JUMP instructions may witness
        // an invalid word and write it to memory.
        builder.slice_range_check_u8(
            &local.op_a_access.access.value.0,
            local.chunk,
            local.channel,
            local.is_real,
        );

        // If we are performing a branch or a store, then the value of `a` is the previous value.
        builder
            .when(
                is_branch_instruction.clone()
                    + self.is_store_instruction::<CB>(&local.opcode_selector),
            )
            .assert_word_eq(local.op_a_val(), local.op_a_access.prev_value);
    }
}
