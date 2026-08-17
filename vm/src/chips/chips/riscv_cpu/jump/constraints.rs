use super::super::{columns::CpuCols, CpuChip};
use crate::{
    compiler::{
        riscv::opcode::{ByteOpcode, Opcode},
        word::Word,
    },
    machine::builder::{ChipBuilder, ChipLookupBuilder, ChipWordBuilder},
};
use p3_air::AirBuilder;
use p3_field::{Field, FieldAlgebra};

impl<F: Field> CpuChip<F> {
    /// Constraints related to jump operations.
    pub(crate) fn eval_jump_ops<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &CpuCols<CB::Var>,
        next: &CpuCols<CB::Var>,
    ) {
        let is_jump_instruction = local.opcode_selector.is_jal + local.opcode_selector.is_jalr;

        // Verify that the local.pc + 4 is saved in op_a for both jump instructions.
        // When op_a is set to register X0, the RISC-V spec states that the jump instruction will
        // not have a return destination address (it is effectively a GOTO command).  In this case,
        // we shouldn't verify the return address.
        let pc_as_word = Word([
            local.pc[0].into(),
            local.pc[1].into(),
            local.pc[2].into(),
            CB::Expr::ZERO,
        ]);
        let op_a_as_word = Word([
            local.op_a_val()[0].into(),
            local.op_a_val()[1].into(),
            local.op_a_val()[2].into(),
            local.op_a_val()[3].into(),
        ]);
        let condition = is_jump_instruction.clone() * (CB::Expr::ONE - local.instruction.op_a_0);
        pc_as_word.add_limb_with_carry(
            builder,
            condition,
            CB::Expr::from_canonical_u8(4),
            op_a_as_word,
            &local.pc_carry_a,
        );

        // Verify that the word form of local.pc is correct for JAL instructions.
        builder
            .when(local.opcode_selector.is_jal)
            .assert_addr_eq(local.pc, local.pc);

        // Verify that the word form of next.pc is correct for both jump instructions.
        builder
            .when_transition()
            .when(next.is_real)
            .when(is_jump_instruction.clone())
            .assert_addr_eq(local.next_pc, next.pc);

        // Assert that the 4th limb (bits 48-63) is 0.
        builder
            .when(is_jump_instruction.clone())
            .assert_zero(local.op_a_val()[3].into());

        // Verify that the new pc is calculated correctly for JAL instructions.
        // Convert Addr to Word (zero-extend to 64-bit)
        let pc_as_word = Word([
            local.pc[0].into(),
            local.pc[1].into(),
            local.pc[2].into(),
            F::ZERO.into(),
        ]);
        let next_pc_as_word = Word([
            local.next_pc[0].into(),
            local.next_pc[1].into(),
            local.next_pc[2].into(),
            F::ZERO.into(),
        ]);
        builder.looking_alu(
            CB::Expr::from_canonical_u32(Opcode::ADD as u32),
            next_pc_as_word.clone(),
            pc_as_word,
            local.op_b_val(),
            local.opcode_selector.is_jal,
        );

        // Verify that the new pc is calculated correctly for JALR instructions.
        //
        // RISC-V clears bit 0 of the target, and the emulator does so (`next_pc = (b + c) & !1`).
        // So `local.next_pc` is the *masked* value while the
        // Add chip is supplied with the *unmasked* sum by `populate_jump`. Dispatching the
        // masked value here makes the tuple unmatchable whenever `rs1 + imm` is odd
        // => regional cumulative sum != 0 => `verifier.rs:391`.
        //
        // Reconstruct the unmasked sum as `next_pc[0] + lsb`.
        //
        // `assert_bool` alone would leave `jalr_lsb` free to slide `next_pc` by one: both
        // `(lsb=0, next_pc=S)` and `(lsb=1, next_pc=S-1)` reproduce the same sum. So also
        // range-check `next_pc[0] / 4` to 14 bits. Because the BitRange table only holds values
        // `< 2^bits`, this forces `next_pc[0]` to be a multiple of 4 below 2^16, which pins
        // `jalr_lsb` to the true bit 0 and additionally rules out targets that are
        // `2 (mod 4)` — those are misaligned instruction fetches that RISC-V traps on, but
        // which `Program::fetch` would otherwise silently truncate into the wrong row.
        //
        // It also means limb 0 cannot overflow: `next_pc[0] <= 0xFFFC`, so
        // `next_pc[0] + lsb <= 0xFFFD`.
        builder.assert_bool(local.jalr_lsb);
        builder.looking_byte(
            CB::F::from_canonical_u32(ByteOpcode::BitRange as u32),
            local.next_pc[0] * CB::F::from_canonical_u32(4).inverse(),
            CB::F::from_canonical_u32(14),
            CB::Expr::ZERO,
            local.opcode_selector.is_jalr,
        );
        let unmasked_target = Word([
            local.next_pc[0] + local.jalr_lsb,
            local.next_pc[1].into(),
            local.next_pc[2].into(),
            CB::Expr::ZERO,
        ]);
        builder.looking_alu(
            CB::Expr::from_canonical_u32(Opcode::ADD as u32),
            unmasked_target,
            local.op_b_val(),
            local.op_c_val(),
            local.opcode_selector.is_jalr,
        );
    }
}
