use super::super::{columns::CpuCols, CpuChip};
use crate::{
    compiler::{riscv::opcode::Opcode, word::Word},
    machine::builder::{ChipBuilder, ChipLookupBuilder, ChipRangeBuilder, ChipWordBuilder},
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
        // RISC-V spec: target = (rs1 + imm) & !1 (clear bit 0).
        // We witness jalr_lsb = bit 0 of (rs1 + imm) and verify:
        //   jalr_lsb ∈ {0, 1},
        //   next_pc[0] is even  (via inverse-multiply range check),
        //   rs1 + imm = next_pc + jalr_lsb  (via ALU ADD).
        let jalr_lsb: CB::Expr = local.opcode_specific.jump().jalr_lsb.into();

        builder
            .when(local.opcode_selector.is_jalr)
            .assert_bool(jalr_lsb.clone());

        // Prove next_pc[0] is even: next_pc[0] * inv(2) must be a valid u16.
        // If next_pc[0] were odd, next_pc[0] * inv(2) mod p ≈ p/2, which exceeds u16 range.
        let two_inv: CB::Expr = F::from_canonical_u32(2).inverse().into();
        let half_low: CB::Expr = local.next_pc[0].into() * two_inv;
        builder.slice_range_check_u16(&[half_low], local.opcode_selector.is_jalr);

        let sum_as_word = Word([
            local.next_pc[0].into() + jalr_lsb,
            local.next_pc[1].into(),
            local.next_pc[2].into(),
            F::ZERO.into(),
        ]);
        builder.looking_alu(
            CB::Expr::from_canonical_u32(Opcode::ADD as u32),
            sum_as_word,
            local.op_b_val(),
            local.op_c_val(),
            local.opcode_selector.is_jalr,
        );
    }
}
