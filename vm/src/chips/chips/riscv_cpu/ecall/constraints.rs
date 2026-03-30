use super::super::{columns::CpuCols, opcode_selector::columns::OpcodeSelectorCols, CpuChip};
use crate::{
    chips::{
        chips::riscv_memory::read_write::columns::MemoryCols,
        gadgets::{
            field_range_check::word_range::FieldWordRangeChecker, is_zero::IsZeroGadget,
            u16_to_u8::U16ToU8Gadget,
        },
    },
    compiler::word::Word,
    emulator::riscv::{public_values::PublicValues, syscalls::SyscallCode},
    machine::builder::{ChipBaseBuilder, ChipBuilder, ChipLookupBuilder, ChipWordBuilder},
    primitives::consts::{DIGEST_SIZE, PV_DIGEST_NUM_WORDS},
};
use p3_air::AirBuilder;
use p3_field::{Field, FieldAlgebra};

impl<F: Field> CpuChip<F> {
    /// Whether the instruction is an ECALL instruction.
    pub(crate) fn is_ecall_instruction<CB: ChipBuilder<F>>(
        &self,
        opcode_selectors: &OpcodeSelectorCols<CB::Var>,
    ) -> CB::Expr {
        opcode_selectors.is_ecall.into()
    }

    /// Constraints related to the ECALL opcode.
    ///
    /// This method will do the following:
    /// 1. Send the syscall to the precompile table, if needed.
    /// 2. Check for valid op_a values.
    pub(crate) fn eval_ecall<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &CpuCols<CB::Var>,
    ) {
        let ecall_cols = local.opcode_specific.ecall();
        let is_ecall_instruction = self.is_ecall_instruction::<CB>(&local.opcode_selector);

        // The syscall code is the read-in value of op_a at the start of the instruction.
        let syscall_code = local.op_a_access.prev_value();

        // Under the u64 (u16-limb) model, syscall_code[0] is a 16-bit limb containing
        // both syscall_id (low 8 bits) and send_to_table (high 8 bits).
        // Use U16ToU8Gadget to decompose the Word into individual bytes.
        let syscall_code_u16: [CB::Expr; 4] = syscall_code.0.map(Into::into);
        let syscall_bytes = U16ToU8Gadget::<CB::F>::eval_u16_to_u8_safe(
            builder,
            syscall_code_u16,
            ecall_cols.syscall_code_bytes,
            is_ecall_instruction.clone(),
        );
        let syscall_id = syscall_bytes[0].clone();
        let send_to_table = syscall_bytes[1].clone();

        // Constrain send_to_table to be boolean (0 or 1).
        builder
            .when(is_ecall_instruction.clone())
            .assert_bool(send_to_table.clone());

        // Constrain num_extra_clk to equal byte 2 of the syscall code.
        // In u16-limb model, byte 2 is the low byte of limb[1]. Using the decomposed
        // byte from U16ToU8Gadget is more precise than using the full u16 limb.
        builder
            .when(is_ecall_instruction.clone())
            .assert_eq(local.num_extra_clk, syscall_bytes[2].clone());

        // Handle cases:
        // - is_ecall_instruction = 1 => ecall_mul_send_to_table == send_to_table
        // - is_ecall_instruction = 0 => ecall_mul_send_to_table == 0
        builder.assert_eq(
            local.ecall_mul_send_to_table,
            send_to_table * is_ecall_instruction.clone(),
        );

        // Assert that op_b and op_c are 48-bit values (upper 16 bits = 0).
        builder
            .when(local.ecall_mul_send_to_table)
            .assert_zero(local.op_b_val()[3].into());
        builder
            .when(local.ecall_mul_send_to_table)
            .assert_zero(local.op_c_val()[3].into());

        let op_b_val = local.op_b_val();
        let op_c_val = local.op_c_val();
        let arg1: [_; 3] = [op_b_val[0], op_b_val[1], op_b_val[2]];
        let arg2: [_; 3] = [op_c_val[0], op_c_val[1], op_c_val[2]];

        builder.looking_syscall(
            local.clk,
            syscall_id.clone(),
            arg1,
            arg2,
            local.ecall_mul_send_to_table,
        );

        // Compute whether this ecall is ENTER_UNCONSTRAINED.
        let is_enter_unconstrained = {
            IsZeroGadget::<CB::F>::eval(
                builder,
                syscall_id.clone()
                    - CB::Expr::from_canonical_u32(SyscallCode::ENTER_UNCONSTRAINED.syscall_id()),
                ecall_cols.is_enter_unconstrained,
                is_ecall_instruction.clone(),
            );
            ecall_cols.is_enter_unconstrained.result
        };

        // Compute whether this ecall is HINT_LEN.
        let is_hint_len = {
            IsZeroGadget::<CB::F>::eval(
                builder,
                syscall_id - CB::Expr::from_canonical_u32(SyscallCode::HINT_LEN.syscall_id()),
                ecall_cols.is_hint_len,
                is_ecall_instruction.clone(),
            );
            ecall_cols.is_hint_len.result
        };

        // When syscall_id is ENTER_UNCONSTRAINED, the new value of op_a should be 0.
        let zero_word = Word([CB::Expr::ZERO; 4]);
        builder
            .when(is_ecall_instruction.clone() * is_enter_unconstrained)
            .assert_word_eq(local.op_a_val(), zero_word);

        // When the syscall is not one of ENTER_UNCONSTRAINED or HINT_LEN, op_a shouldn't change.
        builder
            .when(is_ecall_instruction.clone())
            .when_not(is_enter_unconstrained + is_hint_len)
            .assert_word_eq(local.op_a_val(), local.op_a_access.prev_value);

        // Verify value of ecall_range_check_operand column.
        builder.assert_eq(
            local.ecall_range_check_operand,
            is_ecall_instruction
                * (ecall_cols.is_halt.result + ecall_cols.is_commit_deferred_proofs.result),
        );

        // Range check the operand_to_check word.
        FieldWordRangeChecker::<CB::F>::range_check::<CB>(
            builder,
            ecall_cols.operand_to_check,
            ecall_cols.operand_range_check_cols,
            local.ecall_range_check_operand.into(),
        );
    }

    /// Constraints related to the COMMIT instruction.
    pub(crate) fn eval_commit<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &CpuCols<CB::Var>,
        commit_digest: [Word<CB::Expr>; PV_DIGEST_NUM_WORDS],
        deferred_proofs_digest: [CB::Expr; DIGEST_SIZE],
    ) {
        let (is_commit, is_commit_deferred_proofs) =
            self.get_is_commit_related_syscall(builder, local);

        // Get the ecall specific columns.
        let ecall_columns = local.opcode_specific.ecall();

        // Verify the index bitmap.
        let mut bitmap_sum = CB::Expr::ZERO;
        // They should all be bools.
        for bit in ecall_columns.index_bitmap.iter() {
            builder
                .when(local.opcode_selector.is_ecall)
                .assert_bool(*bit);
            bitmap_sum = bitmap_sum.clone() + (*bit).into();
        }
        // When the syscall is COMMIT, there should be one set bit.
        builder
            .when(
                local.opcode_selector.is_ecall
                    * (is_commit.clone() + is_commit_deferred_proofs.clone()),
            )
            .assert_one(bitmap_sum.clone());
        // When it's some other syscall, there should be no set bits.
        builder
            .when(
                local.opcode_selector.is_ecall
                    * (CB::Expr::ONE - (is_commit.clone() + is_commit_deferred_proofs.clone())),
            )
            .assert_zero(bitmap_sum);

        // Verify that word_idx corresponds to the set bit in index bitmap.
        for (i, bit) in ecall_columns.index_bitmap.iter().enumerate() {
            builder
                .when(*bit * local.opcode_selector.is_ecall)
                .assert_eq(
                    local.op_b_access.prev_value()[0],
                    CB::Expr::from_canonical_u32(i as u32),
                );
        }

        // Verify that the 3 upper bytes of the word_idx are 0.
        for i in 0..3 {
            builder
                .when(
                    local.opcode_selector.is_ecall
                        * (is_commit.clone() + is_commit_deferred_proofs.clone()),
                )
                .assert_eq(
                    local.op_b_access.prev_value()[i + 1],
                    CB::Expr::from_canonical_u32(0),
                );
        }

        // TODO: committed_value_digest is a u32 value (occupies only limbs[0] and limbs[1]).
        // In rv64, the register (op_c) may hold a sign-extended 64-bit value,
        // so we only compare the lower 2 limbs.
        let expected_pv_digest_word =
            builder.index_word_array(&commit_digest, &ecall_columns.index_bitmap);

        let digest_word = local.op_c_access.prev_value();
        let commit_cond = local.opcode_selector.is_ecall * is_commit;

        // Verify the public_values_digest_word.
        builder
            .when(commit_cond.clone())
            .assert_eq(expected_pv_digest_word[0].clone(), digest_word[0]);
        builder
            .when(commit_cond)
            .assert_eq(expected_pv_digest_word[1].clone(), digest_word[1]);

        let expected_deferred_proofs_digest_element =
            builder.index_array(&deferred_proofs_digest, &ecall_columns.index_bitmap);

        // Verify that the operand that was range checked is digest_word.
        builder
            .when(local.opcode_selector.is_ecall * is_commit_deferred_proofs.clone())
            .assert_word_eq(*digest_word, ecall_columns.operand_to_check);

        builder
            .when(local.opcode_selector.is_ecall * is_commit_deferred_proofs)
            .assert_eq(
                expected_deferred_proofs_digest_element,
                // TODO: check if operand is u32 for commit_deferred_proofs
                digest_word.reduce::<CB>(),
            );
    }

    /// Constraint related to the halt and unimpl instruction.
    pub(crate) fn eval_halt_unimpl<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &CpuCols<CB::Var>,
        next: &CpuCols<CB::Var>,
        public_values: &PublicValues<Word<CB::Expr>, CB::Expr>,
    ) {
        let is_halt = self.get_is_halt_syscall(builder, local);

        // If we're halting and it's a transition, then the next.is_real should be 0.
        builder
            .when_transition()
            .when(is_halt.clone() + local.opcode_selector.is_unimpl)
            .assert_zero(next.is_real);

        builder
            .when(is_halt.clone())
            .assert_addr_zero(local.next_pc);

        // Verify that the operand that was range checked is op_b.
        let ecall_columns = local.opcode_specific.ecall();
        builder
            .when(is_halt.clone())
            .assert_word_eq(local.op_b_val(), ecall_columns.operand_to_check);

        // TODO: check if operand is u32 for halt
        builder.when(is_halt.clone()).assert_eq(
            local.op_b_access.value().reduce::<CB>(),
            public_values.exit_code.clone(),
        );
    }

    /// Returns a boolean expression indicating whether the instruction is a HALT instruction.
    pub(crate) fn get_is_halt_syscall<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &CpuCols<CB::Var>,
    ) -> CB::Expr {
        let ecall_cols = local.opcode_specific.ecall();
        let is_ecall_instruction = self.is_ecall_instruction::<CB>(&local.opcode_selector);

        // The syscall code is the read-in value of op_a at the start of the instruction.
        let syscall_code = local.op_a_access.prev_value();

        // Use U16ToU8Gadget (unsafe variant — range check already done in eval_ecall).
        let syscall_code_u16: [CB::Expr; 4] = syscall_code.0.map(Into::into);
        let syscall_bytes = U16ToU8Gadget::<CB::F>::eval_u16_to_u8_unsafe(
            builder,
            syscall_code_u16,
            ecall_cols.syscall_code_bytes,
        );
        let syscall_id = syscall_bytes[0].clone();

        // Compute whether this ecall is HALT.
        let is_halt = {
            IsZeroGadget::<CB::F>::eval(
                builder,
                syscall_id - CB::Expr::from_canonical_u32(SyscallCode::HALT.syscall_id()),
                ecall_cols.is_halt,
                is_ecall_instruction.clone(),
            );
            ecall_cols.is_halt.result
        };

        is_halt * is_ecall_instruction
    }

    /// Returns boolean expression indicating whether the instruction is a COMMIT instruction.
    pub(crate) fn get_is_commit_related_syscall<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &CpuCols<CB::Var>,
    ) -> (CB::Expr, CB::Expr) {
        let ecall_cols = local.opcode_specific.ecall();

        let is_ecall_instruction = self.is_ecall_instruction::<CB>(&local.opcode_selector);

        // The syscall code is the read-in value of op_a at the start of the instruction.
        let syscall_code = local.op_a_access.prev_value();

        // Use U16ToU8Gadget (unsafe variant — range check already done in eval_ecall).
        let syscall_code_u16: [CB::Expr; 4] = syscall_code.0.map(Into::into);
        let syscall_bytes = U16ToU8Gadget::<CB::F>::eval_u16_to_u8_unsafe(
            builder,
            syscall_code_u16,
            ecall_cols.syscall_code_bytes,
        );
        let syscall_id = syscall_bytes[0].clone();

        // Compute whether this ecall is COMMIT.
        let is_commit = {
            IsZeroGadget::<CB::F>::eval(
                builder,
                syscall_id.clone() - CB::Expr::from_canonical_u32(SyscallCode::COMMIT.syscall_id()),
                ecall_cols.is_commit,
                is_ecall_instruction.clone(),
            );
            ecall_cols.is_commit.result
        };

        // Compute whether this ecall is COMMIT_DEFERRED_PROOFS.
        let is_commit_deferred_proofs = {
            IsZeroGadget::<CB::F>::eval(
                builder,
                syscall_id
                    - CB::Expr::from_canonical_u32(
                        SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id(),
                    ),
                ecall_cols.is_commit_deferred_proofs,
                is_ecall_instruction.clone(),
            );
            ecall_cols.is_commit_deferred_proofs.result
        };

        (is_commit.into(), is_commit_deferred_proofs.into())
    }

    /// Returns the number of extra cycles from an ECALL instruction.
    pub(crate) fn get_num_extra_ecall_cycles<CB: ChipBuilder<F>>(
        &self,
        local: &CpuCols<CB::Var>,
    ) -> CB::Expr {
        let is_ecall_instruction = self.is_ecall_instruction::<CB>(&local.opcode_selector);

        local.num_extra_clk * is_ecall_instruction.clone()
    }
}
