use super::{columns::EcallChipCols, ecall_message, EcallChip, NUM_EXTRA_CLK_BITS};
use crate::{
    chips::gadgets::{
        field_range_check::word_range::FieldWordRangeChecker, is_zero::IsZeroGadget,
        u16_to_u8::U16ToU8Gadget,
    },
    compiler::{riscv::opcode::ByteOpcode, word::Word},
    emulator::riscv::{public_values::PublicValues, syscalls::SyscallCode},
    machine::{
        builder::{
            ChipBaseBuilder, ChipBuilder, ChipLookupBuilder, ChipRangeBuilder, ChipWordBuilder,
        },
        lookup::{LookupScope, LookupType, SymbolicLookup},
    },
    primitives::consts::RISCV_NUM_PVS,
};
use p3_air::{Air, AirBuilder, WindowAccess};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use std::{array, borrow::Borrow};

impl<F: PrimeField32, CB: ChipBuilder<F>> Air<CB> for EcallChip<F>
where
    CB::Var: Sized,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &EcallChipCols<CB::Var> = (*local).borrow();
        let next = main.next_slice();
        let next: &EcallChipCols<CB::Var> = (*next).borrow();

        let public_values_slice: [CB::Expr; RISCV_NUM_PVS] =
            array::from_fn(|i| builder.public_values()[i].into());
        let public_values: &PublicValues<Word<CB::Expr>, CB::Expr> =
            public_values_slice.as_slice().borrow();

        let is_real: CB::Expr = local.is_real.into();
        builder.assert_bool(local.is_real);

        // Receive the fat message from the Cpu chip (multiplicity `is_ecall` on the Cpu side,
        // `is_real` here): [chunk, clk, op_a_prev(4), op_a_val(4), op_b_val(4), op_c_val(4),
        // num_extra_clk, is_halt].
        let values: Vec<CB::Expr> = ecall_message(
            local.chunk,
            local.clk,
            local.op_a_prev_value,
            local.op_a_value,
            local.op_b_value,
            local.op_c_value,
            local.num_extra_clk,
            local.is_halt,
        );
        builder.looked(SymbolicLookup::new(
            values,
            is_real.clone(),
            LookupType::Ecall,
            LookupScope::Regional,
        ));

        // ── Syscall-code decode (moved from the Cpu chip's eval_ecall) ────────────────────
        // Under the u64 (u16-limb) model, syscall_code[0] is a 16-bit limb containing both
        // syscall_id (low 8 bits) and send_to_table (high 8 bits). Decompose the Word into
        // bytes with the U16ToU8 gadget (safe variant: u8 range checks with mult `is_real`).
        let syscall_code_u16: [CB::Expr; 4] = local.op_a_prev_value.0.map(Into::into);
        let syscall_bytes = U16ToU8Gadget::<CB::F>::eval_u16_to_u8_safe(
            builder,
            syscall_code_u16,
            local.ecall.syscall_code_bytes,
            is_real.clone(),
        );
        let syscall_id = syscall_bytes[0].clone();
        let send_to_table = syscall_bytes[1].clone();

        // Constrain send_to_table to be boolean (0 or 1).
        builder
            .when(is_real.clone())
            .assert_bool(send_to_table.clone());

        // Certify the Cpu-committed num_extra_clk: it must equal byte 2 of the syscall code.
        builder
            .when(is_real.clone())
            .assert_eq(local.num_extra_clk, syscall_bytes[2].clone());
        // ... and cap it at 6 bits. The Cpu row chain steps by `4 + num_extra_clk` and bounds
        // clk as an integer without any range check of its own (`riscv_cpu/chunk_clk`); that
        // argument needs the step small, and a syscall code is a register word a prover may
        // fill freely when `send_to_table` is 0. Honest values are 0, 1 and 48 (SHA_EXTEND).
        builder.looking_byte(
            CB::Expr::from_u8(ByteOpcode::BitRange as u8),
            local.num_extra_clk,
            CB::Expr::from_u8(NUM_EXTRA_CLK_BITS),
            CB::Expr::ZERO,
            is_real.clone(),
        );

        // The committed syscall-send multiplicity: send_to_table on real rows, 0 on padding
        // rows (unconditional, so padding rows cannot emit syscall lookups).
        builder.assert_eq(local.send_to_table, send_to_table * is_real.clone());

        // Assert that op_b and op_c are 48-bit values (upper 16 bits = 0) when sent to the
        // syscall table.
        builder
            .when(local.send_to_table)
            .assert_zero(local.op_b_value[3].into());
        builder
            .when(local.send_to_table)
            .assert_zero(local.op_c_value[3].into());

        let arg1: [_; 3] = [
            local.op_b_value[0],
            local.op_b_value[1],
            local.op_b_value[2],
        ];
        let arg2: [_; 3] = [
            local.op_c_value[0],
            local.op_c_value[1],
            local.op_c_value[2],
        ];
        builder.looking_syscall(
            local.chunk,
            local.clk,
            syscall_id.clone(),
            arg1,
            arg2,
            local.send_to_table,
        );

        // Compute whether this ecall is ENTER_UNCONSTRAINED.
        let is_enter_unconstrained = {
            IsZeroGadget::<CB::F>::eval(
                builder,
                syscall_id.clone()
                    - CB::Expr::from_u32(SyscallCode::ENTER_UNCONSTRAINED.syscall_id()),
                local.ecall.is_enter_unconstrained,
                is_real.clone(),
            );
            local.ecall.is_enter_unconstrained.result
        };

        // Compute whether this ecall is HINT_LEN.
        let is_hint_len = {
            IsZeroGadget::<CB::F>::eval(
                builder,
                syscall_id.clone() - CB::Expr::from_u32(SyscallCode::HINT_LEN.syscall_id()),
                local.ecall.is_hint_len,
                is_real.clone(),
            );
            local.ecall.is_hint_len.result
        };

        // When syscall_id is ENTER_UNCONSTRAINED, the new value of op_a should be 0.
        let zero_word = Word([CB::Expr::ZERO; 4]);
        builder
            .when(is_real.clone() * is_enter_unconstrained)
            .assert_word_eq(local.op_a_value, zero_word);

        // When the syscall is not one of ENTER_UNCONSTRAINED or HINT_LEN, op_a shouldn't change.
        builder
            .when(is_real.clone())
            .when_not(is_enter_unconstrained + is_hint_len)
            .assert_word_eq(local.op_a_value, local.op_a_prev_value);

        // Compute whether this ecall is HALT, and certify the Cpu-committed is_halt bit.
        let is_halt = {
            IsZeroGadget::<CB::F>::eval(
                builder,
                syscall_id.clone() - CB::Expr::from_u32(SyscallCode::HALT.syscall_id()),
                local.ecall.is_halt,
                is_real.clone(),
            );
            local.ecall.is_halt.result
        };
        builder
            .when(is_real.clone())
            .assert_eq(local.is_halt, is_halt);

        // Compute whether this ecall is COMMIT / COMMIT_DEFERRED_PROOFS.
        let is_commit = {
            IsZeroGadget::<CB::F>::eval(
                builder,
                syscall_id.clone() - CB::Expr::from_u32(SyscallCode::COMMIT.syscall_id()),
                local.ecall.is_commit,
                is_real.clone(),
            );
            local.ecall.is_commit.result
        };
        let is_commit_deferred_proofs = {
            IsZeroGadget::<CB::F>::eval(
                builder,
                syscall_id - CB::Expr::from_u32(SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id()),
                local.ecall.is_commit_deferred_proofs,
                is_real.clone(),
            );
            local.ecall.is_commit_deferred_proofs.result
        };

        // The committed operand range-check gate: (is_halt | is_commit_deferred_proofs) on real
        // rows, 0 on padding rows (unconditional).
        builder.assert_eq(
            local.range_check_operand,
            (is_halt + is_commit_deferred_proofs) * is_real.clone(),
        );

        // Range check the operand_to_check word.
        FieldWordRangeChecker::<CB::F>::range_check::<CB>(
            builder,
            local.ecall.operand_to_check,
            local.ecall.operand_range_check_cols,
            local.range_check_operand.into(),
        );

        // HINT_LEN writes a register word that no other constraint makes canonical (the other
        // ecalls keep the previous word or write zero, both canonical already), and the Cpu chip
        // only range-checks the jump rows' return address (`riscv_cpu/register/constraints.rs`).
        // So the four limbs of `op_a_value` are u16-checked here, on HINT_LEN rows only. The
        // committed gate is `is_hint_len` on real rows, 0 on padding rows (unconditional).
        builder.assert_eq(local.hint_len_mul, is_hint_len * is_real.clone());
        builder.slice_range_check_u16(&local.op_a_value.0, local.hint_len_mul);

        // ── HALT: operand binding + exit_code public value (moved from eval_halt_unimpl) ──
        let halt_cond = is_real.clone() * is_halt;
        builder
            .when(halt_cond.clone())
            .assert_word_eq(local.op_b_value, local.ecall.operand_to_check);

        // TODO: check if operand is u32 for halt
        builder.when(halt_cond).assert_eq(
            local.op_b_value.reduce::<CB>(),
            public_values.exit_code.clone(),
        );

        // ── COMMIT_DEFERRED_PROOFS tally ──────────────────────────────────────────────────
        // The digest is bound only on these rows, so the recursion needs to know which chunk ran
        // all eight of them. A running count and `Σ 2^word_index` down the whole trace, padding
        // rows adding nothing, end on the pair the chunk publishes.
        builder.assert_eq(
            local.deferred_commit_mul,
            is_real.clone() * is_commit_deferred_proofs,
        );
        let weight = |cols: &EcallChipCols<CB::Var>| -> CB::Expr {
            cols.ecall
                .index_bitmap
                .iter()
                .enumerate()
                .map(|(i, &b)| b.into() * CB::Expr::from_u32(1 << i))
                .sum()
        };
        builder
            .when_first_row()
            .assert_eq(local.deferred_commits, local.deferred_commit_mul);
        builder.when_first_row().assert_eq(
            local.deferred_commit_mask,
            weight(local) * local.deferred_commit_mul,
        );
        builder.when_transition().assert_eq(
            next.deferred_commits,
            local.deferred_commits + next.deferred_commit_mul,
        );
        builder.when_transition().assert_eq(
            next.deferred_commit_mask,
            weight(next) * next.deferred_commit_mul + local.deferred_commit_mask,
        );
        builder.when_last_row().assert_eq(
            local.deferred_commits,
            public_values.deferred_commits.clone(),
        );
        builder.when_last_row().assert_eq(
            local.deferred_commit_mask,
            public_values.deferred_commit_mask.clone(),
        );

        // ── COMMIT / COMMIT_DEFERRED_PROOFS public values (moved from eval_commit) ────────
        self.eval_commit(
            builder,
            local,
            is_commit.into(),
            is_commit_deferred_proofs.into(),
            public_values.committed_value_digest.clone(),
            public_values.deferred_proofs_digest.clone(),
        );
    }
}

impl<F: PrimeField32> EcallChip<F> {
    /// Constraints related to the COMMIT / COMMIT_DEFERRED_PROOFS ecalls (moved verbatim from
    /// the Cpu chip; `is_ecall` becomes `is_real`, and operand words come from the fat message
    /// — for an ecall, op_b/op_c are register reads, so value == prev_value).
    #[allow(clippy::too_many_arguments)]
    fn eval_commit<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &EcallChipCols<CB::Var>,
        is_commit: CB::Expr,
        is_commit_deferred_proofs: CB::Expr,
        commit_digest: [Word<CB::Expr>; crate::primitives::consts::PV_DIGEST_NUM_WORDS],
        deferred_proofs_digest: [CB::Expr; crate::primitives::consts::DIGEST_SIZE],
    ) {
        // Verify the index bitmap.
        let mut bitmap_sum = CB::Expr::ZERO;
        // They should all be bools.
        for bit in local.ecall.index_bitmap.iter() {
            builder.when(local.is_real).assert_bool(*bit);
            bitmap_sum = bitmap_sum.clone() + (*bit).into();
        }
        // When the syscall is COMMIT, there should be one set bit.
        builder
            .when(local.is_real * (is_commit.clone() + is_commit_deferred_proofs.clone()))
            .assert_one(bitmap_sum.clone());
        // When it's some other syscall, there should be no set bits.
        builder
            .when(
                local.is_real
                    * (CB::Expr::ONE - (is_commit.clone() + is_commit_deferred_proofs.clone())),
            )
            .assert_zero(bitmap_sum);

        // Verify that word_idx corresponds to the set bit in index bitmap.
        for (i, bit) in local.ecall.index_bitmap.iter().enumerate() {
            builder
                .when(*bit * local.is_real)
                .assert_eq(local.op_b_value[0], CB::Expr::from_u32(i as u32));
        }

        // Verify that the 3 upper limbs of the word_idx are 0.
        for i in 0..3 {
            builder
                .when(local.is_real * (is_commit.clone() + is_commit_deferred_proofs.clone()))
                .assert_eq(local.op_b_value[i + 1], CB::Expr::from_u32(0));
        }

        // committed_value_digest is a u32 value (occupies the lower 2 u16 limbs of the
        // register). Each PV `Word` slot stores 4 little-endian *bytes* (not u16 limbs), so we
        // recompose byte pairs into u16 limbs before comparing against the register word.
        let expected_pv_digest_bytes =
            builder.index_word_array(&commit_digest, &local.ecall.index_bitmap);

        let digest_word = local.op_c_value;
        let commit_cond = local.is_real * is_commit;

        // low u16: bytes[0] + bytes[1] * 256 == digest_word[0]
        builder.when(commit_cond.clone()).assert_eq(
            expected_pv_digest_bytes.0[0].clone()
                + expected_pv_digest_bytes.0[1].clone() * CB::Expr::from_u32(1 << 8),
            digest_word[0],
        );
        // high u16: bytes[2] + bytes[3] * 256 == digest_word[1]
        builder.when(commit_cond.clone()).assert_eq(
            expected_pv_digest_bytes.0[2].clone()
                + expected_pv_digest_bytes.0[3].clone() * CB::Expr::from_u32(1 << 8),
            digest_word[1],
        );

        // The two equalities above are 16 equations against 32 unknowns -- four PV byte slots per
        // word, two equations -- and nothing above bounds a limb. The kernel is 16-dimensional,
        // spanned by `k*(e_b1 - 256*e_b0)`, so a prover could move every pair by
        // `(b0, b1) -> (b0 - 256k, b1 + k)` while `digest_word` stayed bit-identical. The
        // recursion layer then packs these limbs base-256 into a Bn254 element, where
        // `256^31 = 2^248` overflows the modulus and wraps the accumulator onto a digest of the
        // prover's choosing. Measured before this check existed: k in {1, 7, 1000000} all proved
        // and verified, while the control `pv[0] += 1` was rejected.
        //
        // Bounding each limb to a byte closes it. `commit_mul` carries the degree-2 gate, and
        // `commit_digest_bytes` mirrors the bitmap-selected public-value word into the main trace,
        // both for the affinity reasons documented on those columns -- the same shape as
        // `range_check_operand` above.
        builder.assert_eq(local.commit_mul, commit_cond);
        builder
            .when(local.commit_mul)
            .assert_word_eq(local.commit_digest_bytes, expected_pv_digest_bytes);
        builder.slice_range_check_u8(&local.commit_digest_bytes.0, local.commit_mul);

        let expected_deferred_proofs_digest_element =
            builder.index_array(&deferred_proofs_digest, &local.ecall.index_bitmap);

        // Verify that the operand that was range checked is digest_word.
        builder
            .when(local.is_real * is_commit_deferred_proofs.clone())
            .assert_word_eq(digest_word, local.ecall.operand_to_check);

        builder
            .when(local.is_real * is_commit_deferred_proofs)
            .assert_eq(
                expected_deferred_proofs_digest_element,
                // TODO: check if operand is u32 for commit_deferred_proofs
                digest_word.reduce::<CB>(),
            );
    }
}
