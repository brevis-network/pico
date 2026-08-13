use super::super::{columns::CpuCols, CpuChip};
use crate::{
    chips::chips::{
        byte::event::ByteRecordBehavior, riscv_cpu::event::CpuEvent,
        riscv_memory::read_write::columns::MemoryCols,
    },
    emulator::riscv::syscalls::SyscallCode,
};
use p3_field::Field;

impl<F: Field> CpuChip<F> {
    /// Populate columns related to ECALL.
    pub(crate) fn populate_ecall(
        &self,
        cols: &mut CpuCols<F>,
        event: &CpuEvent,
        blu_events: &mut impl ByteRecordBehavior,
    ) -> bool {
        let mut is_halt = false;

        if cols.opcode_selector.is_ecall == F::ONE {
            let ecall_cols = cols.opcode_specific.ecall_mut();

            // Populate the u16 → u8 decomposition gadget for the syscall code word.
            let syscall_code_u64 = cols.op_a_access.prev_value().to_u64();
            ecall_cols
                .syscall_code_bytes
                .populate_u16_to_u8_safe(blu_events, syscall_code_u64);

            // Extract individual bytes from the u64 value.
            let syscall_id_byte = (syscall_code_u64 & 0xFF) as u8;
            let send_to_table_byte = ((syscall_code_u64 >> 8) & 0xFF) as u8;
            let syscall_id = F::from_canonical_u8(syscall_id_byte);

            cols.ecall_mul_send_to_table =
                cols.opcode_selector.is_ecall * F::from_canonical_u8(send_to_table_byte);

            // Populate `is_enter_unconstrained`.
            ecall_cols
                .is_enter_unconstrained
                .populate_from_field_element(
                    syscall_id
                        - F::from_canonical_u32(SyscallCode::ENTER_UNCONSTRAINED.syscall_id()),
                );

            // Populate `is_hint_len`.
            ecall_cols.is_hint_len.populate_from_field_element(
                syscall_id - F::from_canonical_u32(SyscallCode::HINT_LEN.syscall_id()),
            );

            // Populate `is_halt`.
            ecall_cols.is_halt.populate_from_field_element(
                syscall_id - F::from_canonical_u32(SyscallCode::HALT.syscall_id()),
            );

            // Populate `is_commit`.
            ecall_cols.is_commit.populate_from_field_element(
                syscall_id - F::from_canonical_u32(SyscallCode::COMMIT.syscall_id()),
            );

            // Populate `is_commit_deferred_proofs`.
            ecall_cols
                .is_commit_deferred_proofs
                .populate_from_field_element(
                    syscall_id
                        - F::from_canonical_u32(SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id()),
                );

            // If the syscall is `COMMIT` or `COMMIT_DEFERRED_PROOFS`, set the index bitmap and
            // digest word.
            if syscall_id == F::from_canonical_u32(SyscallCode::COMMIT.syscall_id())
                || syscall_id
                    == F::from_canonical_u32(SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id())
            {
                let digest_idx = cols.op_b_access.value().to_u32() as usize;
                ecall_cols.index_bitmap[digest_idx] = F::ONE;
            }

            // Pair the `slice_range_check_u8` the AIR emits over `expected_public_values_digest`
            // (`ecall/constraints.rs`, `eval_commit`). Its multiplicity is **`is_ecall`**, so every
            // ecall row is looked up: COMMIT rows carry the selected digest's bytes, every other
            // ecall row carries zeros.
            //
            // The bytes come from `event.c` because that is what is reachable here, and the two
            // equations in `eval_commit` force the public values to agree with `op_c`'s byte
            // decomposition on any honest trace. A forged public value therefore falls outside
            // what these events cover, which is exactly the intent.
            let digest_bytes =
                if syscall_id == F::from_canonical_u32(SyscallCode::COMMIT.syscall_id()) {
                    let word = event.c as u32;
                    [
                        (word & 0xFF) as u8,
                        ((word >> 8) & 0xFF) as u8,
                        ((word >> 16) & 0xFF) as u8,
                        ((word >> 24) & 0xFF) as u8,
                    ]
                } else {
                    [0u8; 4]
                };
            for (slot, b) in ecall_cols
                .expected_public_values_digest
                .iter_mut()
                .zip(digest_bytes)
            {
                *slot = F::from_canonical_u8(b);
            }
            blu_events.add_u8_range_check(digest_bytes[0], digest_bytes[1]);
            blu_events.add_u8_range_check(digest_bytes[2], digest_bytes[3]);

            is_halt = syscall_id == F::from_canonical_u32(SyscallCode::HALT.syscall_id());

            // For halt and commit deferred proofs syscalls, we need to baby bear range check one of
            // it's operands.
            if is_halt {
                ecall_cols.operand_to_check = event.b.into();
                ecall_cols
                    .operand_range_check_cols
                    .populate(blu_events, event.b);
                cols.ecall_range_check_operand = F::ONE;
            }

            if syscall_id == F::from_canonical_u32(SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id())
            {
                ecall_cols.operand_to_check = event.c.into();
                ecall_cols
                    .operand_range_check_cols
                    .populate(blu_events, event.c);
                cols.ecall_range_check_operand = F::ONE;
            }
        }

        is_halt
    }
}
