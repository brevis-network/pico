use super::{
    columns::{EcallChipCols, NUM_ECALL_CHIP_COLS},
    EcallChip, NUM_EXTRA_CLK_BITS,
};
use crate::{
    chips::{
        chips::{byte::event::ByteRecordBehavior, riscv_cpu::event::CpuEvent},
        gadgets::field_range_check::word_range::FieldWordRangeChecker,
        utils::pad_rows_fixed,
    },
    compiler::{riscv::program::Program, word::Word},
    emulator::riscv::{record::EmulationRecord, syscalls::SyscallCode},
    iter::{IntoPicoIterator, PicoIterator, PicoSlice},
    machine::chip::ChipBehavior,
};
use p3_air::BaseAir;
use p3_field::{Field, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::BorrowMut;

impl<F: Field> BaseAir<F> for EcallChip<F> {
    fn width(&self) -> usize {
        NUM_ECALL_CHIP_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        None
    }
}

/// `Σ bitmap[i]·2^i`: `2^word_index` for a row whose index bitmap is one-hot.
fn bitmap_weight<F: PrimeField32>(bitmap: &[F]) -> F {
    bitmap
        .iter()
        .enumerate()
        .map(|(i, &b)| b * F::from_u32(1 << i))
        .sum()
}

/// The word index a COMMIT_DEFERRED_PROOFS ecall writes, or `None` for any other event.
fn deferred_commit_index(event: &CpuEvent) -> Option<u32> {
    let code = (event.op_a_prev_value() & 0xFF) as u32;
    (event.instruction.is_ecall_instruction()
        && code == SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id())
    .then(|| (event.op_b_committed_value() & 0xFFFF_FFFF) as u32)
}

/// The chunk's COMMIT_DEFERRED_PROOFS tally the Ecall air publishes: how many ran, and the sum of
/// `2^word_index` over them. The public values and the trace's running sums both come from here.
pub fn deferred_commit_tally(events: &[CpuEvent]) -> (u32, u32) {
    let tally = |events: &[CpuEvent]| {
        events
            .iter()
            .filter_map(deferred_commit_index)
            .fold((0, 0), |(n, mask), idx| (n + 1, mask + (1u32 << idx)))
    };
    // A chunk holds millions of events and the tally reads each one's opcode.
    let chunk = std::cmp::max(events.len() / num_cpus::get(), 1);
    events
        .pico_chunks(chunk)
        .map(tally)
        .collect::<Vec<_>>()
        .into_iter()
        .fold((0, 0), |(n, m), (dn, dm)| (n + dn, m + dm))
}

impl<F: PrimeField32> EcallChip<F> {
    /// Build one Ecall-chip row from an ECALL cpu event, emitting the byte lookups that the
    /// U16ToU8 safe decomposition requires.
    fn event_to_row(
        &self,
        event: &CpuEvent,
        cols: &mut EcallChipCols<F>,
        blu_events: &mut impl ByteRecordBehavior,
    ) {
        debug_assert!(event.instruction.is_ecall_instruction());

        cols.chunk = F::from_u32(event.chunk);
        cols.clk = F::from_u32(u32::try_from(event.clk).unwrap());

        let syscall_code_u64 = event.op_a_prev_value();
        let op_b_value = event.op_b_committed_value();
        let op_c_value = event.op_c_committed_value();
        cols.op_a_prev_value = Word::from(syscall_code_u64);
        cols.op_a_value = Word::from(event.op_a_committed_value());
        cols.op_b_value = Word::from(op_b_value);
        cols.op_c_value = Word::from(op_c_value);

        // Populate the u16 → u8 decomposition gadget for the syscall code word.
        cols.ecall
            .syscall_code_bytes
            .populate_u16_to_u8_safe(blu_events, syscall_code_u64);

        let syscall_id_byte = (syscall_code_u64 & 0xFF) as u8;
        let send_to_table_byte = ((syscall_code_u64 >> 8) & 0xFF) as u8;
        let num_extra_clk_byte = ((syscall_code_u64 >> 16) & 0xFF) as u8;
        let syscall_id = F::from_u8(syscall_id_byte);

        cols.num_extra_clk = F::from_u8(num_extra_clk_byte);
        cols.send_to_table = F::from_u8(send_to_table_byte);

        // Populate the IsZero decode gadgets.
        cols.ecall
            .is_enter_unconstrained
            .populate_from_field_element(
                syscall_id - F::from_u32(SyscallCode::ENTER_UNCONSTRAINED.syscall_id()),
            );
        cols.ecall.is_hint_len.populate_from_field_element(
            syscall_id - F::from_u32(SyscallCode::HINT_LEN.syscall_id()),
        );
        // The HINT_LEN return-value range-check gate; its four U16Range events are emitted by
        // `extra_record` (host path) / the ecall kernel (GPU path).
        cols.hint_len_mul =
            F::from_bool(u32::from(syscall_id_byte) == SyscallCode::HINT_LEN.syscall_id());
        cols.ecall
            .is_halt
            .populate_from_field_element(syscall_id - F::from_u32(SyscallCode::HALT.syscall_id()));
        cols.ecall.is_commit.populate_from_field_element(
            syscall_id - F::from_u32(SyscallCode::COMMIT.syscall_id()),
        );
        cols.ecall
            .is_commit_deferred_proofs
            .populate_from_field_element(
                syscall_id - F::from_u32(SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id()),
            );

        // If the syscall is `COMMIT` or `COMMIT_DEFERRED_PROOFS`, set the index bitmap.
        if syscall_id == F::from_u32(SyscallCode::COMMIT.syscall_id())
            || syscall_id == F::from_u32(SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id())
        {
            let digest_idx = (op_b_value & 0xFFFF_FFFF) as usize;
            cols.ecall.index_bitmap[digest_idx] = F::ONE;
        }

        // Mirror the selected public-value digest bytes into the main trace and feed the two u8
        // range checks the AIR looks up for them.
        //
        // On an honest trace those bytes are the little-endian bytes of the u32 the guest passed
        // in a1: `CommitSyscall` stores `decode_u32_abi_word(arg2)` into
        // `public_values.committed_value_digest[word_idx]`, `PublicValues::from` splits that u32
        // into 4 LE bytes, and `arg2` is op_c -- which the fat message delivers here as
        // `op_c_value`. The `as u32` truncation is required, not incidental: the guest ABI allows
        // a sign-extended 32-bit word in the RV64 register.
        //
        // Multiplicity: `commit_mul` is 1 on exactly these rows and 0 everywhere else (including
        // COMMIT_DEFERRED_PROOFS and padding), and `slice_range_check_u8` chunks the 4 limbs in
        // pairs => exactly 2 events per row, emitted in `extra_record`.
        if syscall_id == F::from_u32(SyscallCode::COMMIT.syscall_id()) {
            let digest_bytes = (op_c_value as u32).to_le_bytes();
            cols.commit_digest_bytes = Word(core::array::from_fn(|i| F::from_u8(digest_bytes[i])));
            cols.commit_mul = F::ONE;
            // The byte-lookup events for these four limbs are emitted by `extra_record`, not
            // here: this sink is discarded by `build_host_trace_values` (see the comment at its
            // `let mut blu = Vec::new()`).

            // TEST-ONLY, and load-bearing for the security argument. `vm/examples/test_cvd_forgery.rs`
            // doctors only the chunk's public values, which leaves this mirror column honest -- so
            // the equality constraint above rejects every forgery on its own and the u8 range check
            // is never exercised. Measured on the previous chip layout: with the range check deleted
            // and the equality kept, that harness still reported PASS while the forgery went
            // through. This hook hands the attacker the mirror column too, so the range-check
            // lookup is the ONLY thing left that can catch it, and a green run means what it claims.
            //
            // The events in `extra_record` are deliberately NOT forged with it: they stay honest,
            // so the forged mirror has no row in the byte table and the logup cannot balance.
            #[cfg(feature = "test-utils")]
            if let Ok(k) = std::env::var("CVD_FORGE_K") {
                let k: u32 = k.parse().expect("CVD_FORGE_K must be a u32");
                let kf = F::from_u32(k);
                let k256 = kf * F::from_u32(256);
                for j in 0..2 {
                    cols.commit_digest_bytes.0[2 * j] -= k256;
                    cols.commit_digest_bytes.0[2 * j + 1] += kf;
                }
            }
        }

        let is_halt = syscall_id == F::from_u32(SyscallCode::HALT.syscall_id());
        cols.is_halt = F::from_bool(is_halt);

        // For halt and commit_deferred_proofs syscalls, range check one of the operands.
        if is_halt {
            cols.ecall.operand_to_check = op_b_value.into();
            cols.ecall
                .operand_range_check_cols
                .populate(blu_events, op_b_value);
            cols.range_check_operand = F::ONE;
        }
        if syscall_id == F::from_u32(SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id()) {
            cols.deferred_commit_mul = F::ONE;
            cols.ecall.operand_to_check = op_c_value.into();
            cols.ecall
                .operand_range_check_cols
                .populate(blu_events, op_c_value);
            cols.range_check_operand = F::ONE;
        }

        cols.is_real = F::ONE;
    }

    /// Build the padded, row-major host trace values for a record (the body of
    /// `generate_main`), scanning `cpu_events` in parallel.
    pub fn build_host_trace_values(input: &EmulationRecord) -> Vec<F> {
        let chip = Self::default();
        let events = input.cpu_events.as_slice();
        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);
        let mut rows: Vec<[F; NUM_ECALL_CHIP_COLS]> = events
            .pico_chunks(chunk_size)
            .flat_map_iter(|events| {
                events
                    .iter()
                    .filter(|e| e.instruction.is_ecall_instruction())
                    .map(|event| {
                        let mut row = [F::ZERO; NUM_ECALL_CHIP_COLS];
                        let cols: &mut EcallChipCols<F> = row.as_mut_slice().borrow_mut();
                        // Byte lookups are emitted by `extra_record`; drop the ones collected
                        // here.
                        let mut blu = Vec::new();
                        chip.event_to_row(event, cols, &mut blu);
                        row
                    })
            })
            .collect();

        // Pad the trace to a power of two depending on the proof shape in `input`.
        let log_rows = input.shape_chip_size(&chip.name());
        pad_rows_fixed(&mut rows, || [F::ZERO; NUM_ECALL_CHIP_COLS], log_rows);

        // The tally runs down every row, padding included, so the last row carries the chunk's.
        let (mut count, mut mask) = (F::ZERO, F::ZERO);
        for row in rows.iter_mut() {
            let cols: &mut EcallChipCols<F> = row.as_mut_slice().borrow_mut();
            count += cols.deferred_commit_mul;
            mask += cols.deferred_commit_mul * bitmap_weight(&cols.ecall.index_bitmap);
            cols.deferred_commits = count;
            cols.deferred_commit_mask = mask;
        }

        rows.into_pico_iter().flatten().collect()
    }
}

impl<F: PrimeField32> ChipBehavior<F> for EcallChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Ecall".to_string()
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        RowMajorMatrix::new(Self::build_host_trace_values(input), NUM_ECALL_CHIP_COLS)
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        // The U16ToU8 safe decomposition of the syscall code needs u8 range checks (4 byte
        // pairs per ecall row). These were previously emitted by the Cpu chip's populate_ecall.
        let blu_events: Vec<_> = input
            .cpu_events
            .as_slice()
            .pico_chunks(2048)
            .map(|events| {
                let mut blu = Vec::new();
                for event in events
                    .iter()
                    .filter(|e| e.instruction.is_ecall_instruction())
                {
                    let syscall_code = event.op_a_prev_value();
                    for i in 0..4 {
                        let limb = (syscall_code >> (16 * i)) & 0xFFFF;
                        blu.add_u8_range_checks([(limb & 0xFF) as u8, (limb >> 8) as u8]);
                    }
                    // The BitRange(6) cap on `num_extra_clk` (byte 2 of the syscall code), one
                    // per ecall row, gated like the looked message (`is_real`).
                    blu.add_bit_range_check(
                        ((syscall_code >> 16) & 0xFF) as u16,
                        NUM_EXTRA_CLK_BITS,
                    );

                    // The digest-byte range check `eval` looks up on COMMIT rows. Gated exactly
                    // as `commit_mul` is, so the multiplicities match: two lookups per COMMIT
                    // row, none anywhere else.
                    if (syscall_code & 0xFF) as u32 == SyscallCode::COMMIT.syscall_id() {
                        let digest_bytes = (event.op_c_committed_value() as u32).to_le_bytes();
                        blu.add_u8_range_check(digest_bytes[0], digest_bytes[1]);
                        blu.add_u8_range_check(digest_bytes[2], digest_bytes[3]);
                    }

                    // The operand word-range check, gated as `range_check_operand` is: HALT
                    // checks op_b, COMMIT_DEFERRED_PROOFS checks op_c. `build_host_trace_values`
                    // discards the sink `event_to_row` writes to, so this pass has to emit them.
                    let code = (syscall_code & 0xFF) as u32;
                    if code == SyscallCode::HALT.syscall_id() {
                        FieldWordRangeChecker::<F>::range_check_event(
                            &mut blu,
                            event.op_b_committed_value(),
                        );
                    }
                    if code == SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id() {
                        FieldWordRangeChecker::<F>::range_check_event(
                            &mut blu,
                            event.op_c_committed_value(),
                        );
                    }

                    // The HINT_LEN return-value range check, gated as `hint_len_mul` is: one
                    // U16Range lookup per limb of `op_a_value`, four per HINT_LEN row.
                    if code == SyscallCode::HINT_LEN.syscall_id() {
                        let a = event.op_a_committed_value();
                        for i in 0..4 {
                            blu.add_u16_range_check(((a >> (16 * i)) & 0xFFFF) as u16);
                        }
                    }
                }
                blu
            })
            .collect();
        for blu in blu_events {
            extra.add_byte_lookup_events(blu);
        }
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        // Mirror the Cpu chip: active whenever the chunk executes instructions. An all-padding
        // trace is emitted when the chunk happens to contain no ecalls, so the chip's presence
        // in a proof depends only on the chunk having instructions.
        !record.cpu_events.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::deferred_commit_tally;
    use crate::{
        chips::chips::{
            riscv_cpu::event::CpuEvent,
            riscv_memory::event::{MemoryReadRecord, MemoryRecordEnum},
        },
        compiler::riscv::{instruction::Instruction, opcode::Opcode},
        emulator::riscv::syscalls::SyscallCode,
    };

    /// An ECALL whose syscall code sits in op_a's read and whose word index is op_b.
    fn ecall(code: SyscallCode, word_index: u64) -> CpuEvent {
        CpuEvent {
            instruction: Instruction::new(Opcode::ECALL, 5, 10, 11, false, false),
            a_record: Some(MemoryRecordEnum::Read(MemoryReadRecord {
                value: code.syscall_id() as u64,
                ..Default::default()
            })),
            b: word_index,
            ..Default::default()
        }
    }

    #[test]
    fn the_tally_counts_deferred_commits_and_sums_their_word_bits() {
        let mut events: Vec<CpuEvent> = (0..8)
            .map(|i| ecall(SyscallCode::COMMIT_DEFERRED_PROOFS, i))
            .collect();
        // COMMIT shares the index bitmap but is not counted; neither is any other ecall.
        events.push(ecall(SyscallCode::COMMIT, 3));
        events.push(ecall(SyscallCode::HALT, 0));
        assert_eq!(deferred_commit_tally(&events), (8, 0xFF));
        assert_eq!(deferred_commit_tally(&events[..3]), (3, 0b111));
        assert_eq!(deferred_commit_tally(&[]), (0, 0));
    }
}
