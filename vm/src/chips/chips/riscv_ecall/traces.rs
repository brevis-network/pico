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
#[cfg(feature = "cuda")]
use crate::{
    chips::{trace::TraceData, utils::next_power_of_two},
    cuda_adaptor::resource_pool::{
        mem_pool::get_global_mem_pool, stream_pool::get_global_stream_pool,
    },
    instances::preparer::{PreallocatedGpuMemory, PreparedGpuEvents},
    iter::IntoPicoRefIterator,
    machine::chip::GpuChipBehavior,
};
#[cfg(feature = "cuda")]
use cudart::{
    memory_pools::DevicePoolAllocation,
    slice::{CudaSlice, CudaSliceMut},
    stream::{CudaStream, CudaStreamCreateFlags},
};
#[cfg(feature = "cuda")]
use cudart_sys::*;
use p3_air::BaseAir;
use p3_field::{Field, PrimeField32};
#[cfg(feature = "cuda")]
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
#[cfg(feature = "cuda")]
use pico_gpu_api::{
    cuda_ecall_generate_extra_record_and_main_u64,
    cuda_ecall_generate_extra_record_and_main_u64_packed,
};
use std::borrow::BorrowMut;
#[cfg(feature = "cuda")]
use std::mem::size_of;
#[cfg(feature = "cuda")]
use tracing::info;

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
    ///
    /// This is the CPU-path trace builder and the `MLE_TRACE_COMPARE` reference for the CUDA
    /// kernel (`ecall_events_to_trace_kernel`), which owns the GPU path.
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
                        // Byte lookups are emitted by `extra_record` (host path) / the ecall
                        // kernel (GPU path); drop them here.
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
        // Mirror the Cpu chip: active whenever the chunk executes instructions (an all-padding
        // trace is emitted when the chunk happens to contain no ecalls, keeping the host and
        // GPU activity predicates aligned).
        !record.cpu_events.is_empty()
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32> GpuChipBehavior<F> for EcallChip<F> {
    fn is_active_for_extra_record(&self, record: &PreparedGpuEvents) -> bool {
        record.event_counter.num_cpu_events > 0
    }

    /// Generate the padded, row-major main trace directly on the GPU: the ECALL subset of
    /// `cpu_events` is uploaded to the device and a CUDA kernel fills one row per event
    /// (producing the identical trace to `build_host_trace_values`) plus the byte lookups the chip's
    /// constraints consume: the U16ToU8 u8-range pairs, and on COMMIT rows the two
    /// digest-byte range checks. This kernel is their only producer on the GPU path. Padding rows
    /// are zero except the COMMIT_DEFERRED_PROOFS tally, whose running sums the device carries
    /// down to the last row, as `generate_main` does.
    fn gpu_generate_extra_record_and_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        let packed = prepared_gpu_events.packed.as_deref();
        // Filter `cpu_events` down to the ECALL subset (the rows this chip proves).
        //
        // `pico_iter`, not `iter`: the subset is a handful of rows but the scan reads every cpu
        // event in the chunk, and it runs on the prove lane with the card idle for its duration.
        // Order survives -- rayon's `collect` into a `Vec` keeps the source order after `filter`.
        let events: Vec<CpuEvent> = if packed.is_some() {
            Vec::new()
        } else {
            input
                .cpu_events
                .as_slice()
                .pico_iter()
                .filter(|e| e.instruction.is_ecall_instruction())
                .map(|e| *e)
                .collect()
        };
        // MLE_PACKED_EVENTS: gather the ECALL subset from the packed stream instead (same
        // predicate: is_ecall_instruction() is exactly opcode == ECALL).
        let packed_events: Vec<crate::instances::preparer::CpuEventPacked> = packed
            .map(|p| {
                p.cpu_events()
                    .pico_iter()
                    .filter(|e| e.opcode == crate::compiler::riscv::opcode::Opcode::ECALL as u8)
                    .map(|e| *e)
                    .collect()
            })
            .unwrap_or_default();

        let nb_rows = if packed.is_some() {
            packed_events.len()
        } else {
            events.len()
        };
        let log_rows = input.shape_chip_size(&self.name());
        let padded_nb_rows = match log_rows {
            Some(log_rows) => 1 << log_rows,
            None => next_power_of_two(nb_rows, None),
        };

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let trace_size = padded_nb_rows * NUM_ECALL_CHIP_COLS;
        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .unwrap();
        unsafe {
            let _ = cudaMemsetAsync(
                d_trace.as_mut_ptr() as *mut _,
                0,
                trace_size * size_of::<KoalaBear>(),
                stream.into(),
            );
        }

        let event_size = nb_rows;
        if event_size > 0 {
            let d_byte_trace = preallocated_gpu_memory.d_byte_trace.as_mut().unwrap();

            if let Some(pk) = packed {
                use crate::instances::preparer::{CpuEventPacked, PACKED_EVENT_FORMAT_V1};
                let mut d_events = DevicePoolAllocation::<CpuEventPacked>::alloc_from_pool_async(
                    event_size, mem_pool, stream,
                )
                .unwrap();
                unsafe {
                    let _ = cudaMemcpyAsync(
                        d_events.as_mut_c_void_ptr(),
                        packed_events.as_ptr() as *const _,
                        event_size * size_of::<CpuEventPacked>(),
                        CudaMemoryCopyKind::HostToDevice,
                        stream.into(),
                    );
                    let err = cuda_ecall_generate_extra_record_and_main_u64_packed(
                        NUM_ECALL_CHIP_COLS,
                        event_size,
                        trace_size,
                        d_events.as_ptr() as *const _,
                        pk.chunk as usize,
                        d_trace.as_mut_ptr() as *mut _,
                        stream.into(),
                        d_byte_trace.as_mut_ptr() as *mut _,
                        PACKED_EVENT_FORMAT_V1,
                    );
                    assert_eq!(
                        err.code, 0,
                        "cuda_ecall_generate_extra_record_and_main_u64_packed failed (packed format or column \
                         layout mismatch?)"
                    );
                }
                // Hold the filtered host Vec this copied from until the kernel drains it:
                // it is pageable, unlike the pinned staging the other chips upload from.
                stream.synchronize().unwrap();
                drop(d_events);
            } else {
                let mut d_events = DevicePoolAllocation::<CpuEvent>::alloc_from_pool_async(
                    event_size, mem_pool, stream,
                )
                .unwrap();
                unsafe {
                    let _ = cudaMemcpyAsync(
                        d_events.as_mut_c_void_ptr(),
                        events.as_c_void_ptr(),
                        event_size * size_of::<CpuEvent>(),
                        CudaMemoryCopyKind::HostToDevice,
                        stream.into(),
                    );
                }

                let err = unsafe {
                    cuda_ecall_generate_extra_record_and_main_u64(
                        NUM_ECALL_CHIP_COLS,
                        event_size,
                        trace_size,
                        d_events.as_ptr() as *const _,
                        d_trace.as_mut_ptr() as *mut _,
                        stream.into(),
                        d_byte_trace.as_mut_ptr() as *mut _,
                    )
                };
                assert_eq!(
                    err.code, 0,
                    "cuda_ecall_generate_extra_record_and_main_u64 failed (column layout mismatch?)"
                );
            }
        }

        let sync_stream = get_global_stream_pool(device_id);
        let main_stream = &sync_stream.0;
        stream.synchronize().unwrap();
        let d_trace = d_trace.swap_stream(main_stream);
        stream.synchronize().unwrap();
        main_stream.synchronize().unwrap();

        info!("[ecall-chip] generate_extra_record_and_main on GPU");

        TraceData::Gpu(NUM_ECALL_CHIP_COLS, d_trace)
    }
}

#[cfg(test)]
mod tests {
    use super::deferred_commit_tally;
    use crate::{
        chips::{
            chips::{
                riscv_cpu::event::CpuEvent,
                riscv_memory::event::{MemoryReadRecord, MemoryRecordEnum},
            },
            ffi::FfiOption,
        },
        compiler::riscv::{instruction::Instruction, opcode::Opcode},
        emulator::riscv::syscalls::SyscallCode,
    };

    /// An ECALL whose syscall code sits in op_a's read and whose word index is op_b.
    fn ecall(code: SyscallCode, word_index: u64) -> CpuEvent {
        CpuEvent {
            instruction: Instruction::new(Opcode::ECALL, 5, 10, 11, false, false),
            a_record: FfiOption::Some(MemoryRecordEnum::Read(MemoryReadRecord {
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
