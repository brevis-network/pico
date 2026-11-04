use super::{
    columns::{EcallChipCols, NUM_ECALL_CHIP_COLS},
    EcallChip, NUM_EXTRA_CLK_BITS,
};
use crate::{
    chips::{
        chips::{
            byte::event::{ByteLookupEvent, ByteRecordBehavior},
            riscv_cpu::event::CpuEvent,
            riscv_memory::event::MemoryRecordEnum,
        },
        gadgets::field_range_check::word_range::FieldWordRangeChecker,
        utils::pad_rows_fixed,
    },
    compiler::{riscv::program::Program, word::Word},
    emulator::riscv::{
        record::{EmulationRecord, MemoryAccessRecord},
        syscalls::SyscallCode,
    },
    iter::{IntoPicoIterator, PicoIterator},
    machine::chip::ChipBehavior,
};
#[cfg(feature = "cuda")]
use crate::{
    chips::{trace::TraceData, utils::next_power_of_two},
    cuda_adaptor::resource_pool::{
        mem_pool::get_global_mem_pool, stream_pool::get_global_stream_pool,
    },
    emulator::riscv::{history::ExecutionHistory, history_fill::HISTORY_LAYOUT},
    instances::preparer::{PreallocatedGpuMemory, PreparedGpuEvents, Readiness},
    machine::chip::GpuChipBehavior,
    mle::{machine::trace_oracle::history_launch, spans::device},
};
#[cfg(feature = "cuda")]
use cudart::{
    memory_pools::DevicePoolAllocation,
    slice::CudaSliceMut,
    stream::{CudaStream, CudaStreamCreateFlags},
};
use p3_air::BaseAir;
use p3_field::{Field, PrimeField32};
#[cfg(feature = "cuda")]
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
#[cfg(feature = "cuda")]
use pico_gpu_api::history_ecall_syscall::cuda_ecall_generate_extra_record_and_main_history;
use std::borrow::BorrowMut;
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

/// What an ECALL row reads off its step: the syscall code its `a` held before the call, and the
/// `a`, `b` and `c` it committed. An ECALL writes `a` and reads `b` and `c` ([`Slots::of`]), so
/// each is one of its memory records' values, the value [`CpuEvent`]'s `op_*` accessors give, and
/// none of the operands an event rebuilds is read.
///
/// [`Slots::of`]: crate::emulator::riscv::history::Slots::of
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EcallWords {
    code: u64,
    a: u64,
    b: u64,
    c: u64,
}

impl EcallWords {
    /// # Panics
    ///
    /// If `records` are not an ECALL's: an `a` write, and `b` and `c` reads.
    fn of(records: &MemoryAccessRecord) -> Self {
        let Some(MemoryRecordEnum::Write(a)) = records.a else {
            panic!("an ECALL step writes its a");
        };
        let read = |record: Option<MemoryRecordEnum>| match record {
            Some(MemoryRecordEnum::Read(read)) => read.value,
            _ => panic!("an ECALL step reads its b and c"),
        };
        Self {
            code: a.prev_value,
            a: a.value,
            b: read(records.b),
            c: read(records.c),
        }
    }
}

/// The word index a COMMIT_DEFERRED_PROOFS ecall writes, or `None` for any other syscall.
fn deferred_commit_index(words: EcallWords) -> Option<u32> {
    ((words.code & 0xFF) as u32 == SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id())
        .then_some((words.b & 0xFFFF_FFFF) as u32)
}

/// The chunk's COMMIT_DEFERRED_PROOFS tally the Ecall air publishes: how many ran, and the sum of
/// `2^word_index` over them, read off the records of the ECALL steps the chip's rows are built
/// from. The public values take it from here; the trace sums the rows' own columns, and the air
/// ties its last row to the public values.
pub fn deferred_commit_tally(record: &EmulationRecord) -> (u32, u32) {
    record
        .cpu_steps()
        .ecalls()
        .par_record_runs(|records, (n, mask): &mut (u32, u32)| {
            if let Some(idx) = deferred_commit_index(EcallWords::of(records)) {
                *n += 1;
                *mask += 1u32 << idx;
            }
        })
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
    /// `generate_main`), one row per ECALL step in parallel.
    ///
    /// This is the CPU-path trace builder and the `MLE_TRACE_COMPARE` reference for the CUDA
    /// kernel (`ecall_history_to_trace_kernel`), which owns the GPU path.
    pub fn build_host_trace_values(input: &EmulationRecord) -> Vec<F> {
        let chip = Self::default();
        let ecalls = input.cpu_steps().ecalls();
        let mut rows: Vec<[F; NUM_ECALL_CHIP_COLS]> = (0..ecalls.len())
            .into_pico_iter()
            .map(|index| {
                let mut row = [F::ZERO; NUM_ECALL_CHIP_COLS];
                let cols: &mut EcallChipCols<F> = row.as_mut_slice().borrow_mut();
                // Byte lookups are emitted by `extra_record` (host path) / the ecall kernel (GPU
                // path); drop the ones collected here.
                let mut blu = Vec::new();
                chip.event_to_row(&ecalls.get(index), cols, &mut blu);
                row
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
        let blu_events = input.cpu_steps().ecalls().par_record_runs(
            |records, blu: &mut Vec<ByteLookupEvent>| {
                let EcallWords {
                    code: syscall_code,
                    a,
                    b,
                    c,
                } = EcallWords::of(records);
                for i in 0..4 {
                    let limb = (syscall_code >> (16 * i)) & 0xFFFF;
                    blu.add_u8_range_checks([(limb & 0xFF) as u8, (limb >> 8) as u8]);
                }
                // The BitRange(6) cap on `num_extra_clk` (byte 2 of the syscall code), one
                // per ecall row, gated like the looked message (`is_real`).
                blu.add_bit_range_check(((syscall_code >> 16) & 0xFF) as u16, NUM_EXTRA_CLK_BITS);

                // The digest-byte range check `eval` looks up on COMMIT rows. Gated exactly
                // as `commit_mul` is, so the multiplicities match: two lookups per COMMIT
                // row, none anywhere else.
                if (syscall_code & 0xFF) as u32 == SyscallCode::COMMIT.syscall_id() {
                    let digest_bytes = (c as u32).to_le_bytes();
                    blu.add_u8_range_check(digest_bytes[0], digest_bytes[1]);
                    blu.add_u8_range_check(digest_bytes[2], digest_bytes[3]);
                }

                // The operand word-range check, gated as `range_check_operand` is: HALT
                // checks op_b, COMMIT_DEFERRED_PROOFS checks op_c. `build_host_trace_values`
                // discards the sink `event_to_row` writes to, so this pass has to emit them.
                let code = (syscall_code & 0xFF) as u32;
                if code == SyscallCode::HALT.syscall_id() {
                    FieldWordRangeChecker::<F>::range_check_event(blu, b);
                }
                if code == SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id() {
                    FieldWordRangeChecker::<F>::range_check_event(blu, c);
                }

                // The HINT_LEN return-value range check, gated as `hint_len_mul` is: one
                // U16Range lookup per limb of `op_a_value`, four per HINT_LEN row.
                if code == SyscallCode::HINT_LEN.syscall_id() {
                    for i in 0..4 {
                        blu.add_u16_range_check(((a >> (16 * i)) & 0xFFFF) as u16);
                    }
                }
            },
        );
        for blu in blu_events {
            extra.add_byte_lookup_events(blu);
        }
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        // Mirror the Cpu chip: active whenever the chunk executes instructions (an all-padding
        // trace is emitted when the chunk happens to contain no ecalls, keeping the host and
        // GPU activity predicates aligned).
        !record.cpu_steps().is_empty()
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32> GpuChipBehavior<F> for EcallChip<F> {
    fn is_active_for_extra_record(&self, record: &PreparedGpuEvents) -> bool {
        record.event_counter.num_cpu_events > 0
    }

    /// Generate the padded, row-major main trace directly on the GPU: a CUDA kernel fills one row
    /// per ECALL step of the chunk's history on the device (producing the identical trace to
    /// `build_host_trace_values`) plus the byte lookups the chip's
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
        let view = input
            .history_view()
            .expect("a CPU chunk's record carries its execution history");
        self.gpu_generate_from_history(
            device_id,
            input,
            view.history,
            prepared_gpu_events,
            preallocated_gpu_memory,
        )
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32> EcallChip<F> {
    /// The trace from the chunk's history on the device: the kernel reads the ecall list there,
    /// rebuilding each ECALL's operands, so nothing is gathered on the host and no event is
    /// uploaded, and the list's length sizes the trace as the ECALL subset's does on the stream
    /// path. The tally columns are the kernel's own running sums over those rows.
    fn gpu_generate_from_history(
        &self,
        device_id: usize,
        input: &EmulationRecord,
        history: &ExecutionHistory,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        let event_size = history.chip_steps.ecall.len();
        // The activity check read the CPU count.
        assert_eq!(
            prepared_gpu_events.event_counter.num_cpu_events,
            history.steps.len(),
            "the counter's CPU height is not the history's step count"
        );

        let log_rows = input.shape_chip_size(&self.name());
        let padded_nb_rows = match log_rows {
            Some(log_rows) => 1 << log_rows,
            None => next_power_of_two(event_size, None),
        };

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let d_byte_trace = preallocated_gpu_memory
            .d_byte_trace
            .as_mut()
            .unwrap()
            .as_mut_ptr();

        let trace_size = padded_nb_rows * NUM_ECALL_CHIP_COLS;
        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .unwrap();

        let reader = preallocated_gpu_memory
            .d_history
            .as_ref()
            .expect("a record traced from its history reached a chip without its device fill")
            .reader(stream, Readiness::Complete)
            .unwrap_or_else(|e| panic!("reading the chunk's device history: {e}"));
        let args = reader.args();
        let kernels = device::start(stream);
        let err = unsafe {
            cuda_ecall_generate_extra_record_and_main_history(
                std::ptr::from_ref(&args).cast(),
                HISTORY_LAYOUT,
                NUM_ECALL_CHIP_COLS,
                trace_size,
                d_trace.as_mut_ptr() as *mut _,
                d_byte_trace as *mut _,
                stream.into(),
            )
        };
        assert_eq!(
            err.code, 0,
            "cuda_ecall_generate_extra_record_and_main_history failed: {err}"
        );
        history_launch::note(&self.name());
        drop(reader);

        let sync_stream = get_global_stream_pool(device_id);
        let main_stream = &sync_stream.0;
        device::launched(kernels, stream);
        device::wait(stream).unwrap();
        let d_trace = d_trace.swap_stream(main_stream);
        device::wait(stream).unwrap();
        device::wait(main_stream).unwrap();

        info!("[ecall-chip] generate_extra_record_and_main from the history on GPU");
        TraceData::Gpu(NUM_ECALL_CHIP_COLS, d_trace)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use p3_koala_bear::KoalaBear;

    use super::{deferred_commit_tally, EcallWords};
    use crate::{
        chips::tests::fib_records,
        compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
        emulator::{
            record::RecordBehavior,
            riscv::{
                history::{Access, ExecutionHistory, ReadAccess, Step},
                record::EmulationRecord,
                syscalls::SyscallCode,
            },
        },
        primitives::consts::DIGEST_SIZE,
    };

    /// The same ECALLs as the steps of an execution history: each one's `a` write found the
    /// syscall code, and its `b` read holds the word index.
    fn history(calls: &[(SyscallCode, u64)]) -> EmulationRecord {
        let ecall = Instruction::new(Opcode::ECALL, 5, 10, 11, false, false);
        let program = Program::new(vec![ecall], 0x1000, 0x1000);
        let mut history = ExecutionHistory::default();
        for (index, &(code, word_index)) in calls.iter().enumerate() {
            history.steps.push(Step {
                clk: 8 * (index as u32 + 1),
                pc: 0x1000,
                next_pc: 0x1000,
                first_read: history.reads.len() as u32,
                first_write: history.writes.len() as u32,
            });
            history.writes.push(Access {
                prev_value: u64::from(code.syscall_id()),
                ..Access::default()
            });
            history.reads.extend([
                ReadAccess {
                    value: word_index,
                    ..ReadAccess::default()
                },
                ReadAccess::default(),
            ]);
            history.chip_steps.ecall.push(index as u32);
        }
        let mut record = EmulationRecord::new(Arc::new(program));
        record.history = Some(history);
        record
    }

    /// Eight deferred commits, then a COMMIT, which shares the index bitmap but is not counted,
    /// and a HALT, which is not either.
    fn calls() -> Vec<(SyscallCode, u64)> {
        (0..8)
            .map(|i| (SyscallCode::COMMIT_DEFERRED_PROOFS, i))
            .chain([(SyscallCode::COMMIT, 3), (SyscallCode::HALT, 0)])
            .collect()
    }

    #[test]
    fn the_tally_counts_deferred_commits_and_sums_their_word_bits() {
        let calls = calls();
        assert_eq!(deferred_commit_tally(&history(&calls)), (8, 0xFF));
        assert_eq!(deferred_commit_tally(&history(&calls[..3])), (3, 0b111));
        assert_eq!(deferred_commit_tally(&history(&[])), (0, 0));
    }

    #[test]
    fn a_history_record_publishes_the_deferred_commit_tally() {
        let calls = calls();
        let from_history = history(&calls);
        assert_eq!(deferred_commit_tally(&from_history), (8, 0xFF));
        assert_eq!(deferred_commit_tally(&history(&calls[..3])), (3, 0b111));
        let published = from_history.public_values::<KoalaBear>();
        let mut expected = from_history.public_values;
        expected.deferred_commits = 8;
        expected.deferred_commit_mask = 0xFF;
        assert_eq!(published, expected.to_vec::<KoalaBear>());

        assert_ne!(
            published,
            EmulationRecord::default().public_values::<KoalaBear>(),
            "the public values do not carry the tally"
        );
    }

    /// Over every ECALL of a run, the words read off its records are its event's committed
    /// values, and each chunk's tally read off them is the one its events give.
    #[test]
    fn an_ecalls_words_read_off_its_records_are_its_events() {
        let (mut ecalls, mut run_tally) = (0, (0, 0));
        for record in fib_records().iter().filter(|record| record.is_cpu_chunk) {
            let steps = record.cpu_steps().ecalls();
            let mut tally = (0, 0);
            for index in 0..steps.len() {
                let event = steps.get(index);
                assert_eq!(
                    EcallWords::of(&steps.records(index)),
                    EcallWords {
                        code: event.op_a_prev_value(),
                        a: event.op_a_committed_value(),
                        b: event.op_b_committed_value(),
                        c: event.op_c_committed_value(),
                    },
                    "ECALL {index}"
                );
                let code = (event.op_a_prev_value() & 0xFF) as u32;
                if event.instruction.is_ecall_instruction()
                    && code == SyscallCode::COMMIT_DEFERRED_PROOFS.syscall_id()
                {
                    tally.0 += 1;
                    tally.1 += 1u32 << (event.op_b_committed_value() & 0xFFFF_FFFF);
                }
            }
            assert_eq!(deferred_commit_tally(record), tally);
            ecalls += steps.len();
            run_tally = (run_tally.0 + tally.0, run_tally.1 + tally.1);
        }
        assert!(ecalls > 0, "no ECALL in any chunk");
        let words = DIGEST_SIZE as u32;
        assert_eq!(
            run_tally,
            (words, (1 << words) - 1),
            "the deferred commits a guest makes before it halts"
        );
    }
}
