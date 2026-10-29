use super::{
    columns::{CpuCols, CPU_COL_MAP, NUM_CPU_COLS},
    CpuChip,
};
#[cfg(feature = "cuda")]
use crate::{
    chips::trace::TraceData,
    cuda_adaptor::resource_pool::{
        mem_pool::get_global_mem_pool, stream_pool::get_global_stream_pool,
    },
    instances::preparer::{EventCounter, PreallocatedGpuMemory, PreparedGpuEvents},
    machine::chip::GpuChipBehavior,
};
use crate::{
    chips::{
        chips::{
            alu::event::AluEvent,
            byte::event::ByteRecordBehavior,
            riscv_cpu::event::{CpuEvent, CpuExtraEventIndices},
            riscv_memory::{event::MemoryRecordEnum, read_write::columns::MemoryLiteCols},
        },
        ffi::FfiOption,
    },
    compiler::{
        addr::Pc,
        riscv::{opcode::Opcode, program::Program},
        word::Word,
    },
    emulator::riscv::{record::EmulationRecord, syscalls::SyscallCode},
    instances::compiler::shapes::riscv_shape::RiscvPadShape,
    iter::{IntoPicoRefMutIterator, PicoBridge, PicoIterator, PicoSlice},
    machine::{
        chip::ChipBehavior,
        estimator::{EventCapture, EventSizeCapture},
    },
};
#[cfg(feature = "cuda")]
use cudart::{
    memory_pools::DevicePoolAllocation,
    slice::{CudaSlice, CudaSliceMut},
    stream::{CudaStream, CudaStreamCreateFlags},
};
#[cfg(feature = "cuda")]
use cudart_sys::*;
use hashbrown::HashMap;
use p3_air::BaseAir;
#[cfg(feature = "cuda")]
use p3_field::PrimeCharacteristicRing;
use p3_field::{Field, PrimeField32};
#[cfg(feature = "cuda")]
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
#[cfg(feature = "cuda")]
use pico_gpu_api::{
    cuda_cpu_generate_extra_record_and_main_u64,
    cuda_cpu_generate_extra_record_and_main_u64_packed, cuda_cpu_pad_trace_u64,
};
use std::borrow::BorrowMut;
#[cfg(feature = "cuda")]
use std::mem::size_of;
#[cfg(feature = "cuda")]
use tracing::info;

impl<F: Field> BaseAir<F> for CpuChip<F> {
    fn width(&self) -> usize {
        NUM_CPU_COLS
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        None
    }
}

impl<F: PrimeField32> ChipBehavior<F> for CpuChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    /// This name is now hard-coded and is related to MachineBehavior
    fn name(&self) -> String {
        "Cpu".to_string()
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let n_real_rows = input.cpu_events.len();
        let mut values = vec![F::ZERO; n_real_rows * NUM_CPU_COLS];

        let chunk_size = std::cmp::max(input.cpu_events.len() / num_cpus::get(), 1);
        values
            .chunks_mut(chunk_size * NUM_CPU_COLS)
            .enumerate()
            .pico_bridge()
            .for_each(|(i, rows)| {
                rows.chunks_mut(NUM_CPU_COLS)
                    .enumerate()
                    .for_each(|(j, row)| {
                        let idx = i * chunk_size + j;
                        let cols: &mut CpuCols<F> = row.borrow_mut();
                        let mut byte_lookup_events = Vec::new();
                        self.event_to_row(
                            &input.cpu_events.as_slice()[idx],
                            cols,
                            &mut byte_lookup_events,
                        );
                        // The chain's sink: the AIR defines `is_last` as `is_real - next.is_real`
                        // (`eval_row_chain`), so exactly the last real row carries it, and the
                        // public-value hand-off reads it.
                        if idx + 1 == n_real_rows {
                            cols.is_last = F::ONE;
                        }
                    });
            });

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(values, NUM_CPU_COLS);

        // Pad the trace to a power of two.
        Self::pad_to_power_of_two(self, input.shape.as_ref(), &mut trace.values);

        trace
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        // Generate the trace rows for each event.
        let chunk_size = std::cmp::max(input.cpu_events.len() / num_cpus::get(), 1);
        let (alu_events, blu_events): (Vec<_>, Vec<_>) = input
            .cpu_events
            .as_slice()
            .pico_chunks(chunk_size)
            .map(|ops: &[CpuEvent]| {
                let mut alu = HashMap::new();
                // The range map stores range (u8) lookup event -> multiplicity.
                let mut blu = vec![];
                ops.iter().for_each(|op| {
                    let mut row = [F::ZERO; NUM_CPU_COLS];
                    let cols: &mut CpuCols<F> = row.as_mut_slice().borrow_mut();
                    let alu_events = self.event_to_row(op, cols, &mut blu);
                    alu_events.into_iter().for_each(|(key, value)| {
                        alu.entry(key).or_insert(Vec::default()).extend(value);
                    });
                });
                (alu, blu)
            })
            .unzip();
        for alu_events_chunk in alu_events {
            extra.add_alu_events(alu_events_chunk);
        }
        for blu_events_chunk in blu_events {
            extra.add_byte_lookup_events(blu_events_chunk);
        }
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        !record.cpu_events.is_empty()
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32> GpuChipBehavior<F> for CpuChip<F> {
    fn count_extra_records(record: &Self::Record, counter: &mut EventCounter) {
        counter.num_cpu_events += record.cpu_events.len();
        if counter.num_cpu_events == 0 {
            return;
        }

        let chunk_size = std::cmp::max(counter.num_cpu_events / num_cpus::get(), 1);
        let cpu_counts: Vec<CpuExtraEventIndices> = record
            .cpu_events
            .as_slice()
            .pico_chunks(chunk_size)
            .flat_map_iter(|chunk| chunk.iter().map(|e| Self::count_cpu_event(e)))
            .collect();
        let (cpu_add, cpu_lt) = cpu_counts
            .as_slice()
            .pico_chunks(chunk_size)
            .map(|chunk| {
                chunk
                    .iter()
                    .fold((0, 0), |(a0, a1), c| (a0 + c.add, a1 + c.lt))
            })
            .pico_reduce(|| (0, 0), |(a0, a1), (b0, b1)| (a0 + b0, a1 + b1));
        counter.num_add_sub_events += cpu_add;
        counter.num_add_events += cpu_add;
        counter.num_lt_events += cpu_lt;
        let mut cpu_extra_event_indices = cpu_counts;
        for i in 1..(cpu_extra_event_indices.len() - 1) {
            cpu_extra_event_indices[i].add += cpu_extra_event_indices[i - 1].add;
            cpu_extra_event_indices[i].lt += cpu_extra_event_indices[i - 1].lt;
        }
        cpu_extra_event_indices.insert(0, CpuExtraEventIndices { add: 0, lt: 0 });
        cpu_extra_event_indices.pop();
        counter.cpu_extra_event_indices = cpu_extra_event_indices;
    }

    fn is_active_for_extra_record(&self, record: &PreparedGpuEvents) -> bool {
        record.event_counter.num_cpu_events > 0
    }

    fn gpu_generate_extra_record_and_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        let event_size = prepared_gpu_events.event_counter.num_cpu_events;
        let n_real_rows = event_size;
        let padded_nb_rows = if let Some(shape) = &input.shape {
            1 << shape.inner[&self.name()]
        } else if n_real_rows < 16 {
            16
        } else {
            n_real_rows.next_power_of_two()
        };

        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let stream1 = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();
        let stream2 = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();
        let stream3 = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        let trace_size = padded_nb_rows * NUM_CPU_COLS;
        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream1)
                .unwrap();
        unsafe {
            let _ = cudaMemsetAsync(
                d_trace.as_mut_ptr() as *mut std::ffi::c_void,
                0,
                (n_real_rows * NUM_CPU_COLS) * size_of::<KoalaBear>(),
                stream1.into(),
            );
        }

        let d_cpu_events = preallocated_gpu_memory.d_cpu_events.as_mut().unwrap();
        // `None` when the record has no ADD/SUB events at all. No Cpu row synthesizes an ADD
        // event (a JALR target is proven in-chip), so the Cpu kernel never writes this buffer;
        // the base pointer and start index are handed over because the kernel ABI carries them.
        let d_add_sub_events: *mut std::ffi::c_void = preallocated_gpu_memory
            .d_add_sub_events
            .as_mut()
            .map_or(std::ptr::null_mut(), |b| b.as_mut_ptr() as *mut _);
        // Absent when the chunk has no branch and no SLT/SLTU; the kernel writes this buffer only
        // on branch rows, which force the count above zero, so a null base is never dereferenced.
        let d_lt_events: *mut std::ffi::c_void = preallocated_gpu_memory
            .d_lt_events
            .as_mut()
            .map_or(std::ptr::null_mut(), |b| b.as_mut_ptr() as *mut _);
        let d_byte_trace = preallocated_gpu_memory.d_byte_trace.as_mut().unwrap();

        let mut d_cpu_extra_event_indices =
            DevicePoolAllocation::<CpuExtraEventIndices>::alloc_from_pool_async(
                event_size, mem_pool, stream2,
            )
            .unwrap();

        // MLE_PACKED_EVENTS: the extra-event indices ride the pinned staging (same bytes);
        // the fat path keeps the pageable Vec upload.
        let cpu_extra_indices_src: *const std::ffi::c_void =
            match prepared_gpu_events.packed.as_deref() {
                Some(pk) if pk.cpu_extra_indices().len() == event_size => {
                    pk.cpu_extra_indices().as_ptr() as *const _
                }
                _ => prepared_gpu_events
                    .event_counter
                    .cpu_extra_event_indices
                    .as_c_void_ptr(),
            };
        unsafe {
            let _ = cudaMemcpyAsync(
                d_cpu_extra_event_indices.as_mut_c_void_ptr(),
                cpu_extra_indices_src,
                event_size * size_of::<CpuExtraEventIndices>(),
                CudaMemoryCopyKind::HostToDevice,
                stream2.into(),
            );
        }

        stream1.synchronize().unwrap();
        stream2.synchronize().unwrap();

        if let Some(packed) = prepared_gpu_events.packed.as_deref() {
            // MLE_PACKED_EVENTS: upload the 80B/event packed stream into the same device
            // allocation (fat-typed, so capacity is ample) and run the packed kernel per
            // slice. Bigger slices keep the per-copy overhead amortized at 80B/event.
            use crate::instances::preparer::{CpuEventPacked, PACKED_EVENT_FORMAT_V1};
            let src_all = packed.cpu_events();
            assert_eq!(
                src_all.len(),
                event_size,
                "packed cpu stream length mismatch"
            );
            const SLICE_SIZE_PACKED: usize = 1 << 18;
            let num_slices = event_size.div_ceil(SLICE_SIZE_PACKED);

            for slice_idx in 0..num_slices {
                let slice_start = slice_idx * SLICE_SIZE_PACKED;
                let slice_end = std::cmp::min(slice_start + SLICE_SIZE_PACKED, event_size);
                let current_slice_size = slice_end - slice_start;

                let stream = if slice_idx % 2 == 0 { stream1 } else { stream2 };

                unsafe {
                    let src_ptr = src_all.as_ptr().add(slice_start);
                    let dst_ptr =
                        (d_cpu_events.as_mut_ptr() as *mut CpuEventPacked).add(slice_start);

                    let _ = cudaMemcpyAsync(
                        dst_ptr as *mut _,
                        src_ptr as *const _,
                        current_slice_size * size_of::<CpuEventPacked>(),
                        CudaMemoryCopyKind::HostToDevice,
                        stream.into(),
                    );

                    let err = cuda_cpu_generate_extra_record_and_main_u64_packed(
                        NUM_CPU_COLS,
                        current_slice_size,
                        (d_cpu_events.as_ptr() as *const CpuEventPacked).add(slice_start)
                            as *const _,
                        packed.chunk as usize,
                        d_trace.as_mut_ptr().add(slice_start * NUM_CPU_COLS) as *mut _,
                        stream.into(),
                        d_cpu_extra_event_indices.as_ptr().add(slice_start) as *const _,
                        d_byte_trace.as_mut_ptr() as *mut _,
                        d_add_sub_events,
                        prepared_gpu_events
                            .event_counter
                            .start_indices
                            .cpu_extra_add_sub_start_index,
                        d_lt_events,
                        prepared_gpu_events
                            .event_counter
                            .start_indices
                            .cpu_extra_lt_start_index,
                        PACKED_EVENT_FORMAT_V1,
                    );
                    assert_eq!(
                        err.code, 0,
                        "cuda_cpu_generate_extra_record_and_main_u64_packed failed (packed format mismatch?)"
                    );
                }
            }
        } else {
            // Upload CpuEvent directly to GPU in slices and launch kernel per slice.
            // The CUDA kernel now accepts FfiCpuEventU64 (full CpuEvent) directly,
            // eliminating the host-side CpuEvent→CpuEventSlim conversion overhead.
            // d_cpu_events is also reused by MemoryReadWrite chip.
            const SLICE_SIZE: usize = 1 << 16;
            let num_slices = event_size.div_ceil(SLICE_SIZE);

            for slice_idx in 0..num_slices {
                let slice_start = slice_idx * SLICE_SIZE;
                let slice_end = std::cmp::min(slice_start + SLICE_SIZE, event_size);
                let current_slice_size = slice_end - slice_start;

                let stream = if slice_idx % 2 == 0 { stream1 } else { stream2 };

                unsafe {
                    let src_ptr = CudaSlice::as_slice(&input.cpu_events)
                        .as_ptr()
                        .add(slice_start);
                    let dst_ptr = d_cpu_events.as_mut_ptr().add(slice_start);

                    let _ = cudaMemcpyAsync(
                        dst_ptr as *mut _,
                        src_ptr as *const _,
                        current_slice_size * size_of::<CpuEvent>(),
                        CudaMemoryCopyKind::HostToDevice,
                        stream.into(),
                    );

                    cuda_cpu_generate_extra_record_and_main_u64(
                        NUM_CPU_COLS,
                        current_slice_size,
                        d_cpu_events.as_ptr().add(slice_start) as *const _,
                        d_trace.as_mut_ptr().add(slice_start * NUM_CPU_COLS) as *mut _,
                        stream.into(),
                        d_cpu_extra_event_indices.as_ptr().add(slice_start) as *const _,
                        d_byte_trace.as_mut_ptr() as *mut _,
                        d_add_sub_events,
                        prepared_gpu_events
                            .event_counter
                            .start_indices
                            .cpu_extra_add_sub_start_index,
                        d_lt_events,
                        prepared_gpu_events
                            .event_counter
                            .start_indices
                            .cpu_extra_lt_start_index,
                    );
                }
            }
        }

        unsafe {
            let _ = cuda_cpu_pad_trace_u64(
                NUM_CPU_COLS,
                n_real_rows,
                padded_nb_rows,
                d_trace.as_mut_ptr() as *mut _,
                stream3.into(),
            );
        }

        let sync_stream = get_global_stream_pool(device_id);
        let main_stream = &sync_stream.0;
        stream1.synchronize().unwrap();
        stream2.synchronize().unwrap();
        stream3.synchronize().unwrap();
        let mut d_trace = d_trace.swap_stream(main_stream);

        // `is_last` marks the chain's sink, and the kernel cannot: it is launched once per slice
        // (2^16 fat, 2^18 packed), so a kernel-side "is this the last index" test would mark the
        // last row of every slice and the `is_last` constraints would only fail at verification.
        // Write the single cell from the host instead, after the padding kernel and the slice
        // launches have been synchronised so nothing overwrites it. The trace is row-major here;
        // the transpose happens later, outside trace generation.
        debug_assert_eq!(
            n_real_rows,
            input.cpu_events.len(),
            "the counted event total drives both the row count and the is_last offset"
        );
        // Declared outside the block so the source outlives the async copy: CUDA stages a
        // pageable H2D source before returning, but a pinned one would not be safe here.
        let one = [KoalaBear::ONE];
        if n_real_rows > 0 {
            let offset = (n_real_rows - 1) * NUM_CPU_COLS + CPU_COL_MAP.is_last;
            // The return code is dropped, as at every other copy site in this file. Worth knowing
            // the failure mode: a failed write leaves `is_last` unset on the last real row, which
            // the `eval_row_chain` constraints reject at verification rather than here.
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_trace.as_mut_ptr().add(offset) as *mut std::ffi::c_void,
                    one.as_ptr() as *const std::ffi::c_void,
                    size_of::<KoalaBear>(),
                    CudaMemoryCopyKind::HostToDevice,
                    main_stream.into(),
                );
            }
        }
        main_stream.synchronize().unwrap();

        info!("[cpu-chip] generate_extra_record_and_main on GPU");

        TraceData::Gpu(NUM_CPU_COLS, d_trace)
    }
}

impl<F> EventCapture for CpuChip<F> {
    fn count_extra_records(record: &EmulationRecord, event_counter: &mut EventSizeCapture) {
        event_counter.num_cpu_events += record.cpu_events.len();
        if event_counter.num_cpu_events == 0 {
            return;
        }

        let chunk_size = std::cmp::max(event_counter.num_cpu_events / num_cpus::get(), 1);
        let cpu_counts: Vec<(usize, usize)> = record
            .cpu_events
            .as_slice()
            .pico_chunks(chunk_size)
            .flat_map_iter(|chunk| {
                chunk.iter().map(|e| {
                    let c = Self::count_cpu_event(e);
                    (c.add, c.lt)
                })
            })
            .collect();
        let (cpu_add, cpu_lt) = cpu_counts
            .as_slice()
            .pico_chunks(chunk_size)
            .map(|chunk| {
                chunk
                    .iter()
                    .fold((0, 0), |(a0, a1), (b0, b1)| (a0 + b0, a1 + b1))
            })
            .pico_reduce(|| (0, 0), |(a0, a1), (b0, b1)| (a0 + b0, a1 + b1));
        event_counter.num_add_sub_events += cpu_add;
        event_counter.num_lt_events += cpu_lt;
    }
}

impl<F> CpuChip<F> {
    #[inline(always)]
    /// How many ALU events a CPU row contributes.
    ///
    /// This has to track the emitters exactly, not approximately. The GPU path sizes its event
    /// buffers from this count and then has the kernel fill them, so an over-count leaves
    /// uninitialized slots behind that read back as bogus ALU rows and unbalance the ALU bus.
    /// (The CPU path builds the events directly, so it cannot notice the drift -- which is why
    /// an over-count shows up only under GPU trace-gen.)
    fn count_cpu_event(event: &CpuEvent) -> CpuExtraEventIndices {
        let mut lt_events = 0;

        // A branch dispatches one merged SLT/SLTU comparison (both strict bits on one Lt row).
        // Its *target* does not dispatch: that is a field equation over the sign-extended
        // offset.
        if event.instruction.is_branch_instruction() {
            lt_events += 1;
        }
        // No ADD slot for any row. A JAL target is a field equation; a JALR target is proven
        // in-chip by four boolean carry expressions (`jump/constraints.rs`), so no Cpu row
        // synthesizes an Add event. No AUIPC arm either: since X12 the transpiler re-encodes
        // `AUIPC rd, imm` as the two-immediate `ADD rd, imm, pc`, so that row's Add event comes
        // from the emulator's generic ALU path (`record.add_sub_events`). The `add` field stays
        // in the `repr(C)` struct (the kernels index the ADD/SUB buffer by it) and is always 0.

        CpuExtraEventIndices {
            add: 0,
            lt: lt_events,
        }
    }
}

impl<F: PrimeField32> CpuChip<F> {
    /// Create a row from an event.
    fn event_to_row(
        &self,
        event: &CpuEvent,
        cols: &mut CpuCols<F>,
        blu_events: &mut impl ByteRecordBehavior,
    ) -> HashMap<Opcode, Vec<AluEvent>> {
        let mut new_alu_events = HashMap::new();

        // Populate the clk column.
        self.populate_chunk_clk(cols, event);

        // Populate basic fields. A pc is two limbs: `Pc::try_from` rejects anything at or above
        // 2^32, which the disassembler's guest address bound already rules out.
        cols.pc = Pc::try_from(event.pc).unwrap();
        cols.next_pc = Pc::try_from(event.next_pc).unwrap();

        // Neither pc nor next_pc emits range-check events any more: both lookups are gone on the
        // AIR side. pc's two limbs are pinned element by element to the preprocessed Program
        // table's canonical `Pc::try_from(pc_base + 4i)`, which is strictly stronger than a
        // range check; emitting byte events here would leave the Byte table with multiplicity no
        // lookup claims, and even an honest trace would fail the regional cumulative sum.

        cols.instruction.populate(event.instruction);
        cols.opcode_selector.populate(event.instruction);

        *cols.op_a_access.value_mut() = Word::from(event.a);
        *cols.op_b_access.value_mut() = Word::from(event.b);
        *cols.op_c_access.value_mut() = Word::from(event.c);

        // Populate memory accesses for a, b, and c.
        if let FfiOption::Some(record) = event.a_record {
            cols.op_a_access.populate(record, blu_events);
        }
        if let FfiOption::Some(MemoryRecordEnum::Read(record)) = event.b_record {
            cols.op_b_access.populate(record, blu_events);
        }
        if let FfiOption::Some(MemoryRecordEnum::Read(record)) = event.c_record {
            cols.op_c_access.populate(record, blu_events);
        }

        // No byte event for a jump row's return address: the AIR has no range check on `op_a`
        // there. Limb 0 of `pc + 4` is canonical because `pc_carry` (below) is pinned to the
        // Program table's `[pc[0] >= 0xFFFC]` (`register/constraints.rs`).

        // num_extra_clk is stored in the 3rd-byte of syscall code
        // which comes from the syscall's num_extra_cycles() return value.
        // For non-ecall instructions, this is 0.
        let num_extra_clk = if event.instruction.is_ecall_instruction() {
            let syscall_code = cols.op_a_access.prev_value().to_u64();
            F::from_u8(((syscall_code >> 16) & 0xFF) as u8)
        } else {
            F::ZERO
        };
        cols.num_extra_clk = num_extra_clk;

        // The only ALU event a Cpu row synthesizes is the branch comparison. A JALR target is
        // proven in-chip (`jump/constraints.rs`), so there is no `populate_jump`.
        self.populate_branch(cols, event, &mut new_alu_events);

        // The syscall decode gadgets and their byte lookups moved to
        // the Ecall chip. The Cpu row only commits the halt flag, whose correctness on ecall
        // rows is certified by the Ecall-chip lookup.
        let is_halt = event.instruction.is_ecall_instruction()
            && (cols.op_a_access.prev_value().to_u64() & 0xFF) as u32
                == SyscallCode::HALT.syscall_id();
        cols.is_halt = F::from_bool(is_halt);

        // `pc_carry = [pc[0] >= 0xFFFC]` on every real row. The column travels in the Program
        // message, so it has to equal the preprocessed table's value for this pc
        // (`riscv_program/traces.rs` writes the same function of the row's pc). On a jump row
        // with `rd != x0` it is the carry out of limb 0 in `pc + 4 = op_a`
        // (`Pc::add_limb_with_carry`, `jump/constraints.rs`): a table pc is 4-aligned, so
        // `pc[0] + 4` overflows exactly when `pc[0] == 0xFFFC`. Only limb 0 can carry -- a guest
        // address stays below `0x7800_0000`, so limb 1 absorbs the carry without overflowing,
        // and `op_a`'s limb 2 is zero (a pc has none); the AIR checks those two as plain
        // equalities. Padding rows leave it at 0 (`pad_to_power_of_two`).
        cols.pc_carry = F::from_bool((event.pc & 0xFFFF) >= 0xFFFC);

        // Assert that the instruction is not a no-op.
        cols.is_real = F::ONE;

        // ALU dispatch multiplicity, zero when the destination is `x0`.
        let not_x0 = F::from_bool(event.instruction.op_a != 0);
        cols.is_alu_not_x0 = F::from_bool(event.instruction.is_alu_instruction()) * not_x0;

        // Bit 0 of the unmasked target, which the emulator masked out of `next_pc`.
        cols.jalr_lsb = if event.instruction.opcode == Opcode::JALR {
            F::from_u64(event.b.wrapping_add(event.c) & 1)
        } else {
            F::ZERO
        };

        new_alu_events
    }

    fn pad_to_power_of_two(&self, shape: Option<&RiscvPadShape>, values: &mut Vec<F>) {
        let n_real_rows = values.len() / NUM_CPU_COLS;
        let padded_nb_rows = if let Some(shape) = shape {
            let padded = 1 << shape.inner[&self.name()];
            // `values.resize` below would otherwise silently TRUNCATE real rows.
            assert!(
                padded >= n_real_rows,
                "Cpu shape height {padded} < {n_real_rows} real rows (shape bucket too small)"
            );
            padded
        } else if n_real_rows < 16 {
            16
        } else {
            n_real_rows.next_power_of_two()
        };
        values.resize(padded_nb_rows * NUM_CPU_COLS, F::ZERO);

        // Interpret values as a slice of arrays of length `NUM_CPU_COLS`
        let rows = unsafe {
            core::slice::from_raw_parts_mut(
                values.as_mut_ptr() as *mut [F; NUM_CPU_COLS],
                values.len() / NUM_CPU_COLS,
            )
        };

        rows[n_real_rows..].pico_iter_mut().for_each(|padded_row| {
            padded_row[CPU_COL_MAP.opcode_selector.imm_b] = F::ONE;
            padded_row[CPU_COL_MAP.opcode_selector.imm_c] = F::ONE;
        });
    }
}
