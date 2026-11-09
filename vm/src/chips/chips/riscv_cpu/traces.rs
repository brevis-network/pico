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
    emulator::riscv::{history::ExecutionHistory, history_fill::HISTORY_LAYOUT},
    instances::preparer::{
        DeviceHistory, HistoryReader, PreallocatedGpuMemory, PreparedGpuEvents, Readiness,
    },
    machine::chip::GpuChipBehavior,
    mle::{machine::trace_oracle::history_launch, spans::device},
};
use crate::{
    chips::{
        chips::{
            byte::event::{ByteLookupEvent, ByteRecordBehavior},
            riscv_cpu::event::{CpuEvent, CpuExtraEventIndices},
            riscv_memory::{
                event::MemoryRecordEnum,
                read_write::{columns::MemoryLiteCols, traces::timestamp_diff_lookups},
            },
        },
        ffi::FfiOption,
    },
    compiler::{
        addr::Pc,
        riscv::{opcode::Opcode, program::Program},
        word::Word,
    },
    emulator::riscv::{
        record::{EmulationRecord, MemoryAccessRecord},
        syscalls::SyscallCode,
    },
    instances::compiler::shapes::riscv_shape::RiscvPadShape,
    iter::{IntoPicoRefMutIterator, PicoBridge, PicoIterator},
    machine::{
        chip::ChipBehavior,
        estimator::{EventCapture, EventSizeCapture},
    },
};
#[cfg(feature = "cuda")]
use cudart::{
    memory_pools::DevicePoolAllocation,
    slice::CudaSliceMut,
    stream::{CudaStream, CudaStreamCreateFlags},
};
#[cfg(feature = "cuda")]
use cudart_sys::*;
use p3_air::BaseAir;
#[cfg(feature = "cuda")]
use p3_field::PrimeCharacteristicRing;
use p3_field::{Field, PrimeField32};
#[cfg(feature = "cuda")]
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
#[cfg(feature = "cuda")]
use pico_gpu_api::history_cpu_memory_lt::{
    cuda_cpu_generate_extra_record_and_main_history, cuda_cpu_pad_trace_history,
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
        let steps = input.cpu_steps();
        let n_real_rows = steps.len();
        let mut values = vec![F::ZERO; n_real_rows * NUM_CPU_COLS];

        let chunk_size = std::cmp::max(n_real_rows / num_cpus::get(), 1);
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
                        self.event_to_row(&steps.get(idx), cols, &mut byte_lookup_events);
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
        let blu_events =
            input
                .cpu_steps()
                .par_record_runs(|records, blu: &mut Vec<ByteLookupEvent>| {
                    Self::row_byte_lookups(records, blu);
                });
        for blu_events_chunk in blu_events {
            extra.add_byte_lookup_events(blu_events_chunk);
        }
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        !record.cpu_steps().is_empty()
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32> GpuChipBehavior<F> for CpuChip<F> {
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
impl<F: PrimeField32> CpuChip<F> {
    /// The trace from the chunk's history on the device, slice by slice: slice k's kernel waits for
    /// slice k's copy alone, the step after it included, so it starts as that copy lands, and of
    /// the rest of the fill reads only the descriptor and the exceptions. No event is uploaded and
    /// no other chip's buffer is written: the less-than chip builds the branch comparisons from
    /// the history's branch list. The step count sizes the trace; the counter the activity check
    /// read must have counted the same steps.
    fn gpu_generate_from_history(
        &self,
        device_id: usize,
        input: &EmulationRecord,
        history: &ExecutionHistory,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        use ordering_edge::{delay, kept, Edge};

        let n_real_rows = history.steps.len();
        assert_eq!(
            prepared_gpu_events.event_counter.num_cpu_events, n_real_rows,
            "the counter's CPU height is not the history's step count"
        );
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

        // Zeroed whole before any kernel: which rows the slices fill and which the pad kernel pads
        // is decided on the device, from the fill's step count.
        let trace_size = padded_nb_rows * NUM_CPU_COLS;
        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream1)
                .unwrap();
        delay(Edge::ZeroFill, stream1);
        let fill = device::start(stream1);
        let code = unsafe {
            cudaMemsetAsync(
                d_trace.as_mut_ptr() as *mut std::ffi::c_void,
                0,
                trace_size * size_of::<KoalaBear>(),
                stream1.into(),
            )
        };
        assert_eq!(code, CudaError::Success, "zeroing the CPU trace failed");
        device::filled(fill, stream1);
        if kept(Edge::ZeroFill) {
            device::wait(stream1).unwrap();
        }

        let d_byte_trace = preallocated_gpu_memory
            .d_byte_trace
            .as_mut()
            .unwrap()
            .as_mut_ptr();
        let device_history = chunk_device_history(preallocated_gpu_memory);
        let slices = device_history.slices();
        let slice_steps = device_history.descriptor().cpu_slice_steps as usize;
        let readers = [stream1, stream2].map(|stream| {
            device_history
                .reader(stream, Readiness::Descriptor)
                .unwrap_or_else(|e| panic!("reading the chunk's device history: {e}"))
        });
        for stream in [stream1, stream2, stream3] {
            delay(Edge::SinkWrite, stream);
        }
        for slice in 0..slices {
            let (stream, reader) = if slice % 2 == 0 {
                (stream1, &readers[0])
            } else {
                (stream2, &readers[1])
            };
            if kept(Edge::SliceCopy) {
                reader
                    .wait_slice(slice)
                    .unwrap_or_else(|e| panic!("waiting for CPU slice {slice}'s copy: {e}"));
            }
            let args = reader.args();
            let kernel = device::start(stream);
            let err = unsafe {
                cuda_cpu_generate_extra_record_and_main_history(
                    std::ptr::from_ref(&args).cast(),
                    HISTORY_LAYOUT,
                    slice as u32,
                    slices as u32,
                    slice_steps,
                    NUM_CPU_COLS,
                    trace_size,
                    d_trace.as_mut_ptr() as *mut _,
                    d_byte_trace as *mut _,
                    stream.into(),
                )
            };
            assert_eq!(
                err.code, 0,
                "cuda_cpu_generate_extra_record_and_main_history failed on slice {slice}: {err}"
            );
            history_launch::note(&self.name());
            device::launched(kernel, stream);
        }

        let pad_reader = device_history
            .reader(stream3, Readiness::Descriptor)
            .unwrap_or_else(|e| panic!("reading the chunk's device history: {e}"));
        let args = pad_reader.args();
        let pad = device::start(stream3);
        let err = unsafe {
            cuda_cpu_pad_trace_history(
                std::ptr::from_ref(&args).cast(),
                HISTORY_LAYOUT,
                NUM_CPU_COLS,
                trace_size,
                d_trace.as_mut_ptr() as *mut _,
                stream3.into(),
            )
        };
        assert_eq!(err.code, 0, "cuda_cpu_pad_trace_history failed: {err}");
        history_launch::note(&self.name());
        device::launched(pad, stream3);
        drop(pad_reader);
        drop(readers);

        let sync_stream = get_global_stream_pool(device_id);
        let main_stream = &sync_stream.0;
        if kept(Edge::SinkWrite) {
            device::wait(stream1).unwrap();
            device::wait(stream2).unwrap();
            device::wait(stream3).unwrap();
        }
        let mut d_trace = d_trace.swap_stream(main_stream);

        // The chain's sink, written from the host once every slice and the padding have run.
        let one = [KoalaBear::ONE];
        if n_real_rows > 0 {
            let offset = (n_real_rows - 1) * NUM_CPU_COLS + CPU_COL_MAP.is_last;
            let code = unsafe {
                cudaMemcpyAsync(
                    d_trace.as_mut_ptr().add(offset) as *mut std::ffi::c_void,
                    one.as_ptr() as *const std::ffi::c_void,
                    size_of::<KoalaBear>(),
                    CudaMemoryCopyKind::HostToDevice,
                    main_stream.into(),
                )
            };
            assert_eq!(
                code,
                CudaError::Success,
                "writing the CPU trace's last row failed"
            );
        }
        device::wait(main_stream).unwrap();

        info!("[cpu-chip] generate_extra_record_and_main from the history on GPU");

        TraceData::Gpu(NUM_CPU_COLS, d_trace)
    }
}

/// The ordering edges the CPU chip's history trace rests on, for the tests that hold each one. A
/// case delays one edge's producer for the whole process and, in its dropped arm, drops the edge,
/// so that the trace comes out wrong, or the fill's error word catches the race, exactly when the
/// edge is gone. Only a build with the `drop-ordering-edge` feature can arm a case; any other
/// build keeps every edge and delays nothing.
#[cfg(feature = "cuda")]
pub mod ordering_edge {
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Edge {
        /// CPU slice k's copy, the step after it included, before slice k's kernel.
        SliceCopy,
        /// The CPU trace's zero-fill before the slice kernels and the pad kernel.
        ZeroFill,
        /// Every slice kernel and the pad kernel before the host writes the last row's `is_last`.
        SinkWrite,
        /// The fill's descriptor and its exceptions before any kernel that reads them.
        Descriptor,
        /// Both copy streams' slice copies before the fill's completion word.
        SliceCopyJoin,
        /// The upload's copies out of a pinned arena slot before the slot goes back to the arena,
        /// whose next history overwrites it.
        SlotFence,
    }

    #[cfg(feature = "drop-ordering-edge")]
    pub use armed::{arm, delay, kept, withhold, SPIN_NANOS};

    #[cfg(feature = "drop-ordering-edge")]
    mod armed {
        use super::Edge;
        use cudart::{memory_pools::DevicePoolAllocation, slice::CudaSlice, stream::CudaStream};
        use cudart_sys::{cudaMemcpyAsync, cudaMemsetAsync, CudaError, CudaMemoryCopyKind};
        use pico_gpu_api::history_cpu_memory_lt::cuda_history_spin;
        use std::{ffi::c_void, sync::OnceLock};

        /// How long a delayed producer's stream is held: far longer than a consumer the edge no
        /// longer orders takes to be enqueued and to run.
        pub const SPIN_NANOS: u64 = 200_000_000;

        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        struct Case {
            edge: Edge,
            dropped: bool,
        }

        static CASE: OnceLock<Case> = OnceLock::new();

        /// From now on `edge`'s producer is delayed and, if `dropped`, `edge` no longer orders it
        /// before its consumer. Once per process, before any trace generation.
        ///
        /// # Panics
        ///
        /// If another case was armed.
        pub fn arm(edge: Edge, dropped: bool) {
            let asked = Case { edge, dropped };
            let armed = *CASE.get_or_init(|| asked);
            assert_eq!(armed, asked, "one ordering case per process");
        }

        /// Whether `edge` orders its producer before its consumer.
        #[must_use]
        pub fn kept(edge: Edge) -> bool {
            CASE.get()
                .is_none_or(|case| case.edge != edge || !case.dropped)
        }

        /// Holds `stream` for [`SPIN_NANOS`] when the armed case delays `edge`'s producer, which
        /// is enqueued on `stream` next.
        pub fn delay(edge: Edge, stream: &CudaStream) {
            if CASE.get().is_some_and(|case| case.edge == edge) {
                let err = unsafe { cuda_history_spin(SPIN_NANOS, stream.into()) };
                assert_eq!(err.code, 0, "cuda_history_spin failed: {err}");
            }
        }

        /// When the armed case delays `edge`, takes back the `bytes` at `region` that `stream`
        /// has just written and writes them again [`SPIN_NANOS`] later, all on the device: a
        /// reader that does not wait for `stream` meanwhile reads poison. For a producer copied
        /// from pageable memory, which [`delay`] cannot hold back: such a copy may hold the host
        /// until its stream reaches it, so a spin before it would order it before every reader.
        ///
        /// # Safety
        ///
        /// `region` is `bytes` bytes of device memory that stay allocated until the work enqueued
        /// on `stream` so far has run.
        pub unsafe fn withhold(edge: Edge, region: *mut c_void, bytes: usize, stream: &CudaStream) {
            if !CASE.get().is_some_and(|case| case.edge == edge) {
                return;
            }
            let saved = DevicePoolAllocation::<u8>::alloc_async(bytes, stream)
                .expect("a buffer for the withheld bytes");
            let saved_at = saved.as_c_void_ptr().cast_mut();
            let kind = CudaMemoryCopyKind::DeviceToDevice;
            let codes = unsafe {
                [
                    cudaMemcpyAsync(saved_at, region, bytes, kind, stream.into()),
                    cudaMemsetAsync(region, 0xff, bytes, stream.into()),
                ]
            };
            delay(edge, stream);
            let restored = unsafe { cudaMemcpyAsync(region, saved_at, bytes, kind, stream.into()) };
            for code in codes.into_iter().chain([restored]) {
                assert_eq!(code, CudaError::Success, "withholding a region");
            }
        }
    }

    /// Every edge orders its producer before its consumer.
    #[cfg(not(feature = "drop-ordering-edge"))]
    #[must_use]
    #[inline]
    pub const fn kept(_: Edge) -> bool {
        true
    }

    /// No producer is delayed.
    #[cfg(not(feature = "drop-ordering-edge"))]
    #[inline]
    pub const fn delay(_: Edge, _: &cudart::stream::CudaStream) {}

    /// Nothing is withheld.
    ///
    /// # Safety
    ///
    /// None needed: nothing is read or written.
    #[cfg(not(feature = "drop-ordering-edge"))]
    #[inline]
    pub unsafe fn withhold(
        _: Edge,
        _: *mut std::ffi::c_void,
        _: usize,
        _: &cudart::stream::CudaStream,
    ) {
    }
}

#[cfg(feature = "cuda")]
/// The chunk's fill on the device, which every chip tracing the chunk from its history reads.
pub(crate) fn chunk_device_history<'h, 'a>(
    preallocated_gpu_memory: &'h PreallocatedGpuMemory<'a>,
) -> &'h DeviceHistory<'a> {
    preallocated_gpu_memory
        .d_history
        .as_ref()
        .expect("a record traced from its history reached a chip without its device fill")
}

#[cfg(feature = "cuda")]
/// The chunk's fill as the kernels on `stream` read it, whole. Making the reader makes `stream`
/// wait for the whole fill; dropping it once the kernel is enqueued marks the end of `stream`'s
/// reads, which the fill's error-word read-back and its free follow.
pub(crate) fn chunk_history_reader<'h, 'a>(
    preallocated_gpu_memory: &'h PreallocatedGpuMemory<'a>,
    stream: &'h CudaStream,
) -> HistoryReader<'h, 'a> {
    chunk_device_history(preallocated_gpu_memory)
        .reader(stream, Readiness::Complete)
        .unwrap_or_else(|e| panic!("reading the chunk's device history: {e}"))
}

impl<F> EventCapture for CpuChip<F> {
    fn count_extra_records(record: &EmulationRecord, event_counter: &mut EventSizeCapture) {
        let steps = record.cpu_steps();
        event_counter.num_cpu_events += steps.len();
        if steps.is_empty() {
            return;
        }
        let cpu_lt: usize = steps
            .par_runs(|event, lt: &mut usize| {
                *lt += Self::count_cpu_event(event).lt;
            })
            .into_iter()
            .sum();
        event_counter.num_lt_events += cpu_lt;
    }
}

impl<F> CpuChip<F> {
    #[inline(always)]
    /// How many ALU events a CPU row contributes: the comparison the less-than chip proves for a
    /// branch, and nothing else.
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
        // `AUIPC rd, imm` as the two-immediate `ADD rd, imm, pc`, so that row's Add event is the
        // history's own, on its add list.

        CpuExtraEventIndices { lt: lt_events }
    }
}

impl<F: PrimeField32> CpuChip<F> {
    /// The byte lookups [`Self::event_to_row`] raises, without the row: the timestamp limbs of
    /// the `a` access and of the `b` and `c` register reads. They follow from the step's memory
    /// records alone, so no event, and none of its operands, is built for them.
    fn row_byte_lookups(records: &MemoryAccessRecord, blu_events: &mut impl ByteRecordBehavior) {
        if let Some(record) = records.a {
            timestamp_diff_lookups(record, blu_events);
        }
        for record in [records.b, records.c] {
            if let Some(record @ MemoryRecordEnum::Read(_)) = record {
                timestamp_diff_lookups(record, blu_events);
            }
        }
    }

    /// Create a row from an event.
    fn event_to_row(
        &self,
        event: &CpuEvent,
        cols: &mut CpuCols<F>,
        blu_events: &mut impl ByteRecordBehavior,
    ) {
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

        // The only ALU event a Cpu row synthesizes is the branch comparison, which `extra_record`
        // raises. A JALR target is proven in-chip (`jump/constraints.rs`), so there is no
        // `populate_jump`.
        self.populate_branch(cols, event);

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chips::tests::fib_records,
        emulator::riscv::history_view::{in_compare_order, run_length},
        mle::machine::riscv::Kb,
    };
    use p3_field::PrimeCharacteristicRing;

    /// The byte lookups match the rows, and the history comparisons carry their branch bits.
    #[test]
    fn extra_record_raises_what_the_rows_raise() {
        let records = fib_records();
        let chip = CpuChip::<Kb>::default();
        let mut compared = 0;
        for record in records.iter().filter(|record| record.is_cpu_chunk) {
            let mut harvested = EmulationRecord::default();
            chip.extra_record(record, &mut harvested);

            let mut from_rows = EmulationRecord::default();
            let mut branches = Vec::new();
            for (index, event) in record.cpu_steps().iter().enumerate() {
                let mut row = [Kb::ZERO; NUM_CPU_COLS];
                let cols: &mut CpuCols<Kb> = row.as_mut_slice().borrow_mut();
                chip.event_to_row(&event, cols, &mut from_rows);
                if event.instruction.is_branch_instruction() {
                    let signed = matches!(event.instruction.opcode, Opcode::BLT | Opcode::BGE);
                    branches.push((index, signed, (event.clk, cols.a_lt_b, cols.a_gt_b)));
                }
            }
            assert_eq!(harvested.byte_lookups, from_rows.byte_lookups);
            let run = run_length(record.cpu_steps().len());
            let row_bits: Vec<_> = branches
                .chunk_by(|left, right| left.0 / run == right.0 / run)
                .flat_map(|group| in_compare_order(group, |branch| branch.1))
                .map(|(_, _, bits)| bits)
                .collect();

            let ops = record.alu_ops(crate::emulator::riscv::record::AluStream::Lt);
            let native = record.history.as_ref().unwrap().chip_steps.lt.len();
            let compare_bits: Vec<_> = (native..ops.len())
                .map(|index| ops.get(index))
                .map(|compare| {
                    assert!(compare.is_cmp);
                    (
                        compare.clk,
                        Kb::from_u64(compare.a & 1),
                        Kb::from_u64(compare.a >> 16),
                    )
                })
                .collect();
            assert_eq!(compare_bits, row_bits);
            compared += row_bits.len();
        }
        assert!(compared > 0, "no branch in any chunk");
    }

    /// Step by step, the byte lookups read off a step's records are the ones its row raises, in
    /// the same order, and the records are its event's.
    #[test]
    fn a_steps_byte_lookups_read_off_its_records_are_its_rows() {
        let chip = CpuChip::<Kb>::default();
        let mut steps_read = 0;
        for record in fib_records().iter().filter(|record| record.is_cpu_chunk) {
            let steps = record.cpu_steps();
            for index in 0..steps.len() {
                let (event, records) = (steps.get(index), steps.records(index));
                assert_eq!(
                    [records.a, records.b, records.c, records.memory]
                        .map(FfiOption::<MemoryRecordEnum>::from),
                    [
                        event.a_record,
                        event.b_record,
                        event.c_record,
                        event.memory_record
                    ],
                    "step {index}"
                );
                let mut from_records = Vec::<ByteLookupEvent>::new();
                CpuChip::<Kb>::row_byte_lookups(&records, &mut from_records);
                let mut from_row = Vec::<ByteLookupEvent>::new();
                let mut row = [Kb::ZERO; NUM_CPU_COLS];
                let cols: &mut CpuCols<Kb> = row.as_mut_slice().borrow_mut();
                chip.event_to_row(&event, cols, &mut from_row);
                assert_eq!(from_records, from_row, "step {index}");
                steps_read += 1;
            }
        }
        assert!(steps_read > 0, "no CPU step in any chunk");
    }
}
