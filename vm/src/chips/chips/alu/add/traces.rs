#[cfg(feature = "cuda")]
use crate::{
    chips::{chips::alu::divrem::traces::DivRemAddRows, trace::TraceData},
    cuda_adaptor::resource_pool::{
        mem_pool::get_global_mem_pool, stream_pool::get_global_stream_pool,
    },
    emulator::riscv::history_fill::HISTORY_LAYOUT,
    instances::preparer::{
        DeviceHistory, HistoryReader, PreallocatedGpuMemory, PreparedGpuEvents, Readiness,
    },
    machine::chip::GpuChipBehavior,
    mle::{machine::trace_oracle::history_launch, spans::device},
};
use crate::{
    chips::{
        chips::{
            alu::{
                add::{
                    columns::{AddValueCols, NUM_ADD_COLS, NUM_ADD_VALUE_COLS},
                    AddChip,
                },
                event::AluEvent,
            },
            byte::event::ByteRecordBehavior,
        },
        utils::next_power_of_two,
    },
    compiler::{
        riscv::{opcode::Opcode, program::Program},
        word::Word,
    },
    emulator::riscv::record::{AluStream, EmulationRecord},
    iter::{IndexedPicoIterator, PicoIterator, PicoSliceMut},
    machine::chip::ChipBehavior,
    primitives::consts::ADD_DATAPAR,
};
use core::borrow::BorrowMut;
#[cfg(feature = "cuda")]
use cudart::{
    memory_pools::DevicePoolAllocation,
    stream::{CudaStream, CudaStreamCreateFlags},
};
use p3_field::{Field, PrimeField32};
#[cfg(feature = "cuda")]
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
#[cfg(feature = "cuda")]
use pico_gpu_api::history_add_sub_divrem::cuda_add_generate_extra_record_and_main_history;
#[cfg(feature = "cuda")]
use std::ffi::c_void;
#[cfg(feature = "cuda")]
use tracing::info;

impl<F: PrimeField32> ChipBehavior<F> for AddChip<F> {
    type Record = EmulationRecord;

    type Program = Program;

    fn name(&self) -> String {
        "Add".to_string()
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let ops = input.alu_ops(AluStream::Add);
        let positions = ops.positions(Opcode::ADD);

        let nrows = positions.len().div_ceil(ADD_DATAPAR);
        let log2_nrows = input.shape_chip_size(&self.name());
        let padded_nrows = match log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };
        let mut values = vec![F::ZERO; padded_nrows * NUM_ADD_COLS];

        let populate_len = positions.len() * NUM_ADD_VALUE_COLS;
        values[..populate_len]
            .pico_chunks_mut(NUM_ADD_VALUE_COLS)
            .zip_eq(positions)
            .for_each(|(row, index)| {
                let cols: &mut AddValueCols<_> = row.borrow_mut();
                self.event_to_row(&ops.get(index), cols, &mut vec![]);
            });

        RowMajorMatrix::new(values, NUM_ADD_COLS)
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        let blu_batches = input.alu_ops(AluStream::Add).par_flat_map(|event, blu| {
            if event.opcode == Opcode::ADD {
                let mut dummy = AddValueCols::default();
                self.event_to_row(event, &mut dummy, blu);
            }
        });

        extra.add_byte_lookup_events(blu_batches);
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        // Under a pad shape the shape decides presence, so a bucketed chunk's proof shape
        // depends on the chunk kind rather than on its opcode mix. Without a shape the
        // chip is event-driven, which is what the natural-height path wants.
        if let Some(shape) = record.shape.as_ref() {
            return shape.included::<F, _>(self);
        }
        record.alu_ops(AluStream::Add).contains(Opcode::ADD)
    }

    fn local_only(&self) -> bool {
        true
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32> GpuChipBehavior<F> for AddChip<F> {
    fn is_active_for_extra_record(&self, record: &PreparedGpuEvents) -> bool {
        record.event_counter.num_add_events > 0
    }

    fn gpu_generate_extra_record_and_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        self.gpu_generate_from_history(
            device_id,
            input,
            prepared_gpu_events,
            preallocated_gpu_memory,
        )
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32> AddChip<F> {
    /// The trace from the chunk's history on the device: the add list's ADD rows, split there from
    /// its ADDW rows, then the ADD rows div/rem derived and appended there. The fill's descriptor
    /// counts both, so their sum is the height the counter the activity check read gave.
    fn gpu_generate_from_history(
        &self,
        device_id: usize,
        input: &EmulationRecord,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        let (own, derived_rows) = {
            let descriptor = chunk_history(preallocated_gpu_memory).descriptor();
            (
                descriptor.add_rows as usize,
                descriptor.divrem_add_rows as usize,
            )
        };
        let derived = preallocated_gpu_memory.d_divrem_add_rows.take();
        assert_eq!(
            derived.as_ref().map_or(0, DivRemAddRows::len),
            derived_rows,
            "the ADD rows div/rem appended on the device are not the fill descriptor's count"
        );
        let (d_derived, capacity) = derived
            .as_ref()
            .map_or((std::ptr::null(), 0), |rows| (rows.as_ptr(), rows.len()));
        split_trace_from_history(
            device_id,
            &self.name(),
            input,
            own + derived_rows,
            prepared_gpu_events.event_counter.num_add_events,
            NUM_ADD_COLS,
            preallocated_gpu_memory,
            derived,
            |args, trace_size, d_trace, d_byte_trace, stream| unsafe {
                cuda_add_generate_extra_record_and_main_history(
                    args,
                    HISTORY_LAYOUT,
                    NUM_ADD_VALUE_COLS,
                    trace_size,
                    d_trace,
                    d_byte_trace,
                    d_derived,
                    capacity,
                    stream.into(),
                )
            },
        )
    }
}

#[cfg(feature = "cuda")]
/// The trace of one of the four chips the add and sub lists split into, from the chunk's history
/// on the device. `rows` of it are the chip's, the fill descriptor's count, and `counted` is the
/// height the counter the activity check read gave it, which must be the same; `cols` is the
/// trace's width. `launch` enqueues the chip's history entry on the stream it is handed, with the
/// launch arguments, the trace's size, the trace and the byte table. The add chip's entry also
/// reads `derived`, which its stream waits for and which is freed once the entry has read it.
#[allow(clippy::too_many_arguments)]
pub(crate) fn split_trace_from_history<'t, F: PrimeField32>(
    device_id: usize,
    chip: &str,
    input: &EmulationRecord,
    rows: usize,
    counted: usize,
    cols: usize,
    preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    derived: Option<DivRemAddRows<'_>>,
    launch: impl FnOnce(
        *const c_void,
        usize,
        *mut c_void,
        *mut c_void,
        &CudaStream,
    ) -> pico_gpu_api::Error,
) -> TraceData<'t, F> {
    assert_eq!(
        counted, rows,
        "{chip}: the counter's height is not the fill descriptor's"
    );

    let padded_nrows = match input.shape_chip_size(chip) {
        Some(log2_nrows) => 1 << log2_nrows,
        None => next_power_of_two(rows, None),
    };

    let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

    let sync_mem_pool = get_global_mem_pool(device_id);
    let mem_pool = &sync_mem_pool.0;

    let d_byte_trace = preallocated_gpu_memory
        .d_byte_trace
        .as_mut()
        .unwrap()
        .as_mut_ptr();

    let trace_size = padded_nrows * cols;
    let mut d_trace =
        DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
            .unwrap();

    if let Some(derived) = &derived {
        derived.wait_appended(stream);
    }
    let reader = chunk_history_reader(preallocated_gpu_memory, stream);
    let args = reader.args();
    let kernels = device::start(stream);
    let err = launch(
        std::ptr::from_ref(&args).cast(),
        trace_size,
        d_trace.as_mut_ptr().cast(),
        d_byte_trace.cast(),
        stream,
    );
    assert_eq!(err.code, 0, "{chip}: the history entry failed: {err}");
    history_launch::note(chip);
    drop(reader);
    if let Some(derived) = derived {
        derived.release_after(stream);
    }

    let sync_stream = get_global_stream_pool(device_id);
    let main_stream = &sync_stream.0;
    device::launched(kernels, stream);
    device::wait(stream).unwrap();
    let d_trace = d_trace.swap_stream(main_stream);
    device::wait(stream).unwrap();
    device::wait(main_stream).unwrap();

    info!("[{chip}] generate_extra_record_and_main from the history on GPU");
    TraceData::Gpu(cols, d_trace)
}

#[cfg(feature = "cuda")]
/// The chunk's fill on the device.
///
/// # Panics
///
/// If the chunk has none: a chip reads the history only of a record that carries one, and such a
/// record's fill is uploaded with the chunk.
pub(crate) fn chunk_history<'h, 'a>(
    preallocated_gpu_memory: &'h PreallocatedGpuMemory<'a>,
) -> &'h DeviceHistory<'a> {
    preallocated_gpu_memory
        .d_history
        .as_ref()
        .expect("a record traced from its history reached a chip without its device fill")
}

#[cfg(feature = "cuda")]
/// The chunk's fill as the kernels on `stream` read it. Making the reader makes `stream` wait for
/// the whole fill; dropping it once the kernels are enqueued marks the end of `stream`'s reads,
/// which the fill's error-word read-back and its free follow.
pub(crate) fn chunk_history_reader<'h, 'a>(
    preallocated_gpu_memory: &'h PreallocatedGpuMemory<'a>,
    stream: &'h CudaStream,
) -> HistoryReader<'h, 'a> {
    chunk_history(preallocated_gpu_memory)
        .reader(stream, Readiness::Complete)
        .unwrap_or_else(|e| panic!("reading the chunk's device history: {e}"))
}

impl<F: Field> AddChip<F> {
    /// Populate a single trace row from an ADD event.
    ///
    /// `operand_1` = `b`, `operand_2` = `c`, result = `b + c` = `a` (mod 2^64).
    /// Values are stored as four u16 limbs (little-endian) to match `Add64Gadget`.
    fn event_to_row(
        &self,
        event: &AluEvent,
        cols: &mut AddValueCols<F>,
        blu: &mut impl ByteRecordBehavior,
    ) {
        cols.is_add = F::ONE;
        cols.add_operation.populate(blu, event.b, event.c);
        cols.operand_1 = Word::from(event.b);
        cols.operand_2 = Word::from(event.c);
    }
}
