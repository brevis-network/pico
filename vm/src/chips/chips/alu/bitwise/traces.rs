use super::{columns::NUM_BITWISE_COLS, BitwiseChip};
#[cfg(feature = "cuda")]
use crate::{
    chips::trace::TraceData,
    cuda_adaptor::resource_pool::{
        mem_pool::get_global_mem_pool, stream_pool::get_global_stream_pool,
    },
    emulator::riscv::{history::ExecutionHistory, history_fill::HISTORY_LAYOUT},
    instances::preparer::{PreallocatedGpuMemory, PreparedGpuEvents, Readiness},
    machine::chip::GpuChipBehavior,
    mle::{machine::trace_oracle::history_launch, spans::device},
};
use crate::{
    chips::{
        chips::{
            alu::{
                bitwise::columns::{BitwiseValueCols, NUM_BITWISE_VALUE_COLS},
                event::AluEvent,
            },
            byte::event::ByteRecordBehavior,
        },
        gadgets::bitwise_u16::BitWiseU16Gadget,
        utils::next_power_of_two,
    },
    compiler::{
        riscv::{opcode::Opcode, program::Program},
        word::Word,
    },
    emulator::riscv::record::{AluStream, EmulationRecord},
    iter::{IndexedPicoIterator, PicoIterator, PicoSliceMut},
    machine::{
        chip::ChipBehavior,
        estimator::{EventCapture, EventSizeCapture},
    },
    primitives::consts::BITWISE_DATAPAR,
};
use core::borrow::BorrowMut;
#[cfg(feature = "cuda")]
use cudart::{
    memory_pools::DevicePoolAllocation,
    slice::CudaSliceMut,
    stream::{CudaStream, CudaStreamCreateFlags},
};
use p3_field::{Field, PrimeField32};
#[cfg(feature = "cuda")]
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
#[cfg(feature = "cuda")]
use pico_gpu_api::history_bitwise_mul_shift::cuda_bitwise_generate_extra_record_and_main_history;
#[cfg(feature = "cuda")]
use tracing::info;

impl<F: PrimeField32> ChipBehavior<F> for BitwiseChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Bitwise".to_string()
    }

    fn generate_main(&self, input: &EmulationRecord, _: &mut EmulationRecord) -> RowMajorMatrix<F> {
        let ops = input.alu_ops(AluStream::Bitwise);
        let nrows = ops.len().div_ceil(BITWISE_DATAPAR);
        let log2_nrows = input.shape_chip_size(&self.name());
        let padded_nrows = match log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };

        let mut values = vec![F::ZERO; padded_nrows * NUM_BITWISE_COLS];

        let populate_len = ops.len() * NUM_BITWISE_VALUE_COLS;
        values[..populate_len]
            .pico_chunks_mut(NUM_BITWISE_VALUE_COLS)
            .enumerate()
            .for_each(|(index, row)| {
                let cols: &mut BitwiseValueCols<_> = row.borrow_mut();
                self.event_to_row(&ops.get(index), cols, &mut vec![]);
            });

        RowMajorMatrix::new(values, NUM_BITWISE_COLS)
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        let blu_events = input
            .alu_ops(AluStream::Bitwise)
            .par_flat_map(|event, blu| {
                let mut dummy = BitwiseValueCols::default();
                self.event_to_row(event, &mut dummy, blu);
            });

        extra.add_byte_lookup_events(blu_events);
    }

    // flag reflecting whether chip is used in the record
    fn is_active(&self, record: &Self::Record) -> bool {
        // Under a pad shape the shape decides presence, so a bucketed chunk's proof shape
        // depends on the chunk kind rather than on its opcode mix. Without a shape the
        // chip is event-driven, which is what the natural-height path wants.
        if let Some(shape) = record.shape.as_ref() {
            return shape.included::<F, _>(self);
        }
        !record.alu_ops(AluStream::Bitwise).is_empty()
    }

    fn local_only(&self) -> bool {
        true
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32> GpuChipBehavior<F> for BitwiseChip<F> {
    fn is_active_for_extra_record(&self, record: &PreparedGpuEvents) -> bool {
        record.event_counter.num_bitwise_events > 0
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
impl<F: PrimeField32> BitwiseChip<F> {
    /// The trace from the chunk's history on the device: the kernel reads the bitwise list there,
    /// so no event is uploaded, and the list's length sizes the trace. The counter the activity
    /// check read must have counted the same list.
    fn gpu_generate_from_history(
        &self,
        device_id: usize,
        input: &EmulationRecord,
        history: &ExecutionHistory,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        let event_size = history.chip_steps.alu(AluStream::Bitwise).len();
        assert_eq!(
            prepared_gpu_events.event_counter.num_bitwise_events, event_size,
            "the counter's bitwise height is not the history's bitwise list"
        );

        let nrows = event_size.div_ceil(BITWISE_DATAPAR);
        let log2_nrows = input.shape_chip_size(&self.name());
        let padded_nrows = match log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let d_byte_trace = preallocated_gpu_memory
            .d_byte_trace
            .as_mut()
            .unwrap()
            .as_mut_ptr();

        let trace_size = padded_nrows * NUM_BITWISE_COLS;
        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .unwrap();

        // Waits on `stream` for the whole fill; dropped after the launch, its end-of-reads mark is
        // what the fill's error-word read-back and free follow.
        let reader = preallocated_gpu_memory
            .d_history
            .as_ref()
            .expect("a chunk whose chips read its history has its fill on the device")
            .reader(stream, Readiness::Complete)
            .unwrap_or_else(|e| panic!("reading the chunk's device history: {e}"));
        let args = reader.args();
        let kernels = device::start(stream);
        let err = unsafe {
            cuda_bitwise_generate_extra_record_and_main_history(
                std::ptr::from_ref(&args).cast(),
                HISTORY_LAYOUT,
                NUM_BITWISE_VALUE_COLS,
                trace_size,
                d_trace.as_mut_ptr() as *mut _,
                d_byte_trace as *mut _,
                stream.into(),
            )
        };
        assert_eq!(
            err.code, 0,
            "cuda_bitwise_generate_extra_record_and_main_history failed: {err}"
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

        info!("[bitwise-chip] generate_extra_record_and_main from the history on GPU");
        TraceData::Gpu(NUM_BITWISE_COLS, d_trace)
    }
}

impl<F: Field> BitwiseChip<F> {
    /// Create a row from an event.
    fn event_to_row(
        &self,
        event: &AluEvent,
        cols: &mut BitwiseValueCols<F>,
        blu: &mut impl ByteRecordBehavior,
    ) {
        let a = event.a;
        let b = event.b;
        let c = event.c;

        cols.b = Word::from(b);
        cols.c = Word::from(c);

        cols.is_xor = F::from_bool(event.opcode == Opcode::XOR);
        cols.is_or = F::from_bool(event.opcode == Opcode::OR);
        cols.is_and = F::from_bool(event.opcode == Opcode::AND);

        // Use BitWiseGadget to populate the result
        BitWiseU16Gadget::populate(&mut cols.bitwise, blu, a, b, c, event.opcode);
    }
}

impl<F> EventCapture for BitwiseChip<F> {
    fn count_extra_records(record: &EmulationRecord, event_counter: &mut EventSizeCapture) {
        event_counter.num_bitwise_events += record.alu_ops(AluStream::Bitwise).len();
    }
}
