use super::{columns::NUM_MUL_COLS, MulChip};
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
        chips::alu::mul::columns::{MulValueCols, NUM_MUL_VALUE_COLS},
        utils::next_power_of_two,
    },
    compiler::{
        riscv::{opcode::Opcode, program::Program},
        word::Word,
    },
    emulator::{
        record::RecordBehavior,
        riscv::record::{AluStream, EmulationRecord},
    },
    machine::chip::ChipBehavior,
    primitives::consts::MUL_DATAPAR,
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
use pico_gpu_api::history_bitwise_mul_shift::cuda_mul_generate_extra_record_and_main_history;
use std::borrow::BorrowMut;
#[cfg(feature = "cuda")]
use tracing::info;

impl<F: Field> BaseAir<F> for MulChip<F> {
    fn width(&self) -> usize {
        NUM_MUL_COLS
    }
}

impl<F: PrimeField32> ChipBehavior<F> for MulChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Mul".to_string()
    }

    fn generate_main(
        &self,
        input: &EmulationRecord,
        output: &mut EmulationRecord,
    ) -> RowMajorMatrix<F> {
        let ops = input.alu_ops(AluStream::Mul);
        let nrows = ops.len().div_ceil(MUL_DATAPAR);
        let log2_nrows = input.shape_chip_size(&self.name());
        let padded_nrows = match log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };

        let mut values = vec![F::ZERO; padded_nrows * NUM_MUL_COLS];

        let populate_len = ops.len() * NUM_MUL_VALUE_COLS;
        let mut record = EmulationRecord::default();

        values[..populate_len]
            .chunks_mut(NUM_MUL_VALUE_COLS)
            .enumerate()
            .for_each(|(index, row)| {
                let event = ops.get(index);
                let cols: &mut MulValueCols<_> = row.borrow_mut();
                // Ensure that the opcode is MUL, MULHU, MULH, MULHSU, or MULW.
                assert!(
                    event.opcode == Opcode::MUL
                        || event.opcode == Opcode::MULHU
                        || event.opcode == Opcode::MULH
                        || event.opcode == Opcode::MULHSU
                        || event.opcode == Opcode::MULW
                );

                // Set the output operand a
                cols.a = Word::from(event.a);

                // Use MulGadget to populate the multiplication columns
                let is_mulh = event.opcode == Opcode::MULH;
                let is_mulhsu = event.opcode == Opcode::MULHSU;
                let is_mulw = event.opcode == Opcode::MULW;
                cols.mul_gadget.populate(
                    &mut record,
                    event.b,
                    event.c,
                    is_mulh,
                    is_mulhsu,
                    is_mulw,
                );

                // Set the input operands b and c
                cols.b = Word::from(event.b);
                cols.c = Word::from(event.c);

                // Set opcode flags
                cols.is_mul = F::from_bool(event.opcode == Opcode::MUL);
                cols.is_mulh = F::from_bool(event.opcode == Opcode::MULH);
                cols.is_mulhu = F::from_bool(event.opcode == Opcode::MULHU);
                cols.is_mulhsu = F::from_bool(event.opcode == Opcode::MULHSU);
                cols.is_mulw = F::from_bool(event.opcode == Opcode::MULW);
            });

        output.append(&mut record);
        RowMajorMatrix::new(values, NUM_MUL_COLS)
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        self.generate_main(input, extra);
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        // Under a pad shape the shape decides presence, so a bucketed chunk's proof shape
        // depends on the chunk kind rather than on its opcode mix. Without a shape the
        // chip is event-driven, which is what the natural-height path wants.
        if let Some(shape) = record.shape.as_ref() {
            return shape.included::<F, _>(self);
        }
        !record.alu_ops(AluStream::Mul).is_empty()
    }

    fn local_only(&self) -> bool {
        true
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32> GpuChipBehavior<F> for MulChip<F> {
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

    fn is_active_for_extra_record(&self, record: &PreparedGpuEvents) -> bool {
        record.event_counter.num_mul_events > 0
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32> MulChip<F> {
    /// The trace from the chunk's history on the device: the kernel reads the mul list there, so no
    /// event is uploaded, and the list's length sizes the trace. The counter the activity check
    /// read must have counted the same list.
    fn gpu_generate_from_history(
        &self,
        device_id: usize,
        input: &EmulationRecord,
        history: &ExecutionHistory,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        let event_size = history.chip_steps.alu(AluStream::Mul).len();
        assert_eq!(
            prepared_gpu_events.event_counter.num_mul_events, event_size,
            "the counter's mul height is not the history's mul list"
        );

        let nrows = event_size.div_ceil(MUL_DATAPAR);
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

        let trace_size = padded_nrows * NUM_MUL_COLS;
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
            cuda_mul_generate_extra_record_and_main_history(
                std::ptr::from_ref(&args).cast(),
                HISTORY_LAYOUT,
                NUM_MUL_VALUE_COLS,
                trace_size,
                d_trace.as_mut_ptr() as *mut _,
                d_byte_trace as *mut _,
                stream.into(),
            )
        };
        assert_eq!(
            err.code, 0,
            "cuda_mul_generate_extra_record_and_main_history failed: {err}"
        );
        history_launch::note(&self.name());
        drop(reader);

        let sync_stream = get_global_stream_pool(device_id);
        let main_stream = &sync_stream.0;
        device::launched(kernels, stream);
        device::wait(stream).unwrap();
        let d_trace = d_trace.swap_stream(main_stream);
        device::wait(main_stream).unwrap();

        info!("[mul-chip] generate_extra_record_and_main from the history on GPU");
        TraceData::Gpu(NUM_MUL_COLS, d_trace)
    }
}
