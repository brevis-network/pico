use super::columns::{LtValueCols, NUM_LT_COLS, NUM_LT_VALUE_COLS};
#[cfg(feature = "cuda")]
use crate::{
    chips::{chips::riscv_cpu::traces::chunk_history_reader, trace::TraceData},
    cuda_adaptor::resource_pool::{
        mem_pool::get_global_mem_pool, stream_pool::get_global_stream_pool,
    },
    emulator::riscv::{history::ExecutionHistory, history_fill::HISTORY_LAYOUT},
    instances::preparer::{PreallocatedGpuMemory, PreparedGpuEvents},
    machine::chip::GpuChipBehavior,
    mle::{machine::trace_oracle::history_launch, spans::device},
};
use crate::{
    chips::{
        chips::{alu::event::AluEvent, byte::event::ByteRecordBehavior},
        utils::next_power_of_two,
    },
    compiler::{
        riscv::{opcode::Opcode, program::Program},
        word::Word,
    },
    emulator::riscv::record::{AluStream, EmulationRecord},
    iter::{IndexedPicoIterator, PicoIterator, PicoSliceMut},
    machine::chip::ChipBehavior,
    primitives::consts::{u64_to_u16_limbs, LT_DATAPAR},
};
use core::borrow::BorrowMut;
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
use pico_gpu_api::history_cpu_memory_lt::cuda_lt_generate_extra_record_and_main_history;
#[cfg(feature = "cuda")]
use tracing::info;

/// Lt Chip for proving U32/U64 Signed/Unsigned b < c
#[derive(Default, Clone, Debug)]
pub struct LtChip<F>(std::marker::PhantomData<F>);

impl<F: Field> BaseAir<F> for LtChip<F> {
    fn width(&self) -> usize {
        NUM_LT_COLS
    }
}

impl<F: PrimeField32> ChipBehavior<F> for LtChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "LessThan".to_string()
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let ops = input.alu_ops(AluStream::Lt);
        let nrows = ops.len().div_ceil(LT_DATAPAR);
        let log2_nrows = input.shape_chip_size(&self.name());
        let padded_nrows = match log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };

        let mut values = vec![F::ZERO; padded_nrows * NUM_LT_COLS];

        let populate_len = ops.len() * NUM_LT_VALUE_COLS;
        values[..populate_len]
            .pico_chunks_mut(NUM_LT_VALUE_COLS)
            .enumerate()
            .for_each(|(index, row)| {
                let cols: &mut LtValueCols<_> = row.borrow_mut();
                self.event_to_row(&ops.get(index), cols, &mut vec![]);
            });

        RowMajorMatrix::new(values, NUM_LT_COLS)
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        let blu_events = input.alu_ops(AluStream::Lt).par_flat_map(|event, blu| {
            let mut dummy = LtValueCols::default();
            self.event_to_row(event, &mut dummy, blu);
        });

        extra.add_byte_lookup_events(blu_events);
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        // Under a pad shape the shape decides presence, so a bucketed chunk's proof shape
        // depends on the chunk kind rather than on its opcode mix. Without a shape the
        // chip is event-driven, which is what the natural-height path wants.
        if let Some(shape) = record.shape.as_ref() {
            return shape.included::<F, _>(self);
        }
        !record.alu_ops(AluStream::Lt).is_empty()
    }

    fn local_only(&self) -> bool {
        true
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32> GpuChipBehavior<F> for LtChip<F> {
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
        record.event_counter.num_lt_events > 0
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32> LtChip<F> {
    /// The trace from the chunk's history on the device: the kernel reads the less-than list, then
    /// builds one comparison per branch step itself, so no event is uploaded and no CPU kernel has
    /// to have run. The two lists' length sizes the trace; the counter the activity check read must
    /// have counted the same rows.
    fn gpu_generate_from_history(
        &self,
        device_id: usize,
        input: &EmulationRecord,
        history: &ExecutionHistory,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        let event_size = history.chip_steps.lt.len() + history.chip_steps.branch.len();
        assert_eq!(
            prepared_gpu_events.event_counter.num_lt_events, event_size,
            "the counter's less-than height is not the history's less-than and branch lists"
        );

        let nrows = event_size.div_ceil(LT_DATAPAR);
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

        let trace_size = padded_nrows * NUM_LT_COLS;
        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .unwrap();

        let reader = chunk_history_reader(preallocated_gpu_memory, stream);
        let args = reader.args();
        let kernels = device::start(stream);
        let err = unsafe {
            cuda_lt_generate_extra_record_and_main_history(
                std::ptr::from_ref(&args).cast(),
                HISTORY_LAYOUT,
                NUM_LT_VALUE_COLS,
                trace_size,
                d_trace.as_mut_ptr() as *mut _,
                d_byte_trace as *mut _,
                stream.into(),
            )
        };
        assert_eq!(
            err.code, 0,
            "cuda_lt_generate_extra_record_and_main_history failed: {err}"
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

        info!("[lt-chip] generate_extra_record_and_main from the history on GPU");

        TraceData::Gpu(NUM_LT_COLS, d_trace)
    }
}

impl<F: PrimeField32> LtChip<F> {
    fn event_to_row(
        &self,
        event: &AluEvent,
        cols: &mut LtValueCols<F>,
        blu: &mut impl ByteRecordBehavior,
    ) {
        let a_u64 = event.a;
        let b_u64 = event.b;
        let c_u64 = event.c;

        // Set the input/output words using u16 limbs
        let a_limbs = u64_to_u16_limbs(a_u64);
        let b_limbs = u64_to_u16_limbs(b_u64);
        let c_limbs = u64_to_u16_limbs(c_u64);

        cols.a = Word(a_limbs.map(F::from_u16));
        cols.b = Word(b_limbs.map(F::from_u16));
        cols.c = Word(c_limbs.map(F::from_u16));

        // Set the opcode selectors
        let is_signed = event.opcode == Opcode::SLT;
        cols.is_slt = F::from_bool(is_signed);
        cols.is_slt_u = F::from_bool(event.opcode == Opcode::SLTU);
        // Merged branch comparison: `a = lt | gt << 16`, so `cols.a = [lt, gt, 0, 0]` and the
        // gadget below still takes its `bit` from limb 0.
        cols.is_cmp = F::from_bool(event.is_cmp);

        // Populate the signed less-than gadget
        cols.lt_signed
            .populate_signed(blu, a_u64, b_u64, c_u64, is_signed);
    }
}
