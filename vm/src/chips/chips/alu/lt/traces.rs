use super::columns::{LtValueCols, NUM_LT_COLS, NUM_LT_VALUE_COLS};
use crate::{
    chips::{
        chips::{alu::event::AluEvent, byte::event::ByteRecordBehavior},
        trace::TraceData,
        utils::next_power_of_two,
    },
    compiler::{
        riscv::{opcode::Opcode, program::Program},
        word::Word,
    },
    cuda_adaptor::resource_pool::{
        mem_pool::get_global_mem_pool, stream_pool::get_global_stream_pool,
    },
    emulator::riscv::{ffi::FFIEmulationRecord, record::EmulationRecord},
    instances::preparer::{EventCounter, PreallocatedGpuMemory, PreparedGpuEvents},
    iter::{IndexedPicoIterator, PicoIterator, PicoSlice, PicoSliceMut},
    machine::chip::ChipBehavior,
    primitives::consts::{u64_to_u16_limbs, LT_DATAPAR},
};
use core::borrow::BorrowMut;
use cudart::{
    memory_pools::DevicePoolAllocation,
    slice::CudaSliceMut,
    stream::{CudaStream, CudaStreamCreateFlags},
};
use p3_air::BaseAir;
use p3_field::{Field, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use pico_gpu_api::{
    cuda_lt_generate_extra_record_and_main_u64, cuda_lt_generate_extra_record_and_main_u64_packed,
};
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
    type GpuRecord = FFIEmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "LessThan".to_string()
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let events = input.lt_events.as_slice().iter().collect::<Vec<_>>();
        let nrows = events.len().div_ceil(LT_DATAPAR);
        let log2_nrows = input.shape_chip_size(&self.name());
        let padded_nrows = match log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };

        let mut values = vec![F::ZERO; padded_nrows * NUM_LT_COLS];

        let populate_len = events.len() * NUM_LT_VALUE_COLS;
        values[..populate_len]
            .pico_chunks_mut(NUM_LT_VALUE_COLS)
            .zip_eq(events)
            .for_each(|(row, event)| {
                let cols: &mut LtValueCols<_> = row.borrow_mut();
                self.event_to_row(event, cols, &mut vec![]);
            });

        RowMajorMatrix::new(values, NUM_LT_COLS)
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        let chunk_size = std::cmp::max(input.lt_events.len() / num_cpus::get(), 1);

        let blu_events = input
            .lt_events
            .as_slice()
            .pico_chunks(chunk_size)
            .flat_map(|events| {
                let mut blu = vec![];
                events.iter().for_each(|event| {
                    let mut dummy = LtValueCols::default();
                    self.event_to_row(event, &mut dummy, &mut blu);
                });
                blu
            })
            .collect();

        extra.add_byte_lookup_events(blu_events);
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        // Under a pad shape the shape decides presence, so a bucketed chunk's proof shape
        // depends on the chunk kind rather than on its opcode mix. Without a shape the
        // chip is event-driven, which is what the natural-height path wants.
        if let Some(shape) = record.shape.as_ref() {
            return shape.included::<F, _>(self);
        }
        !record.lt_events.is_empty()
    }

    fn local_only(&self) -> bool {
        true
    }

    fn count_extra_records(record: &Self::Record, counter: &mut EventCounter) {
        counter.num_lt_events += record.lt_events.len();
    }

    fn gpu_generate_extra_record_and_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        let event_size = prepared_gpu_events.event_counter.num_lt_events;

        let nrows = event_size.div_ceil(LT_DATAPAR);
        let log2_nrows = input.shape_chip_size(&self.name());
        let padded_nrows = match log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let trace_size = padded_nrows * NUM_LT_COLS;
        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .unwrap();

        let PreallocatedGpuMemory {
            d_lt_events,
            d_byte_trace,
            ..
        } = preallocated_gpu_memory;
        // Absent on zero events (a whitelist shape can still list this chip): the launcher
        // zero-fills the trace and reads no event, so a null pointer is fine.
        let d_lt_events: *mut std::ffi::c_void = d_lt_events
            .as_mut()
            .map_or(std::ptr::null_mut(), |b| b.as_mut_ptr() as *mut _);
        let d_byte_trace = d_byte_trace.as_mut().unwrap();
        if prepared_gpu_events.packed.is_some() {
            // MLE_PACKED_EVENTS: the event buffer holds packed entries.
            unsafe {
                let err = cuda_lt_generate_extra_record_and_main_u64_packed(
                    NUM_LT_VALUE_COLS,
                    event_size,
                    trace_size,
                    d_lt_events as *const _,
                    d_trace.as_mut_ptr() as *mut _,
                    d_byte_trace.as_mut_ptr() as *mut _,
                    stream.into(),
                    crate::instances::preparer::PACKED_EVENT_FORMAT_V1,
                );
                assert_eq!(err.code, 0, "cuda_lt_generate_extra_record_and_main_u64_packed failed (packed format mismatch?)");
            }
        } else {
            unsafe {
                cuda_lt_generate_extra_record_and_main_u64(
                    NUM_LT_VALUE_COLS,
                    event_size,
                    trace_size,
                    d_lt_events as *const _,
                    d_trace.as_mut_ptr() as *mut _,
                    d_byte_trace.as_mut_ptr() as *mut _,
                    stream.into(),
                );
            }
        }

        let sync_stream = get_global_stream_pool(device_id);
        let main_stream = &sync_stream.0;
        stream.synchronize().unwrap();
        let d_trace = d_trace.swap_stream(main_stream);
        stream.synchronize().unwrap();
        main_stream.synchronize().unwrap();

        info!("[lt-chip] generate_extra_record_and_main on GPU");

        TraceData::Gpu(NUM_LT_COLS, d_trace)
    }

    fn is_active_for_extra_record(&self, record: &PreparedGpuEvents) -> bool {
        record.event_counter.num_lt_events > 0
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
