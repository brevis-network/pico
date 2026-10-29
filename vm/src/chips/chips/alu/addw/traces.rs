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
            alu::{
                addw::{
                    columns::{AddwValueCols, NUM_ADDW_COLS, NUM_ADDW_VALUE_COLS},
                    AddwChip,
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
    emulator::riscv::record::EmulationRecord,
    iter::{IndexedPicoIterator, PicoBridge, PicoIterator, PicoSliceMut},
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
use pico_gpu_api::{
    cuda_addw_generate_extra_record_and_main, cuda_addw_generate_extra_record_and_main_packed,
};
#[cfg(feature = "cuda")]
use tracing::info;

impl<F: PrimeField32> ChipBehavior<F> for AddwChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Addw".to_string()
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        // let events = input.add_sub_events.as_slice();
        let events: Vec<&AluEvent> = input
            .add_sub_events
            .as_slice()
            .iter()
            .filter(|e| e.opcode == Opcode::ADDW)
            .collect();

        let nrows = events.len().div_ceil(ADD_DATAPAR);
        let log2_nrows = input.shape_chip_size(&self.name());
        let padded_nrows = match log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };
        let mut values = vec![F::ZERO; padded_nrows * NUM_ADDW_COLS];

        let populate_len = events.len() * NUM_ADDW_VALUE_COLS;
        values[..populate_len]
            .pico_chunks_mut(NUM_ADDW_VALUE_COLS)
            .zip_eq(events)
            .for_each(|(row, event)| {
                let cols: &mut AddwValueCols<_> = row.borrow_mut();
                self.event_to_row(event, cols, &mut vec![]);
            });

        RowMajorMatrix::new(values, NUM_ADDW_COLS)
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        // let event_iter = input.add_sub_events.as_slice().chunks(chunk_size);
        let events: Vec<&AluEvent> = input
            .add_sub_events
            .as_slice()
            .iter()
            .filter(|e| e.opcode == Opcode::ADDW)
            .collect();

        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);

        let blu_batches = events
            .chunks(chunk_size)
            .pico_bridge()
            .flat_map(|chunk| {
                let mut blu = vec![];
                chunk.iter().for_each(|event| {
                    let mut dummy = AddwValueCols::default();
                    self.event_to_row(event, &mut dummy, &mut blu);
                });
                blu
            })
            .collect();

        extra.add_byte_lookup_events(blu_batches);
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        // Under a pad shape the shape decides presence, so a bucketed chunk's proof shape
        // depends on the chunk kind rather than on its opcode mix. Without a shape the
        // chip is event-driven, which is what the natural-height path wants.
        if let Some(shape) = record.shape.as_ref() {
            return shape.included::<F, _>(self);
        }
        // !record.add_sub_events.is_empty()
        record
            .add_sub_events
            .as_slice()
            .iter()
            .any(|e| e.opcode == Opcode::ADDW)
    }

    fn local_only(&self) -> bool {
        true
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32> GpuChipBehavior<F> for AddwChip<F> {
    fn count_extra_records(record: &Self::Record, counter: &mut EventCounter) {
        counter.num_add_sub_events += record.add_sub_events.len();
    }

    fn gpu_generate_extra_record_and_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        let event_size = prepared_gpu_events.event_counter.num_addw_events;

        let nrows = event_size.div_ceil(ADD_DATAPAR);
        let log2_nrows = input.shape_chip_size(&self.name());
        let padded_nrows = match log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let d_events = preallocated_gpu_memory.d_partitioned_addw_events.as_ref();
        let d_byte_trace = preallocated_gpu_memory.d_byte_trace.as_mut().unwrap();

        let trace_size = padded_nrows * NUM_ADDW_COLS;
        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .unwrap();

        if prepared_gpu_events.packed.is_some() {
            // MLE_PACKED_EVENTS: the event buffer holds packed entries.
            unsafe {
                let err = cuda_addw_generate_extra_record_and_main_packed(
                    NUM_ADDW_VALUE_COLS,
                    event_size,
                    trace_size,
                    d_events.map_or(std::ptr::null(), |e| e.as_ptr() as *const _),
                    d_trace.as_mut_ptr() as *mut _,
                    d_byte_trace.as_mut_ptr() as *mut _,
                    stream.into(),
                    crate::instances::preparer::PACKED_EVENT_FORMAT_V1,
                );
                assert_eq!(err.code, 0, "cuda_addw_generate_extra_record_and_main_packed failed (packed format mismatch?)");
            }
        } else {
            unsafe {
                cuda_addw_generate_extra_record_and_main(
                    NUM_ADDW_VALUE_COLS,
                    event_size,
                    trace_size,
                    d_events.map_or(std::ptr::null(), |e| e.as_ptr() as *const _),
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

        info!("[addw-chip] generate_extra_record_and_main on GPU");
        TraceData::Gpu(NUM_ADDW_COLS, d_trace)
    }

    fn is_active_for_extra_record(&self, record: &PreparedGpuEvents) -> bool {
        record.event_counter.num_add_sub_events > 0
    }
}

impl<F: Field> AddwChip<F> {
    /// Populate a single trace row from an ADDW event.
    ///
    /// Computes `lower32 = (b as u32).wrapping_add(c as u32)`, stores it as two u16 limbs,
    /// and records the MSB for sign extension.
    fn event_to_row(
        &self,
        event: &AluEvent,
        cols: &mut AddwValueCols<F>,
        blu: &mut impl ByteRecordBehavior,
    ) {
        cols.is_addw = F::ONE;
        cols.addw_operation.populate(blu, event.b, event.c);
        cols.operand_1 = Word::from(event.b);
        cols.operand_2 = Word::from(event.c);
    }
}
