use super::{columns::NUM_BITWISE_COLS, BitwiseChip};
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
    machine::{
        chip::ChipBehavior,
        estimator::{EventCapture, EventSizeCapture},
    },
    primitives::consts::BITWISE_DATAPAR,
};
use core::borrow::BorrowMut;
use cudart::{
    memory_pools::DevicePoolAllocation,
    slice::{CudaSlice, CudaSliceMut},
    stream::{CudaStream, CudaStreamCreateFlags},
};
use cudart_sys::*;
use p3_field::{Field, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use pico_gpu_api::cuda_bitwise_generate_extra_record_and_main_u64;
use tracing::info;

impl<F: PrimeField32> ChipBehavior<F> for BitwiseChip<F> {
    type Record = EmulationRecord;
    type GpuRecord = FFIEmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Bitwise".to_string()
    }

    fn generate_main(&self, input: &EmulationRecord, _: &mut EmulationRecord) -> RowMajorMatrix<F> {
        let events = input.bitwise_events.iter().collect::<Vec<_>>();
        let nrows = events.len().div_ceil(BITWISE_DATAPAR);
        let log2_nrows = input.shape_chip_size(&self.name());
        let padded_nrows = match log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };

        let mut values = vec![F::ZERO; padded_nrows * NUM_BITWISE_COLS];

        let populate_len = events.len() * NUM_BITWISE_VALUE_COLS;
        values[..populate_len]
            .pico_chunks_mut(NUM_BITWISE_VALUE_COLS)
            .zip_eq(events)
            .for_each(|(row, event)| {
                let cols: &mut BitwiseValueCols<_> = row.borrow_mut();
                self.event_to_row(event, cols, &mut vec![]);
            });

        RowMajorMatrix::new(values, NUM_BITWISE_COLS)
    }

    fn extra_record(&self, input: &Self::Record, extra: &mut Self::Record) {
        let chunk_size = std::cmp::max(input.bitwise_events.len() / num_cpus::get(), 1);

        let blu_events = input
            .bitwise_events
            .pico_chunks(chunk_size)
            .flat_map(|events| {
                let mut blu = vec![];
                events.iter().for_each(|event| {
                    let mut dummy = BitwiseValueCols::default();
                    self.event_to_row(event, &mut dummy, &mut blu);
                });
                blu
            })
            .collect();

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
        !record.bitwise_events.is_empty()
    }

    fn local_only(&self) -> bool {
        true
    }

    fn count_extra_records(record: &Self::Record, counter: &mut EventCounter) {
        counter.num_bitwise_events += record.bitwise_events.len();
    }

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
        let events = &input.bitwise_events;

        let nrows = events.len().div_ceil(BITWISE_DATAPAR);
        let log2_nrows = input.shape_chip_size(&self.name());
        let padded_nrows = match log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;
        // TODO: check error
        // gpu generate trace
        let event_size = events.len();
        let mut d_events =
            DevicePoolAllocation::<AluEvent>::alloc_from_pool_async(event_size, mem_pool, stream)
                .unwrap();
        // Same bytes from the preparer's pinned staging when present (a pageable source
        // blocks this thread for the whole DMA); unstaged chunks keep the Vec upload.
        let staged = prepared_gpu_events.staged_alu.bitwise();
        unsafe {
            let src_ptr: *const std::ffi::c_void = if staged.len() == event_size && event_size > 0 {
                staged.as_ptr() as *const _
            } else {
                CudaSlice::as_slice(events).as_c_void_ptr()
            };
            let _ = cudaMemcpyAsync(
                d_events.as_mut_c_void_ptr(),
                src_ptr,
                event_size * size_of::<AluEvent>(),
                CudaMemoryCopyKind::HostToDevice,
                stream.into(),
            );
        }

        let trace_size = padded_nrows * NUM_BITWISE_COLS;
        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .unwrap();
        let d_byte_trace = preallocated_gpu_memory.d_byte_trace.as_mut().unwrap();
        unsafe {
            cuda_bitwise_generate_extra_record_and_main_u64(
                NUM_BITWISE_VALUE_COLS,
                event_size,
                trace_size,
                d_events.as_ptr() as *const _,
                d_trace.as_mut_ptr() as *mut _,
                d_byte_trace.as_mut_ptr() as *mut _,
                stream.into(),
            );
        }

        let sync_stream = get_global_stream_pool(device_id);
        let main_stream = &sync_stream.0;
        stream.synchronize().unwrap();
        let d_trace = d_trace.swap_stream(main_stream);
        stream.synchronize().unwrap();
        main_stream.synchronize().unwrap();

        info!("[bitwise-chip] generate_extra_record_and_main on GPU");
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
        event_counter.num_bitwise_events += record.bitwise_events.len();
    }
}
