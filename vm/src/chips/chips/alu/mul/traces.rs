use super::{columns::NUM_MUL_COLS, MulChip};
use crate::{
    chips::{
        chips::alu::mul::columns::{MulValueCols, NUM_MUL_VALUE_COLS},
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
    emulator::{
        record::RecordBehavior,
        riscv::{ffi::FFIEmulationRecord, record::EmulationRecord},
    },
    instances::preparer::{EventCounter, PreallocatedGpuMemory, PreparedGpuEvents},
    machine::chip::ChipBehavior,
    primitives::consts::MUL_DATAPAR,
};
use cudart::{
    memory_pools::DevicePoolAllocation,
    slice::CudaSliceMut,
    stream::{CudaStream, CudaStreamCreateFlags},
};
use itertools::Itertools;
use p3_air::BaseAir;
use p3_field::{Field, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use pico_gpu_api::cuda_mul_generate_extra_record_and_main_u64;
use std::borrow::BorrowMut;
use tracing::info;

impl<F: Field> BaseAir<F> for MulChip<F> {
    fn width(&self) -> usize {
        NUM_MUL_COLS
    }
}

impl<F: PrimeField32> ChipBehavior<F> for MulChip<F> {
    type Record = EmulationRecord;
    type GpuRecord = FFIEmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Mul".to_string()
    }

    fn generate_main(
        &self,
        input: &EmulationRecord,
        output: &mut EmulationRecord,
    ) -> RowMajorMatrix<F> {
        let events = input.mul_events.iter().collect::<Vec<_>>();
        let nrows = events.len().div_ceil(MUL_DATAPAR);
        let log2_nrows = input.shape_chip_size(&self.name());
        let padded_nrows = match log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };

        let mut values = vec![F::ZERO; padded_nrows * NUM_MUL_COLS];

        let populate_len = events.len() * NUM_MUL_VALUE_COLS;
        let mut record = EmulationRecord::default();

        values[..populate_len]
            .chunks_mut(NUM_MUL_VALUE_COLS)
            .zip_eq(events)
            .for_each(|(row, event)| {
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
        !record.mul_events.is_empty()
    }

    fn local_only(&self) -> bool {
        true
    }
    fn count_extra_records(record: &Self::Record, counter: &mut EventCounter) {
        counter.num_mul_events += record.mul_events.len();
    }

    fn gpu_generate_extra_record_and_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        // The orchestrator already allocated `d_mul_events` and uploaded `input.mul_events` into it
        // (before the DivRem chip ran); `num_mul_events == input.mul_events.len()`, since no kernel
        // appends mul extras. This chip used to ignore that pre-transfer and re-upload the events from
        // a fresh pageable Vec every chunk; use the resident buffer instead.
        let event_size = prepared_gpu_events.event_counter.num_mul_events;

        let nrows = event_size.div_ceil(MUL_DATAPAR);
        let log2_nrows = input.shape_chip_size(&self.name());
        let padded_nrows = match log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        // The orchestrator uploads `input.mul_events` before the DivRem chip; the buffer is
        // absent on zero events (a whitelist shape can still list this chip), and the launcher
        // then zero-fills the trace and reads no event, so a null pointer is fine.
        let d_events_ptr: *const std::ffi::c_void = preallocated_gpu_memory
            .d_mul_events
            .as_ref()
            .map_or(std::ptr::null(), |b| b.as_ptr() as *const _);

        let d_byte_trace = preallocated_gpu_memory.d_byte_trace.as_mut().unwrap();

        let trace_size = padded_nrows * NUM_MUL_COLS;
        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .unwrap();

        unsafe {
            cuda_mul_generate_extra_record_and_main_u64(
                NUM_MUL_VALUE_COLS,
                event_size,
                trace_size,
                d_events_ptr,
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

        info!("[mul-chip] generate_extra_record_and_main on GPU");
        TraceData::Gpu(NUM_MUL_COLS, d_trace)
    }

    fn is_active_for_extra_record(&self, record: &PreparedGpuEvents) -> bool {
        record.event_counter.num_mul_events > 0
    }
}
