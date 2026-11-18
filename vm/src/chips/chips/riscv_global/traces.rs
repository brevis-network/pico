use super::{
    columns::{GlobalCols, NUM_GLOBAL_COLS},
    GlobalChip,
};
#[cfg(feature = "cuda")]
use crate::{
    chips::trace::TraceData,
    cuda_adaptor::resource_pool::{
        mem_pool::get_global_mem_pool, stream_pool::get_global_stream_pool,
    },
    instances::preparer::{EventCounter, PreallocatedGpuMemory, PreparedGpuEvents},
    machine::chip::GpuChipBehavior,
    mle::spans::device,
};
use crate::{
    chips::{
        chips::byte::event::{ByteLookupEvent, ByteRecordBehavior},
        utils::{next_power_of_two, zeroed_f_vec},
    },
    compiler::riscv::program::Program,
    emulator::riscv::record::EmulationRecord,
    iter::{IndexedPicoIterator, PicoIterator, PicoSlice, PicoSliceMut},
    machine::{
        chip::ChipBehavior,
        estimator::{EventCapture, EventSizeCapture},
    },
};
#[cfg(feature = "cuda")]
use cudart::{
    memory_pools::DevicePoolAllocation,
    stream::{CudaStream, CudaStreamCreateFlags},
};
use p3_field::PrimeField32;
#[cfg(feature = "cuda")]
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
#[cfg(feature = "cuda")]
use pico_gpu_api::cuda_riscv_global_generate_extra_record_and_main;
use std::borrow::BorrowMut;
#[cfg(feature = "cuda")]
use tracing::info;

impl<F: PrimeField32> ChipBehavior<F> for GlobalChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Global".to_string()
    }

    fn extra_record(&self, input: &Self::Record, output: &mut Self::Record) {
        let events = &input.global_lookup_events;

        let chunk_size = std::cmp::max(events.len() / num_cpus::get(), 1);

        let blu_batches: Vec<Vec<ByteLookupEvent>> = events
            .pico_chunks(chunk_size)
            .map(|events| {
                let mut blu: Vec<ByteLookupEvent> = vec![];
                events.iter().for_each(|event| {
                    // 25-bit decomposition of message[0] (16 + 8 + 1; the boolean high bit
                    // needs no byte lookup).
                    blu.add_u16_range_check((event.message[0] & 0xFFFF) as u16);
                    // Slot order must match the constraint: b = the 8-bit limb, c = 0.
                    blu.add_u8_range_check(((event.message[0] >> 16) & 0xFF) as u8, 0);
                    // 16 + 9 decomposition of message[1].
                    blu.add_u16_range_check((event.message[1] & 0xFFFF) as u16);
                    blu.add_bit_range_check(((event.message[1] >> 16) & 0x1FF) as u16, 9);
                    blu.add_u16_range_check(event.message[7] as u16);
                });
                blu
            })
            .collect();

        output.add_byte_lookup_events(blu_batches.into_iter().flatten().collect());
    }

    /// One row per cross-chunk event, in the record's order, at the natural power-of-two height.
    /// The MLE machine proves the Global AIR at one fixed height whatever the event count, and
    /// pads to it where it splits the trace into the AIR's two partitions; padding rows are all
    /// zero, so the padding is an append.
    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let events = &input.global_lookup_events;
        let padded_nb_rows = next_power_of_two(events.len(), None);
        let mut values = zeroed_f_vec(padded_nb_rows * NUM_GLOBAL_COLS);

        values[..events.len() * NUM_GLOBAL_COLS]
            .pico_chunks_mut(NUM_GLOBAL_COLS)
            .enumerate()
            .for_each(|(i, row)| {
                let event = &events[i];
                let cols: &mut GlobalCols<F> = row.borrow_mut();
                cols.message = event.message.map(F::from_u32);
                cols.kind = F::from_u8(event.kind);
                cols.is_real = F::ONE;
                if event.is_receive {
                    cols.is_receive = F::ONE;
                    cols.mu = -F::ONE;
                } else {
                    cols.is_send = F::ONE;
                    cols.mu = F::ONE;
                }
                cols.message_0_16bit_limb = F::from_u32(event.message[0] & 0xFFFF);
                cols.message_0_8bit_limb = F::from_u32((event.message[0] >> 16) & 0xFF);
                cols.message_0_high_bit = F::from_u32((event.message[0] >> 24) & 1);
                cols.message_1_16bit_limb = F::from_u32(event.message[1] & 0xFFFF);
                cols.message_1_hi9 = F::from_u32((event.message[1] >> 16) & 0x1FF);
            });

        RowMajorMatrix::new(values, NUM_GLOBAL_COLS)
    }

    fn is_active(&self, _: &Self::Record) -> bool {
        true
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32> GpuChipBehavior<F> for GlobalChip<F> {
    fn count_extra_records(_record: &Self::Record, _counter: &mut EventCounter) {}

    /// One row per cross-chunk event, in the order of the chunk's event buffer on the device: the
    /// kernels of the chips that emit the events have filled it before this one runs. The same
    /// rows as [`ChipBehavior::generate_main`] makes on the host, padded here to the height the
    /// record's shape gives the chip (the host pads to the power of two above the events).
    fn gpu_generate_extra_record_and_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        let event_size = prepared_gpu_events.event_counter.num_global_lookup_events;
        let padded_nb_rows = next_power_of_two(event_size, input.shape_chip_size(&self.name()));

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();
        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        let trace_size = padded_nb_rows * NUM_GLOBAL_COLS;
        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .unwrap();

        // Without events the kernel zeroes the trace and reads nothing, so a chunk that has no
        // event buffer passes null.
        let d_events = match preallocated_gpu_memory.d_global_events.as_mut() {
            Some(d_events) => d_events.as_mut_ptr() as *const std::ffi::c_void,
            None => {
                assert_eq!(
                    event_size, 0,
                    "cross-chunk events without their device buffer"
                );
                std::ptr::null()
            }
        };
        let d_byte_trace = preallocated_gpu_memory.d_byte_trace.as_mut().unwrap();

        let kernels = device::start(stream);
        unsafe {
            cuda_riscv_global_generate_extra_record_and_main(
                NUM_GLOBAL_COLS,
                event_size,
                trace_size,
                d_events,
                d_trace.as_mut_ptr() as *mut _,
                stream.into(),
                d_byte_trace.as_mut_ptr() as *mut _,
            );
        }
        device::launched(kernels, stream);

        let sync_stream = get_global_stream_pool(device_id);
        let main_stream = &sync_stream.0;
        device::wait(stream).unwrap();
        let d_trace = d_trace.swap_stream(main_stream);
        device::wait(main_stream).unwrap();

        info!("[riscv-global-chip] generate_extra_record_and_main on GPU");
        TraceData::Gpu(NUM_GLOBAL_COLS, d_trace)
    }

    fn is_active_for_extra_record(&self, _record: &PreparedGpuEvents) -> bool {
        true
    }
}

impl<F> EventCapture for GlobalChip<F> {
    fn count_extra_records(_record: &EmulationRecord, _event_counter: &mut EventSizeCapture) {}
}
