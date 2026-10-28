use crate::{
    chips::{
        chips::{byte::event::ByteRecordBehavior, events::ByteLookupEvent},
        precompiles::sha256::extend::{
            columns::{ShaExtendCols, NUM_SHA_EXTEND_COLS},
            ShaExtendChip,
        },
        utils::pad_rows_fixed,
    },
    compiler::riscv::{opcode::ByteOpcode, program::Program},
    emulator::riscv::{
        record::EmulationRecord,
        syscalls::{
            precompiles::{PrecompileEvent, ShaExtendEvent},
            SyscallCode,
        },
    },
    machine::chip::ChipBehavior,
};
use core::borrow::BorrowMut;

#[cfg(feature = "cuda")]
use crate::{
    chips::{
        precompiles::sha256::extend::ffi::ShaExtendFfiEvent, trace::TraceData,
        utils::next_power_of_two,
    },
    cuda_adaptor::resource_pool::{
        mem_pool::get_global_mem_pool, stream_pool::get_global_stream_pool,
    },
    instances::preparer::{PreallocatedGpuMemory, PreparedGpuEvents},
    machine::chip::GpuChipBehavior,
};
#[cfg(feature = "cuda")]
use core::mem::size_of;
#[cfg(feature = "cuda")]
use cudart::{
    memory_pools::DevicePoolAllocation,
    slice::{CudaSlice, CudaSliceMut},
    stream::{CudaStream, CudaStreamCreateFlags},
};
#[cfg(feature = "cuda")]
use cudart_sys::*;
#[cfg(feature = "cuda")]
use log::info;
use p3_air::BaseAir;
use p3_field::PrimeField32;
#[cfg(feature = "cuda")]
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::{ParallelIterator, ParallelSlice};
#[cfg(feature = "cuda")]
use pico_gpu_api::cuda_precompile_sha256_extend_generate_extra_record_and_main;

impl<F: PrimeField32> BaseAir<F> for ShaExtendChip<F> {
    fn width(&self) -> usize {
        NUM_SHA_EXTEND_COLS
    }
}

impl<F: PrimeField32> ChipBehavior<F> for ShaExtendChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "ShaExtend".to_string()
    }

    fn generate_main(&self, input: &EmulationRecord, _: &mut EmulationRecord) -> RowMajorMatrix<F> {
        let rows = vec![];

        let mut wrapped_rows = Some(rows);
        for (_, event) in input.get_precompile_events(SyscallCode::SHA_EXTEND).iter() {
            let event = if let PrecompileEvent::ShaExtend(event) = event {
                event
            } else {
                unreachable!()
            };

            self.event_to_rows(event, &mut wrapped_rows, &mut vec![]);
        }

        let mut rows = wrapped_rows.unwrap();

        let log_rows = input.shape_chip_size(&self.name());
        pad_rows_fixed(&mut rows, || [F::ZERO; NUM_SHA_EXTEND_COLS], log_rows);

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_SHA_EXTEND_COLS,
        )
    }

    fn extra_record(&self, input: &Self::Record, output: &mut Self::Record) {
        let extend_events: Vec<_> = input
            .get_precompile_events(SyscallCode::SHA_EXTEND)
            .iter()
            .filter_map(|(_, event)| {
                if let PrecompileEvent::ShaExtend(event) = event {
                    Some(event)
                } else {
                    unreachable!()
                }
            })
            .collect();
        let chunk_size = std::cmp::max(extend_events.len() / num_cpus::get(), 1);
        let blu_batches = extend_events
            .par_chunks(chunk_size)
            .flat_map(|events| {
                let mut blu = vec![];
                events.iter().for_each(|event| {
                    self.event_to_rows(event, &mut None, &mut blu);
                });
                blu
            })
            .collect();

        output.add_byte_lookup_events(blu_batches);
    }

    fn is_active(&self, record: &Self::Record) -> bool {
        if let Some(shape) = record.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !record
                .get_precompile_events(SyscallCode::SHA_EXTEND)
                .is_empty()
        }
    }
}

#[cfg(feature = "cuda")]
impl<F: PrimeField32> GpuChipBehavior<F> for ShaExtendChip<F> {
    fn gpu_generate_extra_record_and_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        let events = &prepared_gpu_events.sha_extend_events;

        let num_cols_per_row = NUM_SHA_EXTEND_COLS;
        let log_rows = input.shape_chip_size(&self.name());
        // Each SHA extend event generates 48 rows
        let num_total_rows = next_power_of_two(events.len() * 48, log_rows);
        let trace_size = num_total_rows * num_cols_per_row;
        let event_size = events.len();

        // TODO: hack so that zero length events are correct, which requires
        // calling the kernel
        //
        // our CUDA bridge uses as_slice to convert to pointer for some reason
        // which causes rust to panic when the allocation is 0
        let event_alloc_size = if event_size == 0 { 1 } else { event_size };

        let stream = &CudaStream::create_with_flags(CudaStreamCreateFlags::NON_BLOCKING).unwrap();

        let sync_mem_pool = get_global_mem_pool(device_id);
        let mem_pool = &sync_mem_pool.0;

        // Allocate device memory for events
        let mut d_events = DevicePoolAllocation::<ShaExtendFfiEvent>::alloc_from_pool_async(
            event_alloc_size,
            mem_pool,
            stream,
        )
        .unwrap();
        // Allocate device memory for trace output
        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .unwrap();

        unsafe {
            let _ = cudaMemcpyAsync(
                d_events.as_mut_c_void_ptr(),
                events.as_c_void_ptr(),
                event_size * size_of::<ShaExtendFfiEvent>(),
                CudaMemoryCopyKind::HostToDevice,
                stream.into(),
            );
        }

        let d_byte_trace = preallocated_gpu_memory.d_byte_trace.as_mut().unwrap();
        unsafe {
            cuda_precompile_sha256_extend_generate_extra_record_and_main(
                d_events.as_ptr() as *const _,
                event_size,
                d_trace.as_mut_ptr() as *mut _,
                num_total_rows,
                num_cols_per_row,
                d_byte_trace.as_mut_ptr() as *mut _,
                stream.into(),
            );
        }

        // Switch to main stream for further processing
        let sync_stream = get_global_stream_pool(device_id);
        let main_stream = &sync_stream.0;
        stream.synchronize().unwrap();
        let d_trace = d_trace.swap_stream(main_stream);
        stream.synchronize().unwrap();
        main_stream.synchronize().unwrap();

        info!("[precompile-sha256-extend-chip] generate_extra_record_and_main on GPU");

        TraceData::Gpu(num_cols_per_row, d_trace)
    }

    fn is_active_for_extra_record(&self, record: &PreparedGpuEvents) -> bool {
        if let Some(shape) = record.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !record.sha_extend_events.is_empty()
        }
    }
}

impl<F: PrimeField32> ShaExtendChip<F> {
    fn event_to_rows(
        &self,
        event: &ShaExtendEvent,
        rows: &mut Option<Vec<[F; NUM_SHA_EXTEND_COLS]>>,
        blu: &mut impl ByteRecordBehavior,
    ) {
        let start_clk = event.clk;
        for j in 0..48_usize {
            let mut row = [F::ZERO; NUM_SHA_EXTEND_COLS];
            let cols: &mut ShaExtendCols<F> = row.as_mut_slice().borrow_mut();
            cols.is_real = F::ONE;
            let i = j as u64 + 16;
            cols.i = F::from_u64(i);
            cols.chunk = F::from_u32(event.chunk);
            cols.clk = F::from_u32(u32::try_from(start_clk + j as u64).unwrap());
            cols.w_ptr = [
                F::from_u64(event.w_ptr & 0xFFFF),
                F::from_u64((event.w_ptr >> 16) & 0xFFFF),
                F::from_u64((event.w_ptr >> 32) & 0xFFFF),
            ];
            cols.w_i_minus_15_ptr
                .populate(blu, event.w_ptr, (i - 15) * 8);
            cols.w_i_minus_2_ptr.populate(blu, event.w_ptr, (i - 2) * 8);
            cols.w_i_minus_16_ptr
                .populate(blu, event.w_ptr, (i - 16) * 8);
            cols.w_i_minus_7_ptr.populate(blu, event.w_ptr, (i - 7) * 8);
            cols.w_i_ptr.populate(blu, event.w_ptr, i * 8);

            cols.w_i_minus_15.populate(event.w_i_minus_15_reads[j], blu);
            cols.w_i_minus_2.populate(event.w_i_minus_2_reads[j], blu);
            cols.w_i_minus_16.populate(event.w_i_minus_16_reads[j], blu);
            cols.w_i_minus_7.populate(event.w_i_minus_7_reads[j], blu);

            // `s0 := (w[i-15] rightrotate 7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift
            // 3)`.
            let w_i_minus_15 = event.w_i_minus_15_reads[j].value;
            let w_i_minus_15_rr_7 = cols.w_i_minus_15_rr_7.populate(blu, w_i_minus_15 as u32, 7);
            let w_i_minus_15_rr_18 = cols
                .w_i_minus_15_rr_18
                .populate(blu, w_i_minus_15 as u32, 18);
            let w_i_minus_15_rs_3 = cols.w_i_minus_15_rs_3.populate(blu, w_i_minus_15 as u32, 3);
            let s0_intermediate =
                cols.s0_intermediate
                    .populate(blu, w_i_minus_15_rr_7, w_i_minus_15_rr_18);
            let s0 = cols.s0.populate(blu, s0_intermediate, w_i_minus_15_rs_3);

            // `s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift
            // 10)`.
            let w_i_minus_2 = event.w_i_minus_2_reads[j].value;
            let w_i_minus_2_rr_17 = cols.w_i_minus_2_rr_17.populate(blu, w_i_minus_2 as u32, 17);
            let w_i_minus_2_rr_19 = cols.w_i_minus_2_rr_19.populate(blu, w_i_minus_2 as u32, 19);
            let w_i_minus_2_rs_10 = cols.w_i_minus_2_rs_10.populate(blu, w_i_minus_2 as u32, 10);
            let s1_intermediate =
                cols.s1_intermediate
                    .populate(blu, w_i_minus_2_rr_17, w_i_minus_2_rr_19);
            let s1 = cols.s1.populate(blu, s1_intermediate, w_i_minus_2_rs_10);

            // Compute `s2`.
            let w_i_minus_7 = event.w_i_minus_7_reads[j].value;
            let w_i_minus_16 = event.w_i_minus_16_reads[j].value;
            cols.s2
                .populate(blu, w_i_minus_16 as u32, s0, w_i_minus_7 as u32, s1);

            cols.w_i.populate(event.w_i_writes[j], blu);
            blu.add_byte_lookup_event(ByteLookupEvent {
                opcode: ByteOpcode::LTU,
                a1: 1u16,
                a2: 0,
                b: j as u8,
                c: 48,
            });

            if rows.as_ref().is_some() {
                rows.as_mut().unwrap().push(row);
            }
        }
    }
}
