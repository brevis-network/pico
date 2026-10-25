use super::{
    columns::{ShaCompressCols, NUM_SHA_COMPRESS_COLS},
    ShaCompressChip, SHA_COMPRESS_K,
};
use crate::{
    chips::{
        chips::{byte::event::ByteRecordBehavior, riscv_memory::event::MemoryRecordEnum},
        precompiles::sha256::compress::ffi::ShaCompressFfiEvent,
        trace::TraceData,
        utils::{next_power_of_two, pad_rows_fixed},
    },
    compiler::riscv::program::Program,
    cuda_adaptor::resource_pool::{
        mem_pool::get_global_mem_pool, stream_pool::get_global_stream_pool,
    },
    emulator::riscv::{
        ffi::FFIEmulationRecord,
        record::EmulationRecord,
        syscalls::{
            precompiles::{PrecompileEvent, ShaCompressEvent},
            SyscallCode,
        },
    },
    instances::preparer::{PreallocatedGpuMemory, PreparedGpuEvents},
    machine::chip::ChipBehavior,
    primitives::consts::u32_to_half_word,
};
use core::{borrow::BorrowMut, mem::size_of};
use cudart::{
    memory_pools::DevicePoolAllocation,
    slice::{CudaSlice, CudaSliceMut},
    stream::{CudaStream, CudaStreamCreateFlags},
};
use cudart_sys::*;
use log::info;
use p3_air::BaseAir;
use p3_field::PrimeField32;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::{ParallelIterator, ParallelSlice};
use pico_gpu_api::cuda_precompile_sha256_compress_generate_extra_record_and_main;

impl<F: PrimeField32> BaseAir<F> for ShaCompressChip<F> {
    fn width(&self) -> usize {
        NUM_SHA_COMPRESS_COLS
    }
}

impl<F: PrimeField32> ChipBehavior<F> for ShaCompressChip<F> {
    type Record = EmulationRecord;
    type GpuRecord = FFIEmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "ShaCompress".to_string()
    }

    fn generate_main(&self, input: &EmulationRecord, _: &mut EmulationRecord) -> RowMajorMatrix<F> {
        let rows = vec![];

        let mut wrapped_rows = Some(rows);
        for (_, event) in input.get_precompile_events(SyscallCode::SHA_COMPRESS) {
            let event = if let PrecompileEvent::ShaCompress(event) = event {
                event
            } else {
                unreachable!()
            };
            self.event_to_rows(event, &mut wrapped_rows, &mut vec![]);
        }

        let mut rows = wrapped_rows.unwrap();
        let num_real_rows = rows.len();

        let log_rows = input.shape_chip_size(&self.name());
        pad_rows_fixed(&mut rows, || [F::ZERO; NUM_SHA_COMPRESS_COLS], log_rows);

        // Set the octet_num and octect columns for the padded rows.
        let mut octet_num = 0;
        let mut octet = 0;
        for row in rows[num_real_rows..].iter_mut() {
            let cols: &mut ShaCompressCols<F> = row.as_mut_slice().borrow_mut();
            cols.octet_num[octet_num] = F::ONE;
            cols.octet[octet] = F::ONE;
            cols.index = F::from_u32((8 * octet_num + octet) as u32);

            // If in the compression phase, set the k value.
            if octet_num != 0 && octet_num != 9 {
                let compression_idx = octet_num - 1;
                let k_idx = compression_idx * 8 + octet;
                cols.k = u32_to_half_word(SHA_COMPRESS_K[k_idx]);
            }

            octet = (octet + 1) % 8;
            if octet == 0 {
                octet_num = (octet_num + 1) % 10;
            }
        }

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_SHA_COMPRESS_COLS,
        )
    }

    fn extra_record(&self, input: &Self::Record, output: &mut Self::Record) {
        let compress_events: Vec<_> = input
            .get_precompile_events(SyscallCode::SHA_COMPRESS)
            .iter()
            .filter_map(|(_, event)| {
                if let PrecompileEvent::ShaCompress(event) = event {
                    Some(event)
                } else {
                    unreachable!()
                }
            })
            .collect();

        let chunk_size = std::cmp::max(compress_events.len() / num_cpus::get(), 1);
        let blu_batches = compress_events
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
                .get_precompile_events(SyscallCode::SHA_COMPRESS)
                .is_empty()
        }
    }

    fn is_active_for_extra_record(&self, record: &PreparedGpuEvents) -> bool {
        if let Some(shape) = record.shape.as_ref() {
            shape.included::<F, _>(self)
        } else {
            !record.sha_compress_events.is_empty()
        }
    }

    fn gpu_generate_extra_record_and_main(
        &self,
        device_id: usize,
        input: &Self::Record,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> TraceData<'_, F> {
        let events = &prepared_gpu_events.sha_compress_events;

        let num_cols_per_row = NUM_SHA_COMPRESS_COLS;
        let log_rows = input.shape_chip_size(&self.name());
        // Each SHA compress event generates 80 rows (8 init + 64 compress + 8 finalize)
        let num_total_rows = next_power_of_two(events.len() * 80, log_rows);
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
        let mut d_events = DevicePoolAllocation::<ShaCompressFfiEvent>::alloc_from_pool_async(
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
                event_size * size_of::<ShaCompressFfiEvent>(),
                CudaMemoryCopyKind::HostToDevice,
                stream.into(),
            );
        }
        let d_byte_trace = preallocated_gpu_memory.d_byte_trace.as_mut().unwrap();
        unsafe {
            cuda_precompile_sha256_compress_generate_extra_record_and_main(
                d_events.as_ptr() as *const _,
                event_size,
                size_of::<ShaCompressCols<F>>(),
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

        info!("[precompile-sha256-compress-chip] gpu_generate_extra_record_and_main on GPU");

        TraceData::Gpu(num_cols_per_row, d_trace)
    }
}

impl<F: PrimeField32> ShaCompressChip<F> {
    fn event_to_rows(
        &self,
        event: &ShaCompressEvent,
        rows: &mut Option<Vec<[F; NUM_SHA_COMPRESS_COLS]>>,
        blu: &mut impl ByteRecordBehavior,
    ) {
        let og_h = event.h;

        let mut octet_num_idx = 0;

        // Load a, b, c, d, e, f, g, h.
        for j in 0..8usize {
            let mut row = [F::ZERO; NUM_SHA_COMPRESS_COLS];
            let cols: &mut ShaCompressCols<F> = row.as_mut_slice().borrow_mut();

            cols.chunk = F::from_u32(event.chunk);
            cols.clk = F::from_u32(u32::try_from(event.clk).unwrap());

            cols.w_ptr = [
                F::from_u16((event.w_ptr & 0xFFFF) as u16),
                F::from_u16((event.w_ptr >> 16) as u16),
                F::from_u16((event.w_ptr >> 32) as u16),
            ];
            cols.h_ptr = [
                F::from_u16((event.h_ptr & 0xFFFF) as u16),
                F::from_u16((event.h_ptr >> 16) as u16),
                F::from_u16((event.h_ptr >> 32) as u16),
            ];

            cols.octet[j] = F::ONE;
            cols.octet_num[octet_num_idx] = F::ONE;
            cols.is_initialize = F::ONE;

            cols.mem_addr_init.populate(blu, event.h_ptr, j as u64 * 8);
            cols.mem
                .populate(MemoryRecordEnum::Read(event.h_read_records[j]), blu);
            cols.mem_value = u32_to_half_word(event.h_read_records[j].value as u32);
            cols.mem_addr = cols.mem_addr_init.value;

            cols.a = u32_to_half_word(event.h_read_records[0].value as u32);
            cols.b = u32_to_half_word(event.h_read_records[1].value as u32);
            cols.c = u32_to_half_word(event.h_read_records[2].value as u32);
            cols.d = u32_to_half_word(event.h_read_records[3].value as u32);
            cols.e = u32_to_half_word(event.h_read_records[4].value as u32);
            cols.f = u32_to_half_word(event.h_read_records[5].value as u32);
            cols.g = u32_to_half_word(event.h_read_records[6].value as u32);
            cols.h = u32_to_half_word(event.h_read_records[7].value as u32);

            cols.index = F::from_u32(j as u32);

            cols.is_real = F::ONE;

            if rows.as_ref().is_some() {
                rows.as_mut().unwrap().push(row);
            }
        }

        // Performs the compress operation.
        let mut h_array = event.h;
        for j in 0..64usize {
            if j.is_multiple_of(8) {
                octet_num_idx += 1;
            }

            let mut row = [F::ZERO; NUM_SHA_COMPRESS_COLS];
            let cols: &mut ShaCompressCols<F> = row.as_mut_slice().borrow_mut();

            cols.chunk = F::from_u32(event.chunk);
            cols.clk = F::from_u32(u32::try_from(event.clk).unwrap());

            cols.w_ptr = [
                F::from_u16((event.w_ptr & 0xFFFF) as u16),
                F::from_u16((event.w_ptr >> 16) as u16),
                F::from_u16((event.w_ptr >> 32) as u16),
            ];
            cols.h_ptr = [
                F::from_u16((event.h_ptr & 0xFFFF) as u16),
                F::from_u16((event.h_ptr >> 16) as u16),
                F::from_u16((event.h_ptr >> 32) as u16),
            ];

            cols.k = u32_to_half_word(SHA_COMPRESS_K[j]);
            cols.octet[j % 8] = F::ONE;
            cols.octet_num[octet_num_idx] = F::ONE;
            cols.is_compression = F::ONE;

            cols.mem_addr_compress
                .populate(blu, event.w_ptr, j as u64 * 8);
            cols.mem
                .populate(MemoryRecordEnum::Read(event.w_i_read_records[j]), blu);
            cols.mem_value = u32_to_half_word(event.w_i_read_records[j].value as u32);
            cols.mem_addr = cols.mem_addr_compress.value;
            cols.index = F::from_u32(j as u32 + 8);

            let a = h_array[0];
            let b = h_array[1];
            let c = h_array[2];
            let d = h_array[3];
            let e = h_array[4];
            let f = h_array[5];
            let g = h_array[6];
            let h = h_array[7];
            cols.a = u32_to_half_word(a);
            cols.b = u32_to_half_word(b);
            cols.c = u32_to_half_word(c);
            cols.d = u32_to_half_word(d);
            cols.e = u32_to_half_word(e);
            cols.f = u32_to_half_word(f);
            cols.g = u32_to_half_word(g);
            cols.h = u32_to_half_word(h);

            let e_rr_6 = cols.e_rr_6.populate(blu, e, 6);
            let e_rr_11 = cols.e_rr_11.populate(blu, e, 11);
            let e_rr_25 = cols.e_rr_25.populate(blu, e, 25);
            let s1_intermediate = cols.s1_intermediate.populate(blu, e_rr_6, e_rr_11);
            let s1 = cols.s1.populate(blu, s1_intermediate, e_rr_25);

            let e_and_f = cols.e_and_f.populate(blu, e, f);
            let e_not = cols.e_not.populate(e);
            let e_not_and_g = cols.e_not_and_g.populate(blu, e_not, g);
            let ch = cols.ch.populate(blu, e_and_f, e_not_and_g);

            let temp1 = cols
                .temp1
                .populate(blu, h, s1, ch, event.w[j], SHA_COMPRESS_K[j]);

            let a_rr_2 = cols.a_rr_2.populate(blu, a, 2);
            let a_rr_13 = cols.a_rr_13.populate(blu, a, 13);
            let a_rr_22 = cols.a_rr_22.populate(blu, a, 22);
            let s0_intermediate = cols.s0_intermediate.populate(blu, a_rr_2, a_rr_13);
            let s0 = cols.s0.populate(blu, s0_intermediate, a_rr_22);

            let a_and_b = cols.a_and_b.populate(blu, a, b);
            let a_and_c = cols.a_and_c.populate(blu, a, c);
            let b_and_c = cols.b_and_c.populate(blu, b, c);
            let maj_intermediate = cols.maj_intermediate.populate(blu, a_and_b, a_and_c);
            let maj = cols.maj.populate(blu, maj_intermediate, b_and_c);

            let temp2 = cols.temp2.populate(blu, s0, maj);

            let d_add_temp1 = cols.d_add_temp1.populate(blu, d, temp1);
            let temp1_add_temp2 = cols.temp1_add_temp2.populate(blu, temp1, temp2);

            h_array[7] = g;
            h_array[6] = f;
            h_array[5] = e;
            h_array[4] = d_add_temp1;
            h_array[3] = c;
            h_array[2] = b;
            h_array[1] = a;
            h_array[0] = temp1_add_temp2;

            cols.is_real = F::ONE;

            if rows.as_ref().is_some() {
                rows.as_mut().unwrap().push(row);
            }
        }

        let mut v: [u32; 8] = (0..8)
            .map(|i| h_array[i])
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        octet_num_idx += 1;
        // Store a, b, c, d, e, f, g, h.
        for j in 0..8usize {
            let mut row = [F::ZERO; NUM_SHA_COMPRESS_COLS];
            let cols: &mut ShaCompressCols<F> = row.as_mut_slice().borrow_mut();

            cols.chunk = F::from_u32(event.chunk);
            cols.clk = F::from_u32(u32::try_from(event.clk).unwrap());

            cols.w_ptr = [
                F::from_u16((event.w_ptr & 0xFFFF) as u16),
                F::from_u16((event.w_ptr >> 16) as u16),
                F::from_u16((event.w_ptr >> 32) as u16),
            ];
            cols.h_ptr = [
                F::from_u16((event.h_ptr & 0xFFFF) as u16),
                F::from_u16((event.h_ptr >> 16) as u16),
                F::from_u16((event.h_ptr >> 32) as u16),
            ];

            cols.octet[j] = F::ONE;
            cols.octet_num[octet_num_idx] = F::ONE;
            cols.is_finalize = F::ONE;

            cols.mem_addr_finalize
                .populate(blu, event.h_ptr, j as u64 * 8);
            cols.mem
                .populate(MemoryRecordEnum::Write(event.h_write_records[j]), blu);
            cols.mem_value = u32_to_half_word(event.h_write_records[j].value as u32);
            cols.mem_addr = cols.mem_addr_finalize.value;
            cols.index = F::from_u32(j as u32 + 72);
            cols.finalize_add.populate(blu, og_h[j], h_array[j]);

            v[j] = h_array[j];
            cols.a = u32_to_half_word(v[0]);
            cols.b = u32_to_half_word(v[1]);
            cols.c = u32_to_half_word(v[2]);
            cols.d = u32_to_half_word(v[3]);
            cols.e = u32_to_half_word(v[4]);
            cols.f = u32_to_half_word(v[5]);
            cols.g = u32_to_half_word(v[6]);
            cols.h = u32_to_half_word(v[7]);

            match j {
                0 => cols.finalized_operand = cols.a,
                1 => cols.finalized_operand = cols.b,
                2 => cols.finalized_operand = cols.c,
                3 => cols.finalized_operand = cols.d,
                4 => cols.finalized_operand = cols.e,
                5 => cols.finalized_operand = cols.f,
                6 => cols.finalized_operand = cols.g,
                7 => cols.finalized_operand = cols.h,
                _ => panic!("unsupported j"),
            };

            cols.is_real = F::ONE;

            if rows.as_ref().is_some() {
                rows.as_mut().unwrap().push(row);
            }
        }
    }
}
