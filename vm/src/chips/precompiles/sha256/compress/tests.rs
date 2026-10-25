use crate::{
    chips::{
        chips::byte::{columns::NUM_BYTE_MULT_COLS, ByteChip},
        precompiles::sha256::compress::{
            columns::NUM_SHA_COMPRESS_COLS, controller::NUM_SHA_COMPRESS_CONTROL_COLS,
            ShaCompressChip, ShaCompressControlChip,
        },
        tests::init_test_stream,
        trace::TraceData,
    },
    emulator::riscv::{
        record::EmulationRecord,
        syscalls::{
            precompiles::{sha256::event::ShaCompressEvent, PrecompileEvent},
            SyscallCode, SyscallEvent,
        },
    },
    instances::preparer::{
        gpu_allocate_byte_trace, gpu_finalize_byte_trace, precompute_event_size,
        PreallocatedGpuMemory, PreparedGpuEvents,
    },
    machine::chip::ChipBehavior,
};
use p3_koala_bear::KoalaBear;
use rand::{rng, RngExt};
use std::time::Instant;

type Chip<F> = ShaCompressChip<F>;
type F = KoalaBear;

pub fn generate_sha_compress_bench_record(num_events: usize) -> EmulationRecord {
    let mut rng = rng();
    let mut events = Vec::with_capacity(num_events);

    for i in 0..num_events {
        let mut h = [0u32; 8];
        for val in h.iter_mut() {
            *val = rng.random();
        }

        let mut w = Vec::with_capacity(64);
        for _ in 0..64 {
            w.push(rng.random::<u32>());
        }

        // Simulating memory records - values should match the hash and schedule.
        // Timestamps start at 1: `MemoryAccessCols::populate_access` asserts
        // `timestamp - prev_timestamp - 1 < 2^25`, and with `prev_timestamp: 0` a read at clk 0
        // underflows. The largest value here, 65535 * 100 + 88 for 2^16 events, stays far below
        // the 25-bit budget.
        let mut h_read_records = [Default::default(); 8];
        for j in 0..8 {
            h_read_records[j] = crate::chips::chips::riscv_memory::event::MemoryReadRecord {
                value: h[j] as u64,
                chunk: 1,
                timestamp: (i * 100 + 1 + j) as u32,
                prev_chunk: 1,
                prev_timestamp: 0,
            };
        }

        let mut w_i_read_records = Vec::with_capacity(64);
        for j in 0..64 {
            w_i_read_records.push(crate::chips::chips::riscv_memory::event::MemoryReadRecord {
                value: w[j] as u64,
                chunk: 1,
                timestamp: (i * 100 + 9 + j) as u32,
                prev_chunk: 1,
                prev_timestamp: 0,
            });
        }

        // Final hash after compression (simplified for bench, normally you'd run sha256_compress)
        let mut h_write_records = [Default::default(); 8];
        for j in 0..8 {
            h_write_records[j] = crate::chips::chips::riscv_memory::event::MemoryWriteRecord {
                value: (h[j].wrapping_add(w[j % 64])) as u64, // dummy
                prev_value: h[j] as u64,
                chunk: 1,
                timestamp: (i * 100 + 81 + j) as u32,
                prev_chunk: 1,
                prev_timestamp: (i * 100 + 1 + j) as u32,
            };
        }

        events.push(ShaCompressEvent {
            chunk: 1,
            clk: (i * 100) as u64,
            w_ptr: 0x10000,
            h_ptr: 0x20000,
            w,
            h,
            h_read_records,
            w_i_read_records,
            h_write_records,
            local_mem_access: vec![],
        });
    }

    let mut record = EmulationRecord::default();
    let pre_events: Vec<(SyscallEvent, PrecompileEvent)> = events
        .into_iter()
        .map(|e| (SyscallEvent::default(), PrecompileEvent::ShaCompress(e)))
        .collect();
    record
        .precompile_events
        .insert(SyscallCode::SHA_COMPRESS, pre_events);
    record
}

#[test]
fn test_sha_compress_gpu_generate_extra_record_and_main() {
    // Generate 2^16 synthetic events for correctness test
    // (2^20 would require ~83M rows × 162 cols ≈ 50GB, exceeding GPU memory;
    //  2^16 × 80 rows = 5.2M rows is the practical max)
    let num_events = 1 << 16;
    let original_record = generate_sha_compress_bench_record(num_events);
    let chip = Chip::<F>::default();

    let mut complete_record = original_record.clone();
    chip.extra_record(&original_record, &mut complete_record);

    let mut counted_record = original_record.clone();
    let mut event_counter = precompute_event_size::<F>(&mut counted_record);
    event_counter.num_poseidon2_events = 0;
    event_counter.num_global_lookup_events = 0;
    event_counter.num_syscall_events = 0;
    event_counter.num_precompile_syscall_events = 0;

    event_counter.assert_event_counts_match(&complete_record);

    let cpu_trace = chip.generate_main(&complete_record, &mut EmulationRecord::default());
    let byte_chip = ByteChip::<F>::default();
    let cpu_byte_trace = byte_chip.generate_main(&complete_record, &mut EmulationRecord::default());

    let stream = init_test_stream();
    let prepared_gpu_events = PreparedGpuEvents::new(&counted_record, event_counter);
    let mut preallocated_gpu_memory = PreallocatedGpuMemory {
        d_byte_trace: gpu_allocate_byte_trace(&stream, 0).unwrap(),
        ..Default::default()
    };

    let gpu_trace = chip
        .gpu_generate_extra_record_and_main(
            0,
            &counted_record,
            &prepared_gpu_events,
            &mut preallocated_gpu_memory,
        )
        .to_host(&stream);
    stream.synchronize().unwrap();

    let num_real_rows = num_events * 80;
    let num_cols = NUM_SHA_COMPRESS_COLS;
    let cpu_vals = &cpu_trace.values[..num_real_rows * num_cols];
    let gpu_vals = &gpu_trace.values[..num_real_rows * num_cols];

    if cpu_vals != gpu_vals {
        for row in 0..num_real_rows {
            for col in 0..num_cols {
                let idx = row * num_cols + col;
                if cpu_vals[idx] != gpu_vals[idx] {
                    panic!(
                        "Main trace mismatch at row {}, col {}! CPU: {:?}, GPU: {:?}",
                        row, col, cpu_vals[idx], gpu_vals[idx]
                    );
                }
            }
        }
    }

    gpu_finalize_byte_trace(&stream, &mut preallocated_gpu_memory).unwrap();
    stream.synchronize().unwrap();
    let host_gpu_byte_trace = TraceData::<F>::Gpu(
        NUM_BYTE_MULT_COLS,
        preallocated_gpu_memory.d_byte_trace.take().unwrap(),
    )
    .to_host(&stream);
    stream.synchronize().unwrap();

    // Verify byte trace - for multiplicities, we only care that they match for the used range
    assert_eq!(
        host_gpu_byte_trace.values.len(),
        cpu_byte_trace.values.len(),
        "Byte trace length mismatch"
    );
    assert_eq!(
        host_gpu_byte_trace.values, cpu_byte_trace.values,
        "Byte trace mismatch"
    );
    println!(
        "ShaCompress GPU correctness test passed for {} events!",
        num_events
    );
}

#[test]
fn bench_sha_compress_cpu_vs_gpu() {
    use crate::{
        chips::{
            precompiles::sha256::compress::{columns::ShaCompressCols, ffi::ShaCompressFfiEvent},
            utils::next_power_of_two,
        },
        cuda_adaptor::resource_pool::mem_pool::get_global_mem_pool,
    };
    use cudart::{
        memory_pools::DevicePoolAllocation,
        slice::{CudaSlice, CudaSliceMut},
    };
    use cudart_sys::*;
    use p3_koala_bear::KoalaBear;
    use pico_gpu_api::cuda_precompile_sha256_compress_generate_extra_record_and_main;

    let chip = Chip::<F>::default();
    let byte_chip = ByteChip::<F>::default();

    let warmup_sizes: Vec<usize> = vec![1024];
    let bench_sizes: Vec<usize> = vec![1024, 4096, 16384, 65536];

    println!("\n{:-<60}", "");
    println!(
        "{:<12} {:>12} {:>12} {:>12}",
        "events", "cpu (ms)", "gpu (ms)", "speedup"
    );
    println!("{:-<60}", "");

    for (is_warmup, &num_events) in warmup_sizes
        .iter()
        .map(|n| (true, n))
        .chain(bench_sizes.iter().map(|n| (false, n)))
    {
        let original_record = generate_sha_compress_bench_record(num_events);

        // ── CPU ──
        let mut complete_record = original_record.clone();
        let cpu_start = Instant::now();
        chip.extra_record(&original_record, &mut complete_record);
        let cpu_trace = chip.generate_main(&complete_record, &mut EmulationRecord::default());
        let _cpu_byte = byte_chip.generate_main(&complete_record, &mut EmulationRecord::default());
        let cpu_ms = cpu_start.elapsed().as_secs_f64() * 1000.0;

        // ── GPU (kernel only: exclude H2D and D2H) ──
        let stream = init_test_stream();
        let sync_mem_pool = get_global_mem_pool(0);
        let mem_pool = &sync_mem_pool.0;

        let mut counted_record = original_record.clone();
        let event_counter = precompute_event_size::<F>(&mut counted_record);
        let prepared_gpu_events = PreparedGpuEvents::new(&counted_record, event_counter);

        let events = &prepared_gpu_events.sha_compress_events;
        let event_size = events.len();
        let num_cols = NUM_SHA_COMPRESS_COLS;
        let num_total_rows = next_power_of_two(event_size * 80, None);
        let trace_size = num_total_rows * num_cols;

        let event_alloc_size = if event_size == 0 { 1 } else { event_size };

        // Allocate GPU memory and do H2D transfer (NOT timed)
        let mut d_events = DevicePoolAllocation::<ShaCompressFfiEvent>::alloc_from_pool_async(
            event_alloc_size,
            mem_pool,
            stream,
        )
        .unwrap();
        if event_size > 0 {
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_events.as_mut_c_void_ptr(),
                    events.as_c_void_ptr(),
                    event_size * std::mem::size_of::<ShaCompressFfiEvent>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );
            }
        }
        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .unwrap();
        let mut d_byte_trace = gpu_allocate_byte_trace(stream, 0).unwrap().unwrap();

        stream.synchronize().unwrap();

        // Time only the kernel execution
        let gpu_start = Instant::now();
        unsafe {
            cuda_precompile_sha256_compress_generate_extra_record_and_main(
                d_events.as_ptr() as *const _,
                event_size,
                std::mem::size_of::<ShaCompressCols<F>>(),
                d_trace.as_mut_ptr() as *mut _,
                num_total_rows,
                num_cols,
                d_byte_trace.as_mut_ptr() as *mut _,
                stream.into(),
            );
        }
        stream.synchronize().unwrap();
        let gpu_ms = gpu_start.elapsed().as_secs_f64() * 1000.0;

        if is_warmup {
            println!(
                "{:<12} {:>12} {:>12} {:>12}",
                num_events, "warmup", "warmup", "—"
            );
            continue;
        }

        // ── Verify CPU == GPU (D2H + compare, not timed) ──
        let gpu_trace = TraceData::<F>::Gpu(num_cols, d_trace).to_host(stream);
        stream.synchronize().unwrap();

        let num_real_rows = num_events * 80;
        assert_eq!(
            cpu_trace.values[..num_real_rows * num_cols],
            gpu_trace.values[..num_real_rows * num_cols],
            "Main trace mismatch at bench size {}",
            num_events
        );

        let speedup = cpu_ms / gpu_ms;
        println!(
            "{:<12} {:>12.2} {:>12.2} {:>11.1}x  ✓",
            num_events, cpu_ms, gpu_ms, speedup
        );
    }
    println!("{:-<60}", "");
}

#[test]
fn test_sha_compress_control_gpu_generate_extra_record_and_main() {
    let chip = ShaCompressControlChip::<F>::default();
    let stream = init_test_stream();

    let num_events = 65536;
    let original_record = generate_sha_compress_bench_record(num_events);
    let mut complete_record = original_record.clone();
    chip.extra_record(&original_record, &mut complete_record);

    let event_counter = precompute_event_size::<F>(&mut complete_record);
    let prepared_gpu_events = PreparedGpuEvents::new(&complete_record, event_counter);
    let mut preallocated_gpu_memory = PreallocatedGpuMemory {
        d_byte_trace: gpu_allocate_byte_trace(&stream, 0).unwrap(),
        ..Default::default()
    };

    let gpu_trace_data = chip.gpu_generate_extra_record_and_main(
        0,
        &complete_record,
        &prepared_gpu_events,
        &mut preallocated_gpu_memory,
    );

    let mut expected_byte = EmulationRecord::default();
    let cpu_trace_exact = chip.generate_main(&complete_record, &mut expected_byte);

    let gpu_trace = gpu_trace_data.to_host(&stream);
    gpu_finalize_byte_trace(&stream, &mut preallocated_gpu_memory).unwrap();
    stream.synchronize().unwrap();

    let num_real_rows = num_events;
    let num_cols = NUM_SHA_COMPRESS_CONTROL_COLS;
    assert_eq!(
        cpu_trace_exact.values[..num_real_rows * num_cols],
        gpu_trace.values[..num_real_rows * num_cols],
        "ShaCompressControl GPU mismatch for 1st real event"
    );

    println!(
        "ShaCompressControl GPU correctness test passed for {} events!",
        num_events
    );
}

#[test]
fn bench_sha_compress_control_cpu_vs_gpu() {
    use crate::{
        chips::{
            precompiles::sha256::compress::ffi::ShaCompressFfiEvent, utils::next_power_of_two,
        },
        cuda_adaptor::resource_pool::mem_pool::get_global_mem_pool,
    };
    use cudart::{
        memory_pools::DevicePoolAllocation,
        slice::{CudaSlice, CudaSliceMut},
    };
    use cudart_sys::*;
    use p3_koala_bear::KoalaBear;
    use pico_gpu_api::cuda_precompile_sha256_compress_control_generate_extra_record_and_main;

    let chip = ShaCompressControlChip::<F>::default();

    let warmup_sizes: Vec<usize> = vec![1024];
    let bench_sizes: Vec<usize> = vec![1024, 4096, 16384, 65536];

    println!("\n{:-<60}", "");
    println!(
        "{:<12} {:>12} {:>12} {:>12}",
        "events", "cpu (ms)", "gpu (ms)", "speedup"
    );
    println!("{:-<60}", "");

    for (is_warmup, &num_events) in warmup_sizes
        .iter()
        .map(|n| (true, n))
        .chain(bench_sizes.iter().map(|n| (false, n)))
    {
        let original_record = generate_sha_compress_bench_record(num_events);

        // ── CPU ──
        let mut complete_record = original_record.clone();
        let cpu_start = Instant::now();
        chip.extra_record(&original_record, &mut complete_record);
        let cpu_trace = chip.generate_main(&complete_record, &mut EmulationRecord::default());
        let cpu_ms = cpu_start.elapsed().as_secs_f64() * 1000.0;

        // ── GPU (kernel only: exclude H2D and D2H) ──
        let stream = init_test_stream();
        let sync_mem_pool = get_global_mem_pool(0);
        let mem_pool = &sync_mem_pool.0;

        let mut counted_record = original_record.clone();
        let event_counter = precompute_event_size::<F>(&mut counted_record);
        let prepared_gpu_events = PreparedGpuEvents::new(&counted_record, event_counter);

        let events = &prepared_gpu_events.sha_compress_events;
        let event_size = events.len();
        let num_cols = NUM_SHA_COMPRESS_CONTROL_COLS;
        let num_total_rows = next_power_of_two(event_size, None);
        let trace_size = num_total_rows * num_cols;

        let event_alloc_size = if event_size == 0 { 1 } else { event_size };

        // Allocate GPU memory and do H2D transfer (NOT timed)
        let mut d_events = DevicePoolAllocation::<ShaCompressFfiEvent>::alloc_from_pool_async(
            event_alloc_size,
            mem_pool,
            stream,
        )
        .unwrap();
        if event_size > 0 {
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_events.as_mut_c_void_ptr(),
                    events.as_c_void_ptr(),
                    event_size * std::mem::size_of::<ShaCompressFfiEvent>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );
            }
        }
        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .unwrap();
        let mut d_byte_trace = gpu_allocate_byte_trace(stream, 0).unwrap().unwrap();

        stream.synchronize().unwrap();

        // Time only the kernel execution
        let gpu_start = Instant::now();
        unsafe {
            cuda_precompile_sha256_compress_control_generate_extra_record_and_main(
                d_events.as_ptr() as *const _,
                event_size,
                d_trace.as_mut_ptr() as *mut _,
                num_total_rows,
                num_cols,
                d_byte_trace.as_mut_ptr() as *mut _,
                stream.into(),
            );
        }
        stream.synchronize().unwrap();
        let gpu_ms = gpu_start.elapsed().as_secs_f64() * 1000.0;

        if is_warmup {
            println!(
                "{:<12} {:>12} {:>12} {:>12}",
                num_events, "warmup", "warmup", "—"
            );
            continue;
        }

        // ── Verify CPU == GPU (D2H + compare, not timed) ──
        let gpu_trace = TraceData::<F>::Gpu(num_cols, d_trace).to_host(stream);
        stream.synchronize().unwrap();

        let num_real_rows = num_events;
        assert_eq!(
            cpu_trace.values[..num_real_rows * num_cols],
            gpu_trace.values[..num_real_rows * num_cols],
            "Main trace mismatch at bench size {}",
            num_events
        );

        let speedup = cpu_ms / gpu_ms;
        println!(
            "{:<12} {:>12.2} {:>12.2} {:>11.1}x  ✓",
            num_events, cpu_ms, gpu_ms, speedup
        );
    }
    println!("{:-<60}", "");
}
