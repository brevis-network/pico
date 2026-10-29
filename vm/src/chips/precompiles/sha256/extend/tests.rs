use crate::emulator::riscv::{
    record::EmulationRecord,
    syscalls::{
        precompiles::{sha256::event::ShaExtendEvent, PrecompileEvent},
        SyscallCode, SyscallEvent,
    },
};
#[cfg(feature = "cuda")]
use crate::{
    chips::{
        chips::byte::{columns::NUM_BYTE_MULT_COLS, ByteChip},
        precompiles::sha256::extend::{
            columns::NUM_SHA_EXTEND_COLS, controller::NUM_SHA_EXTEND_CONTROL_COLS, ShaExtendChip,
            ShaExtendControlChip,
        },
        tests::init_test_stream,
        trace::TraceData,
    },
    instances::preparer::{
        gpu_allocate_byte_trace, gpu_finalize_byte_trace, precompute_event_size,
        PreallocatedGpuMemory, PreparedGpuEvents,
    },
    machine::chip::{ChipBehavior, GpuChipBehavior},
};
#[cfg(feature = "cuda")]
use p3_koala_bear::KoalaBear;
use rand::{rng, RngExt};
#[cfg(feature = "cuda")]
use std::time::Instant;

#[cfg(feature = "cuda")]
type Chip<F> = ShaExtendChip<F>;
#[cfg(feature = "cuda")]
type F = KoalaBear;

pub fn generate_sha_extend_bench_record(num_events: usize) -> EmulationRecord {
    let mut rng = rng();
    let mut events = Vec::with_capacity(num_events);

    for i in 0..num_events {
        let mut w_i_minus_15_reads = Vec::with_capacity(48);
        let mut w_i_minus_2_reads = Vec::with_capacity(48);
        let mut w_i_minus_16_reads = Vec::with_capacity(48);
        let mut w_i_minus_7_reads = Vec::with_capacity(48);
        let mut w_i_writes = Vec::with_capacity(48);

        for j in 0..48 {
            // `MemoryAccessCols::populate_access` asserts `timestamp - prev_timestamp - 1 < 2^25`
            // and every record here has `prev_timestamp: 0`, so the stride must keep the largest
            // timestamp under the budget for 2^16 events: 65535 * 500 + 479 < 2^25. One event's
            // 48 rows span `j * 10 + 5 <= 475 < 500`, so consecutive events never overlap.
            let ts_base = (i * 500 + j * 10) as u32;
            w_i_minus_15_reads.push(crate::chips::chips::riscv_memory::event::MemoryReadRecord {
                value: rng.random::<u32>() as u64,
                chunk: 1,
                timestamp: ts_base + 1,
                prev_chunk: 1,
                prev_timestamp: 0,
            });
            w_i_minus_2_reads.push(crate::chips::chips::riscv_memory::event::MemoryReadRecord {
                value: rng.random::<u32>() as u64,
                chunk: 1,
                timestamp: ts_base + 2,
                prev_chunk: 1,
                prev_timestamp: 0,
            });
            w_i_minus_16_reads.push(crate::chips::chips::riscv_memory::event::MemoryReadRecord {
                value: rng.random::<u32>() as u64,
                chunk: 1,
                timestamp: ts_base + 3,
                prev_chunk: 1,
                prev_timestamp: 0,
            });
            w_i_minus_7_reads.push(crate::chips::chips::riscv_memory::event::MemoryReadRecord {
                value: rng.random::<u32>() as u64,
                chunk: 1,
                timestamp: ts_base + 4,
                prev_chunk: 1,
                prev_timestamp: 0,
            });
            w_i_writes.push(
                crate::chips::chips::riscv_memory::event::MemoryWriteRecord {
                    value: rng.random::<u32>() as u64,
                    prev_value: 0,
                    chunk: 1,
                    timestamp: ts_base + 5,
                    prev_chunk: 1,
                    prev_timestamp: 0,
                },
            );
        }

        events.push(ShaExtendEvent {
            chunk: 1,
            clk: (i * 1000) as u64,
            w_ptr: 0x10000,
            w_i_minus_15_reads,
            w_i_minus_2_reads,
            w_i_minus_16_reads,
            w_i_minus_7_reads,
            w_i_writes,
            local_mem_access: vec![],
        });
    }

    let mut record = EmulationRecord::default();
    let pre_events: Vec<(SyscallEvent, PrecompileEvent)> = events
        .into_iter()
        .map(|e| (SyscallEvent::default(), PrecompileEvent::ShaExtend(e)))
        .collect();
    record
        .precompile_events
        .insert(SyscallCode::SHA_EXTEND, pre_events);
    record
}

#[cfg(feature = "cuda")]
#[test]
fn test_sha_extend_gpu_generate_extra_record_and_main() {
    let num_events = 1 << 16;
    let original_record = generate_sha_extend_bench_record(num_events);
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

    let num_real_rows = num_events * 48; // ShaExtend generates 48 rows per event
    let num_cols = NUM_SHA_EXTEND_COLS;
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
        "ShaExtend GPU correctness test passed for {} events!",
        num_events
    );
}

#[cfg(feature = "cuda")]
#[test]
fn bench_sha_extend_cpu_vs_gpu() {
    use crate::{
        chips::{precompiles::sha256::extend::ffi::ShaExtendFfiEvent, utils::next_power_of_two},
        cuda_adaptor::resource_pool::mem_pool::get_global_mem_pool,
    };
    use cudart::{memory_pools::DevicePoolAllocation, slice::CudaSliceMut};
    use cudart_sys::*;
    use p3_koala_bear::KoalaBear;
    use pico_gpu_api::cuda_precompile_sha256_extend_generate_extra_record_and_main;

    let chip = Chip::<F>::default();
    let byte_chip = ByteChip::<F>::default();

    let warmup_sizes: Vec<usize> = vec![1 << 12];
    let bench_sizes: Vec<usize> = vec![1 << 12, 1 << 14, 1 << 16];

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
        let original_record = generate_sha_extend_bench_record(num_events);

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

        let events = &prepared_gpu_events.sha_extend_events;
        let event_size = events.len();
        let num_cols = NUM_SHA_EXTEND_COLS;
        let num_total_rows = next_power_of_two(event_size * 48, None);
        let trace_size = num_total_rows * num_cols;

        let event_alloc_size = if event_size == 0 { 1 } else { event_size };

        // Allocate GPU memory and do H2D transfer (NOT timed)
        let mut d_events = DevicePoolAllocation::<ShaExtendFfiEvent>::alloc_from_pool_async(
            event_alloc_size,
            mem_pool,
            stream,
        )
        .unwrap();
        if event_size > 0 {
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_events.as_mut_c_void_ptr(),
                    events.as_ptr() as *const _,
                    event_size * std::mem::size_of::<ShaExtendFfiEvent>(),
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
            cuda_precompile_sha256_extend_generate_extra_record_and_main(
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

        let num_real_rows = num_events * 48;
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

#[cfg(feature = "cuda")]
#[test]
fn test_sha_extend_control_gpu_generate_extra_record_and_main() {
    let num_events = 1 << 16;
    let original_record = generate_sha_extend_bench_record(num_events);
    let chip = ShaExtendControlChip::<F>::default();

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

    let num_real_rows = num_events; // ShaExtendControl generates 1 row per event
    let num_cols = NUM_SHA_EXTEND_CONTROL_COLS;
    let cpu_vals = &cpu_trace.values[..num_real_rows * num_cols];
    let gpu_vals = &gpu_trace.values[..num_real_rows * num_cols];

    if cpu_vals != gpu_vals {
        for row in 0..num_real_rows {
            for col in 0..num_cols {
                let idx = row * num_cols + col;
                if cpu_vals[idx] != gpu_vals[idx] {
                    panic!(
                        "Control exact mismatch at row {}, col {}! CPU: {:?}, GPU: {:?}",
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
        "ShaExtendControl GPU correctness test passed for {} events!",
        num_events
    );
}

#[cfg(feature = "cuda")]
#[test]
fn bench_sha_extend_control_cpu_vs_gpu() {
    use crate::{
        chips::{precompiles::sha256::extend::ffi::ShaExtendFfiEvent, utils::next_power_of_two},
        cuda_adaptor::resource_pool::mem_pool::get_global_mem_pool,
    };
    use cudart::{memory_pools::DevicePoolAllocation, slice::CudaSliceMut};
    use cudart_sys::*;
    use p3_koala_bear::KoalaBear;
    use pico_gpu_api::cuda_precompile_sha256_extend_control_generate_extra_record_and_main;

    let chip = ShaExtendControlChip::<F>::default();
    let byte_chip = ByteChip::<F>::default();

    let warmup_sizes: Vec<usize> = vec![1 << 12];
    let bench_sizes: Vec<usize> = vec![1 << 12, 1 << 14, 1 << 16];

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
        let original_record = generate_sha_extend_bench_record(num_events);

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

        let events = &prepared_gpu_events.sha_extend_events;
        let event_size = events.len();
        let num_cols = NUM_SHA_EXTEND_CONTROL_COLS;
        let num_total_rows = next_power_of_two(event_size, None);
        let trace_size = num_total_rows * num_cols;

        let event_alloc_size = if event_size == 0 { 1 } else { event_size };

        // Allocate GPU memory and do H2D transfer (NOT timed)
        let mut d_events = DevicePoolAllocation::<ShaExtendFfiEvent>::alloc_from_pool_async(
            event_alloc_size,
            mem_pool,
            stream,
        )
        .unwrap();
        if event_size > 0 {
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_events.as_mut_c_void_ptr(),
                    events.as_ptr() as *const _,
                    event_size * std::mem::size_of::<ShaExtendFfiEvent>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );
            }
        }
        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .unwrap();
        let mut d_byte_trace = gpu_allocate_byte_trace(stream, 0).unwrap().unwrap();

        // Wait for all H2D transfers to complete
        stream.synchronize().unwrap();

        // Time only the kernel execution
        let gpu_start = Instant::now();
        unsafe {
            cuda_precompile_sha256_extend_control_generate_extra_record_and_main(
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
