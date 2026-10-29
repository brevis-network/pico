use crate::{
    chips::chips::syscall::SyscallChunkKind,
    emulator::riscv::{record::EmulationRecord, syscalls::SyscallEvent},
    machine::chip::ChipBehavior,
};
#[cfg(feature = "cuda")]
use crate::{
    chips::{
        chips::syscall::{SyscallChip, NUM_SYSCALL_COLS},
        tests::init_test_stream,
        trace::TraceData,
    },
    cuda_adaptor::resource_pool::mem_pool::get_global_mem_pool,
    instances::{
        compiler::shapes::riscv_shape::RiscvPadShape,
        preparer::{
            gpu_allocate_and_copy_global_events, gpu_allocate_byte_trace, precompute_event_size,
            verify_global_events, PreallocatedGpuMemory, PreparedGpuEvents,
        },
    },
    machine::chip::GpuChipBehavior,
};
#[cfg(feature = "cuda")]
use cudart::{memory_pools::DevicePoolAllocation, slice::CudaSliceMut};
#[cfg(feature = "cuda")]
use cudart_sys::*;
#[cfg(feature = "cuda")]
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
#[cfg(feature = "cuda")]
use p3_matrix::dense::RowMajorMatrix;
#[cfg(feature = "cuda")]
use pico_gpu_api::cuda_syscall_generate_extra_record_and_main_u64;
#[cfg(feature = "cuda")]
use rand::{rng, RngExt};
#[cfg(feature = "cuda")]
use std::{sync::LazyLock, time::Instant};

#[cfg(feature = "cuda")]
type F = KoalaBear;

#[cfg(feature = "cuda")]
static GPU_TEST_RECORD: LazyLock<EmulationRecord> =
    LazyLock::new(|| generate_gpu_test_record(1 << 20));

#[cfg(feature = "cuda")]
fn cpu_generate_main(chip: &SyscallChip<F>, input: &EmulationRecord) -> RowMajorMatrix<F> {
    chip.generate_main(input, &mut EmulationRecord::default())
}

#[cfg(feature = "cuda")]
fn generate_gpu_test_record(event_count: usize) -> EmulationRecord {
    let rng = &mut rng();
    let events: Vec<SyscallEvent> = (0..event_count)
        .map(|i| SyscallEvent {
            chunk: 0,
            clk: (i as u64) + 1,
            syscall_id: rng.random_range(1..100u32),
            arg1: rng.random::<u64>() & 0xFFFF_FFFF_FFFF, // 48-bit
            arg2: rng.random::<u64>() & 0xFFFF_FFFF_FFFF, // 48-bit
        })
        .collect();

    let mut record = EmulationRecord::default();
    record.syscall_events = events;
    record
}

#[cfg(feature = "cuda")]
#[test]
fn test_syscall_gpu_generate_extra_record_and_main() {
    let original_record = LazyLock::force(&GPU_TEST_RECORD);

    let chip = SyscallChip::<F>::new(SyscallChunkKind::Riscv);

    let mut complete_record = original_record.clone();
    chip.extra_record(original_record, &mut complete_record);
    let mut counted_record = original_record.clone();
    let event_counter = precompute_event_size::<F>(&mut counted_record);

    let n = original_record.syscall_events.len();
    let log2 = (n as f64).log2().ceil() as usize + 1;
    complete_record.shape = Some(RiscvPadShape::default());
    complete_record
        .shape
        .as_mut()
        .unwrap()
        .inner
        .insert(chip.name(), log2);
    counted_record.shape = Some(RiscvPadShape::default());
    counted_record
        .shape
        .as_mut()
        .unwrap()
        .inner
        .insert(chip.name(), log2);

    let cpu_trace = cpu_generate_main(&chip, &complete_record);

    let stream = init_test_stream();
    let prepared_gpu_events = PreparedGpuEvents::new(&counted_record, event_counter.clone());
    let mut preallocated_gpu_memory = PreallocatedGpuMemory {
        d_global_events: gpu_allocate_and_copy_global_events(
            stream,
            0,
            &counted_record,
            &prepared_gpu_events,
        )
        .unwrap(),
        // The chip's byte lookups land in the shared byte trace, which the kernel unwraps.
        d_byte_trace: gpu_allocate_byte_trace(stream, 0).unwrap(),
        ..Default::default()
    };

    let gpu_trace_data = chip.gpu_generate_extra_record_and_main(
        0,
        &counted_record,
        &prepared_gpu_events,
        &mut preallocated_gpu_memory,
    );
    let gpu_trace = gpu_trace_data.to_host(stream);
    assert_eq!(cpu_trace, gpu_trace);

    let non_zero_main = cpu_trace.values.iter().filter(|&&v| v != F::ZERO).count();
    assert!(
        non_zero_main > 0,
        "main trace is all zeros — both CPU and GPU may be broken"
    );

    verify_global_events(
        &preallocated_gpu_memory.d_global_events,
        &complete_record,
        stream,
        event_counter
            .start_indices
            .syscall_riscv_extra_global_lookup_start_index,
        event_counter.num_global_lookup_events,
    );

    println!(
        "syscall: {} events, main trace non-zero: {}/{}",
        n,
        non_zero_main,
        cpu_trace.values.len(),
    );
}

#[cfg(feature = "cuda")]
#[test]
fn bench_syscall_cpu_vs_gpu() {
    let warmup_sizes: Vec<usize> = vec![1 << 16];
    let bench_sizes: Vec<usize> = vec![1 << 16, 1 << 18, 1 << 20, 1 << 22];

    println!("\n{:-<60}", "");
    println!(
        "{:<12} {:>12} {:>12} {:>12}",
        "events", "cpu (ms)", "gpu (ms)", "speedup"
    );
    println!("{:-<60}", "");

    for (is_warmup, &n) in warmup_sizes
        .iter()
        .map(|n| (true, n))
        .chain(bench_sizes.iter().map(|n| (false, n)))
    {
        let original_record = generate_gpu_test_record(n);
        let chip = SyscallChip::<F>::new(SyscallChunkKind::Riscv);

        let mut complete_record = original_record.clone();
        chip.extra_record(&original_record, &mut complete_record);
        let mut counted_record = original_record.clone();
        let event_counter = precompute_event_size::<F>(&mut counted_record);

        let log2 = (n as f64).log2().ceil() as usize + 1;
        complete_record.shape = Some(RiscvPadShape::default());
        complete_record
            .shape
            .as_mut()
            .unwrap()
            .inner
            .insert(chip.name(), log2);
        counted_record.shape = Some(RiscvPadShape::default());
        counted_record
            .shape
            .as_mut()
            .unwrap()
            .inner
            .insert(chip.name(), log2);

        // CPU
        let cpu_start = Instant::now();
        let cpu_trace = cpu_generate_main(&chip, &complete_record);
        let cpu_ms = cpu_start.elapsed().as_secs_f64() * 1000.0;

        // GPU (kernel only: exclude H2D)
        let stream = init_test_stream();
        let prepared_gpu_events = PreparedGpuEvents::new(&counted_record, event_counter.clone());
        let sync_mem_pool = get_global_mem_pool(0);
        let mem_pool = &sync_mem_pool.0;

        let events = &counted_record.syscall_events;
        let event_size = events.len();
        let padded_nrows = 1 << log2;
        let trace_size = padded_nrows * NUM_SYSCALL_COLS;

        let mut d_events = DevicePoolAllocation::<SyscallEvent>::alloc_from_pool_async(
            event_size, mem_pool, stream,
        )
        .unwrap();
        unsafe {
            let _ = cudaMemcpyAsync(
                d_events.as_mut_c_void_ptr(),
                events.as_ptr() as *const _,
                event_size * size_of::<SyscallEvent>(),
                CudaMemoryCopyKind::HostToDevice,
                stream.into(),
            );
        }
        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .unwrap();
        unsafe {
            let _ = cudaMemsetAsync(
                d_trace.as_mut_ptr() as *mut _,
                0,
                trace_size * size_of::<KoalaBear>(),
                stream.into(),
            );
        }
        let mut d_global_events_alloc =
            gpu_allocate_and_copy_global_events(stream, 0, &counted_record, &prepared_gpu_events)
                .unwrap()
                .unwrap();
        stream.synchronize().unwrap();

        let start_index = prepared_gpu_events
            .event_counter
            .start_indices
            .syscall_riscv_extra_global_lookup_start_index;

        let gpu_start = Instant::now();
        unsafe {
            cuda_syscall_generate_extra_record_and_main_u64(
                NUM_SYSCALL_COLS,
                event_size,
                trace_size,
                d_events.as_ptr() as *const _,
                d_trace.as_mut_ptr() as *mut _,
                stream.into(),
                d_global_events_alloc.as_mut_ptr() as *mut _,
                start_index,
                SyscallChunkKind::Riscv as u8,
                std::ptr::null_mut(),
            );
        }
        stream.synchronize().unwrap();
        let gpu_ms = gpu_start.elapsed().as_secs_f64() * 1000.0;

        if is_warmup {
            println!("{:<12} {:>12} {:>12} {:>12}", n, "warmup", "warmup", "—");
            continue;
        }

        let gpu_trace = TraceData::<F>::Gpu(NUM_SYSCALL_COLS, d_trace).to_host(stream);
        assert_eq!(
            cpu_trace.values, gpu_trace.values,
            "CPU/GPU main trace mismatch at n={}",
            n
        );

        let speedup = cpu_ms / gpu_ms;
        println!(
            "{:<12} {:>12.2} {:>12.2} {:>11.1}x  ✓",
            n, cpu_ms, gpu_ms, speedup
        );
    }
    println!("{:-<60}", "");
}

#[test]
#[should_panic(expected = "frozen 48-bit proof address contract")]
fn syscall_extra_record_rejects_arg1_above_48_bits() {
    let chip = crate::chips::chips::syscall::SyscallChip::<KoalaBear>::new(SyscallChunkKind::Riscv);
    let mut record = EmulationRecord::default();
    let mut complete_record = EmulationRecord::default();
    record.syscall_events.push(SyscallEvent {
        chunk: 0,
        clk: 1,
        syscall_id: 7,
        arg1: 1u64 << 48,
        arg2: 0,
    });

    chip.extra_record(&record, &mut complete_record);
}

#[test]
#[should_panic(expected = "frozen 48-bit proof address contract")]
fn syscall_extra_record_rejects_arg2_above_48_bits() {
    let chip = crate::chips::chips::syscall::SyscallChip::<KoalaBear>::new(SyscallChunkKind::Riscv);
    let mut record = EmulationRecord::default();
    let mut complete_record = EmulationRecord::default();
    record.syscall_events.push(SyscallEvent {
        chunk: 0,
        clk: 1,
        syscall_id: 7,
        arg1: 0,
        arg2: 1u64 << 48,
    });

    chip.extra_record(&record, &mut complete_record);
}
