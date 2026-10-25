use std::marker::PhantomData;

pub mod columns;
pub mod constraints;
pub mod traces;

/// The type of memory chip that is being initialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryChipType {
    Initialize,
    Finalize,
}

/// A memory chip that can initialize or finalize values in memory.
pub struct MemoryInitializeFinalizeChip<F> {
    pub kind: MemoryChipType,
    _phantom: PhantomData<F>,
}

impl<F> MemoryInitializeFinalizeChip<F> {
    /// Creates a new memory chip with a certain type.
    pub const fn new(kind: MemoryChipType) -> Self {
        Self {
            kind,
            _phantom: PhantomData,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::columns::NUM_MEMORY_INITIALIZE_FINALIZE_COLS;
    use crate::{
        chips::{
            chips::{
                events::MemoryInitializeFinalizeEvent,
                riscv_memory::initialize_finalize::{MemoryChipType, MemoryInitializeFinalizeChip},
            },
            tests::init_test_stream,
            trace::TraceData,
            utils::next_power_of_two,
        },
        cuda_adaptor::resource_pool::mem_pool::get_global_mem_pool,
        emulator::riscv::{public_values::PublicValues, record::EmulationRecord},
        instances::{
            compiler::shapes::riscv_shape::RiscvPadShape,
            preparer::{
                gpu_allocate_and_copy_global_events, gpu_allocate_byte_trace,
                gpu_finalize_byte_trace, precompute_event_size, verify_global_events,
                PreallocatedGpuMemory, PreparedGpuEvents,
            },
        },
        machine::chip::ChipBehavior,
    };
    use cudart::memory_pools::DevicePoolAllocation;
    use cudart_sys::{cudaMemcpyAsync, CudaMemoryCopyKind};
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;
    use p3_matrix::dense::RowMajorMatrix;
    use pico_gpu_api::cuda_memory_initialize_finalize_generate_extra_record_and_main_u64;
    use rand::{rng, RngExt};
    use std::{mem::size_of, sync::LazyLock, time::Instant};

    type F = KoalaBear;

    static SHARD: LazyLock<EmulationRecord> = LazyLock::new(|| generate_record(1 << 16));

    fn generate_record(size: usize) -> EmulationRecord {
        let mut rng = rng();
        let size = size as u64;
        let memory_initialize_events = (0..size)
            .map(|i| {
                let addr = i + 1;
                let value: u64 = rng.random();
                let chunk = 0u32;
                let timestamp = 0u32;
                let used = 0u32;
                MemoryInitializeFinalizeEvent {
                    addr,
                    value,
                    chunk,
                    timestamp,
                    used,
                }
            })
            .collect();
        let memory_finalize_events = (0..size)
            .map(|i| {
                let addr = i + 1;
                let value: u64 = rng.random();
                let chunk = 0u32;
                let timestamp = size as u32;
                let used = 1u32;
                MemoryInitializeFinalizeEvent {
                    addr,
                    value,
                    chunk,
                    timestamp,
                    used,
                }
            })
            .collect();

        let mut record = EmulationRecord::default();
        record.memory_initialize_events = memory_initialize_events;
        record.memory_finalize_events = memory_finalize_events;
        record.public_values = PublicValues {
            previous_init_addr_limbs: [0; 3],
            previous_finalize_addr_limbs: [0; 3],
            ..Default::default()
        };

        record
    }

    fn cpu_generate_main(
        chip: &MemoryInitializeFinalizeChip<F>,
        input: &EmulationRecord,
    ) -> RowMajorMatrix<F> {
        chip.generate_main(input, &mut EmulationRecord::default())
    }

    fn gpu_generate_extra_record_and_main(
        chip: &MemoryInitializeFinalizeChip<F>,
        input: &EmulationRecord,
        prepared_gpu_events: &PreparedGpuEvents,
        preallocated_gpu_memory: &mut PreallocatedGpuMemory,
    ) -> RowMajorMatrix<F> {
        let stream = init_test_stream();

        let trace = chip.gpu_generate_extra_record_and_main(
            0,
            input,
            &prepared_gpu_events,
            preallocated_gpu_memory,
        );
        trace.to_host(stream)
    }

    #[test]
    fn test_memory_init_finalize_gpu_generate_extra_record_and_main() {
        let original_record = LazyLock::force(&SHARD).clone();

        let mem_initialize_chip = MemoryInitializeFinalizeChip::new(MemoryChipType::Initialize);
        let mem_finalize_chip = MemoryInitializeFinalizeChip::new(MemoryChipType::Finalize);

        let mut complete_record = original_record.clone();
        mem_initialize_chip.extra_record(&original_record, &mut complete_record);
        mem_finalize_chip.extra_record(&original_record, &mut complete_record);

        complete_record.shape = Some(RiscvPadShape::default());
        complete_record
            .shape
            .as_mut()
            .unwrap()
            .inner
            .insert(mem_initialize_chip.name(), 17);
        complete_record
            .shape
            .as_mut()
            .unwrap()
            .inner
            .insert(mem_finalize_chip.name(), 17);

        let cpu_initialize_trace = cpu_generate_main(&mem_initialize_chip, &complete_record);
        let cpu_finalize_trace = cpu_generate_main(&mem_finalize_chip, &complete_record);

        let mut counted_record = original_record.clone();
        let mut event_counter = precompute_event_size::<F>(&mut counted_record);
        event_counter.num_poseidon2_events = complete_record.poseidon2_events.len();

        counted_record.shape = Some(RiscvPadShape::default());
        counted_record
            .shape
            .as_mut()
            .unwrap()
            .inner
            .insert(mem_initialize_chip.name(), 17);
        counted_record
            .shape
            .as_mut()
            .unwrap()
            .inner
            .insert(mem_finalize_chip.name(), 17);

        let stream = init_test_stream();
        let prepared_gpu_events = PreparedGpuEvents::new(&counted_record, event_counter.clone());

        let mut preallocated_gpu_memory = PreallocatedGpuMemory {
            d_global_events: gpu_allocate_and_copy_global_events(
                &stream,
                0,
                &counted_record,
                &prepared_gpu_events,
            )
            .unwrap(),
            d_byte_trace: gpu_allocate_byte_trace(&stream, 0).unwrap(),
            ..Default::default()
        };

        let gpu_initialize_trace = gpu_generate_extra_record_and_main(
            &mem_initialize_chip,
            &counted_record,
            &prepared_gpu_events,
            &mut preallocated_gpu_memory,
        );
        let gpu_finalize_trace = gpu_generate_extra_record_and_main(
            &mem_finalize_chip,
            &counted_record,
            &prepared_gpu_events,
            &mut preallocated_gpu_memory,
        );

        gpu_finalize_byte_trace(&stream, &mut preallocated_gpu_memory).unwrap();
        stream.synchronize().unwrap();

        event_counter.assert_event_counts_match(&complete_record);

        assert!(
            !cpu_initialize_trace.values.is_empty(),
            "CPU initialize trace should not be empty"
        );
        assert!(
            cpu_initialize_trace.values.iter().any(|v| *v != F::ZERO),
            "CPU initialize trace should not be all zeros"
        );
        assert!(
            !cpu_finalize_trace.values.is_empty(),
            "CPU finalize trace should not be empty"
        );
        assert!(
            cpu_finalize_trace.values.iter().any(|v| *v != F::ZERO),
            "CPU finalize trace should not be all zeros"
        );

        assert_eq!(
            cpu_initialize_trace, gpu_initialize_trace,
            "Initialize traces do not match"
        );
        assert_eq!(
            cpu_finalize_trace, gpu_finalize_trace,
            "Finalize traces do not match"
        );

        verify_global_events(
            &preallocated_gpu_memory.d_global_events,
            &complete_record,
            &stream,
            event_counter
                .start_indices
                .memory_initialize_extra_global_start_index,
            event_counter.num_global_lookup_events,
        );
    }

    #[test]
    fn bench_memory_init_finalize_cpu_vs_gpu() {
        let warmup_sizes: Vec<usize> = vec![1 << 16];
        let bench_sizes: Vec<usize> = vec![1 << 16, 1 << 18, 1 << 20, 1 << 22];

        println!("\n--- MemoryInitialize ---");
        println!("{:-<60}", "");
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
            let original_record = generate_record(n);
            let chip = MemoryInitializeFinalizeChip::<F>::new(MemoryChipType::Initialize);

            let mut complete_record = original_record.clone();
            chip.extra_record(&original_record, &mut complete_record);
            let mut counted_record = original_record.clone();
            let mut event_counter = precompute_event_size::<F>(&mut counted_record);
            event_counter.num_poseidon2_events = complete_record.poseidon2_events.len();

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

            let cpu_start = Instant::now();
            let cpu_trace = cpu_generate_main(&chip, &complete_record);
            let cpu_ms = cpu_start.elapsed().as_secs_f64() * 1000.0;

            // GPU: alloc + H2D before timer (kernel-only timing, apple-to-apple with CPU)
            let stream = init_test_stream();
            let prepared_gpu_events =
                PreparedGpuEvents::new(&counted_record, event_counter.clone());
            let sync_mem_pool = get_global_mem_pool(0);
            let mem_pool = &sync_mem_pool.0;
            let mut preallocated_gpu_memory = PreallocatedGpuMemory {
                d_global_events: gpu_allocate_and_copy_global_events(
                    &stream,
                    0,
                    &counted_record,
                    &prepared_gpu_events,
                )
                .unwrap(),
                d_byte_trace: gpu_allocate_byte_trace(&stream, 0).unwrap(),
                ..Default::default()
            };
            stream.synchronize().unwrap();

            let memory_events = &counted_record.memory_initialize_events;
            let nrows = memory_events.len();
            let padded_nrows = next_power_of_two(nrows, Some(log2));
            let event_size = memory_events.len();
            let trace_size = padded_nrows * NUM_MEMORY_INITIALIZE_FINALIZE_COLS;
            let previous_addr_limbs: [u32; 3] =
                counted_record.public_values.previous_init_addr_limbs;

            let mut d_events =
                DevicePoolAllocation::<MemoryInitializeFinalizeEvent>::alloc_from_pool_async(
                    event_size, mem_pool, &stream,
                )
                .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_events.as_mut_ptr() as *mut std::ffi::c_void,
                    memory_events.as_ptr() as *const std::ffi::c_void,
                    event_size * size_of::<MemoryInitializeFinalizeEvent>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );
            }
            let mut d_previous_addr_limbs =
                DevicePoolAllocation::<u32>::alloc_from_pool_async(3, mem_pool, &stream).unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_previous_addr_limbs.as_mut_ptr() as *mut std::ffi::c_void,
                    previous_addr_limbs.as_ptr() as *const std::ffi::c_void,
                    3 * size_of::<u32>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );
            }
            let mut d_trace = DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(
                trace_size, mem_pool, &stream,
            )
            .unwrap();
            stream.synchronize().unwrap();

            let gpu_start = Instant::now();
            let d_global_events = preallocated_gpu_memory.d_global_events.as_mut().unwrap();
            let d_byte_trace = preallocated_gpu_memory.d_byte_trace.as_mut().unwrap();
            let start_index = prepared_gpu_events
                .event_counter
                .start_indices
                .memory_initialize_extra_global_start_index;
            unsafe {
                cuda_memory_initialize_finalize_generate_extra_record_and_main_u64(
                    NUM_MEMORY_INITIALIZE_FINALIZE_COLS,
                    event_size,
                    trace_size,
                    d_events.as_ptr() as *const _,
                    d_previous_addr_limbs.as_ptr() as *const _,
                    d_trace.as_mut_ptr() as *mut _,
                    d_global_events.as_mut_ptr() as *mut _,
                    start_index,
                    false, // is_receive
                    d_byte_trace.as_mut_ptr() as *mut _,
                    stream.into(),
                );
            }
            stream.synchronize().unwrap();
            let gpu_ms = gpu_start.elapsed().as_secs_f64() * 1000.0;

            if is_warmup {
                println!("{:<12} {:>12} {:>12} {:>12}", n, "warmup", "warmup", "—");
                continue;
            }

            let gpu_trace =
                TraceData::<F>::Gpu(NUM_MEMORY_INITIALIZE_FINALIZE_COLS, d_trace).to_host(&stream);
            assert_eq!(
                cpu_trace.values, gpu_trace.values,
                "CPU/GPU Initialize trace mismatch at n={}",
                n
            );

            let speedup = cpu_ms / gpu_ms;
            println!(
                "{:<12} {:>12.2} {:>12.2} {:>11.1}x  ✓",
                n, cpu_ms, gpu_ms, speedup
            );
        }
        println!("{:-<60}", "");

        println!("\n--- MemoryFinalize ---");
        println!("{:-<60}", "");
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
            let original_record = generate_record(n);
            let chip = MemoryInitializeFinalizeChip::<F>::new(MemoryChipType::Finalize);

            let mut complete_record = original_record.clone();
            chip.extra_record(&original_record, &mut complete_record);
            let mut counted_record = original_record.clone();
            let mut event_counter = precompute_event_size::<F>(&mut counted_record);
            event_counter.num_poseidon2_events = complete_record.poseidon2_events.len();

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

            let cpu_start = Instant::now();
            let cpu_trace = cpu_generate_main(&chip, &complete_record);
            let cpu_ms = cpu_start.elapsed().as_secs_f64() * 1000.0;

            // GPU: alloc + H2D before timer (kernel-only timing, apple-to-apple with CPU)
            let stream = init_test_stream();
            let prepared_gpu_events =
                PreparedGpuEvents::new(&counted_record, event_counter.clone());
            let sync_mem_pool = get_global_mem_pool(0);
            let mem_pool = &sync_mem_pool.0;
            let mut preallocated_gpu_memory = PreallocatedGpuMemory {
                d_global_events: gpu_allocate_and_copy_global_events(
                    &stream,
                    0,
                    &counted_record,
                    &prepared_gpu_events,
                )
                .unwrap(),
                d_byte_trace: gpu_allocate_byte_trace(&stream, 0).unwrap(),
                ..Default::default()
            };
            stream.synchronize().unwrap();

            let memory_events = &counted_record.memory_finalize_events;
            let nrows = memory_events.len();
            let padded_nrows = next_power_of_two(nrows, Some(log2));
            let event_size = memory_events.len();
            let trace_size = padded_nrows * NUM_MEMORY_INITIALIZE_FINALIZE_COLS;
            let previous_addr_limbs: [u32; 3] =
                counted_record.public_values.previous_finalize_addr_limbs;

            let mut d_events =
                DevicePoolAllocation::<MemoryInitializeFinalizeEvent>::alloc_from_pool_async(
                    event_size, mem_pool, &stream,
                )
                .unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_events.as_mut_ptr() as *mut std::ffi::c_void,
                    memory_events.as_ptr() as *const std::ffi::c_void,
                    event_size * size_of::<MemoryInitializeFinalizeEvent>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );
            }
            let mut d_previous_addr_limbs =
                DevicePoolAllocation::<u32>::alloc_from_pool_async(3, mem_pool, &stream).unwrap();
            unsafe {
                let _ = cudaMemcpyAsync(
                    d_previous_addr_limbs.as_mut_ptr() as *mut std::ffi::c_void,
                    previous_addr_limbs.as_ptr() as *const std::ffi::c_void,
                    3 * size_of::<u32>(),
                    CudaMemoryCopyKind::HostToDevice,
                    stream.into(),
                );
            }
            let mut d_trace = DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(
                trace_size, mem_pool, &stream,
            )
            .unwrap();
            stream.synchronize().unwrap();

            let gpu_start = Instant::now();
            let d_global_events = preallocated_gpu_memory.d_global_events.as_mut().unwrap();
            let d_byte_trace = preallocated_gpu_memory.d_byte_trace.as_mut().unwrap();
            let start_index = prepared_gpu_events
                .event_counter
                .start_indices
                .memory_finalize_extra_global_start_index;
            unsafe {
                cuda_memory_initialize_finalize_generate_extra_record_and_main_u64(
                    NUM_MEMORY_INITIALIZE_FINALIZE_COLS,
                    event_size,
                    trace_size,
                    d_events.as_ptr() as *const _,
                    d_previous_addr_limbs.as_ptr() as *const _,
                    d_trace.as_mut_ptr() as *mut _,
                    d_global_events.as_mut_ptr() as *mut _,
                    start_index,
                    true, // is_receive
                    d_byte_trace.as_mut_ptr() as *mut _,
                    stream.into(),
                );
            }
            stream.synchronize().unwrap();
            let gpu_ms = gpu_start.elapsed().as_secs_f64() * 1000.0;

            if is_warmup {
                println!("{:<12} {:>12} {:>12} {:>12}", n, "warmup", "warmup", "—");
                continue;
            }

            let gpu_trace =
                TraceData::<F>::Gpu(NUM_MEMORY_INITIALIZE_FINALIZE_COLS, d_trace).to_host(&stream);
            assert_eq!(
                cpu_trace.values, gpu_trace.values,
                "CPU/GPU Finalize trace mismatch at n={}",
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
}
