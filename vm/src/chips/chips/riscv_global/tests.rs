#[cfg(feature = "cuda")]
use crate::{
    chips::{
        chips::{
            byte::{columns::NUM_BYTE_MULT_COLS, ByteChip},
            riscv_global::{columns::NUM_GLOBAL_COLS, event::GlobalInteractionEvent, GlobalChip},
        },
        tests::init_test_stream,
        trace::TraceData,
    },
    emulator::riscv::record::EmulationRecord,
    instances::{
        compiler::shapes::riscv_shape::RiscvPadShape,
        preparer::{
            gpu_allocate_and_copy_global_events, gpu_allocate_and_copy_poseidon2_events,
            gpu_allocate_byte_trace, gpu_finalize_byte_trace, precompute_event_size,
            verify_poseidon2_events, PreallocatedGpuMemory, PreparedGpuEvents,
        },
    },
    machine::{
        chip::{ChipBehavior, GpuChipBehavior},
        field::FieldSpecificPoseidon2Config,
    },
};
#[cfg(feature = "cuda")]
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
#[cfg(feature = "cuda")]
use p3_matrix::dense::RowMajorMatrix;
#[cfg(feature = "cuda")]
use rand::{rng, RngExt};
#[cfg(feature = "cuda")]
use std::{sync::LazyLock, time::Instant};

type F = KoalaBear;

#[cfg(feature = "cuda")]
static GPU_TEST_RECORD: LazyLock<EmulationRecord> =
    LazyLock::new(|| generate_gpu_test_record(1 << 20));

#[cfg(feature = "cuda")]
fn cpu_generate_main(chip: &GlobalChip<F>, input: &EmulationRecord) -> RowMajorMatrix<F> {
    chip.generate_main(input, &mut EmulationRecord::default())
}

#[cfg(feature = "cuda")]
fn generate_gpu_test_record(event_count: usize) -> EmulationRecord {
    let rng = &mut rng();

    let events: Vec<GlobalInteractionEvent> = (0..event_count)
        .map(|_| GlobalInteractionEvent {
            message: [
                rng.random::<u32>(),
                rng.random::<u32>(),
                rng.random::<u32>(),
                rng.random::<u32>(),
                rng.random::<u32>(),
                rng.random::<u32>(),
                rng.random::<u32>(),
                rng.random::<u16>() as u32,
            ],
            is_receive: rng.random_bool(0.5),
            kind: rng.random_range(0..64u8),
        })
        .collect();

    let mut record = EmulationRecord::default();
    record.global_lookup_events = events;
    record
}

#[cfg(feature = "cuda")]
fn setup_gpu_memory<'a>(
    stream: &'a cudart::stream::CudaStream,
    counted_record: &'a EmulationRecord,
    prepared_gpu_events: &'a PreparedGpuEvents,
) -> PreallocatedGpuMemory<'a> {
    PreallocatedGpuMemory {
        d_global_events: gpu_allocate_and_copy_global_events(
            stream,
            0,
            counted_record,
            prepared_gpu_events,
        )
        .unwrap(),
        d_poseidon2_events: gpu_allocate_and_copy_poseidon2_events(
            stream,
            0,
            &counted_record.poseidon2_events,
            prepared_gpu_events,
        )
        .unwrap(),
        d_byte_trace: gpu_allocate_byte_trace(stream, 0).unwrap(),
        ..Default::default()
    }
}

#[cfg(feature = "cuda")]
#[test]
fn test_riscv_global_gpu_generate_extra_record_and_main() {
    let original_record = LazyLock::force(&GPU_TEST_RECORD);

    let chip = GlobalChip::<F>::default();

    let mut complete_record = original_record.clone();
    chip.extra_record(original_record, &mut complete_record);
    let mut counted_record = original_record.clone();
    let event_counter = precompute_event_size::<F>(&mut counted_record);

    let n = original_record.global_lookup_events.len();
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
    let cpu_trace = cpu_generate_main(&chip, &complete_record);
    let byte_chip = ByteChip::<F>::default();
    let cpu_byte_trace = byte_chip.generate_main(&complete_record, &mut EmulationRecord::default());

    // GPU
    let stream = init_test_stream();
    let prepared_gpu_events = PreparedGpuEvents::new(&counted_record, event_counter.clone());
    let mut preallocated_gpu_memory =
        setup_gpu_memory(stream, &counted_record, &prepared_gpu_events);

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

    verify_poseidon2_events(
        &preallocated_gpu_memory.d_poseidon2_events,
        event_counter.num_poseidon2_events,
        &complete_record,
        stream,
    );

    gpu_finalize_byte_trace(stream, &mut preallocated_gpu_memory).unwrap();
    stream.synchronize().unwrap();

    let d_byte_trace = preallocated_gpu_memory.d_byte_trace.take().unwrap();
    let host_gpu_byte_trace = TraceData::<F>::Gpu(NUM_BYTE_MULT_COLS, d_byte_trace).to_host(stream);
    assert_eq!(host_gpu_byte_trace.values, cpu_byte_trace.values);

    let non_zero_byte = cpu_byte_trace
        .values
        .iter()
        .filter(|&&v| v != F::ZERO)
        .count();
    assert!(
        non_zero_byte > 0,
        "byte trace is all zeros — both CPU and GPU may be broken"
    );

    println!(
        "riscv_global: {} events, main trace non-zero: {}/{}, byte trace non-zero: {}/{}",
        n,
        non_zero_main,
        cpu_trace.values.len(),
        non_zero_byte,
        cpu_byte_trace.values.len(),
    );
}

#[cfg(feature = "cuda")]
#[test]
fn bench_riscv_global_cpu_vs_gpu() {
    let warmup_sizes: Vec<usize> = vec![1 << 16];
    let bench_sizes: Vec<usize> = vec![1 << 16, 1 << 18, 1 << 20, 1 << 22];

    println!("\n{:-<60}", "");
    println!(
        "{:<12} {:>12} {:>12} {:>12}",
        "events", "cpu (ms)", "gpu (ms)", "speedup"
    );
    println!("{:-<60}", "");

    let chip = GlobalChip::<F>::default();

    for (is_warmup, &n) in warmup_sizes
        .iter()
        .map(|n| (true, n))
        .chain(bench_sizes.iter().map(|n| (false, n)))
    {
        let original_record = generate_gpu_test_record(n);

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

        // GPU: allocate + H2D before timing
        let stream = init_test_stream();
        let prepared_gpu_events = PreparedGpuEvents::new(&counted_record, event_counter.clone());
        let mut preallocated_gpu_memory =
            setup_gpu_memory(stream, &counted_record, &prepared_gpu_events);

        let sync_mem_pool = crate::cuda_adaptor::resource_pool::mem_pool::get_global_mem_pool(0);
        let mem_pool = &sync_mem_pool.0;

        let event_size = prepared_gpu_events.event_counter.num_global_lookup_events;
        let padded_nrows = 1usize << log2;
        let trace_size = padded_nrows * NUM_GLOBAL_COLS;

        let mut d_trace =
            cudart::memory_pools::DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(
                trace_size, mem_pool, stream,
            )
            .unwrap();
        let rc_flat = KoalaBear::round_constants().flatten_for_gpu();
        let mut d_round_constants =
            cudart::memory_pools::DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(
                rc_flat.len(),
                mem_pool,
                stream,
            )
            .unwrap();
        unsafe {
            let _ = cudart_sys::cudaMemcpyAsync(
                d_round_constants.as_mut_ptr() as *mut _,
                rc_flat.as_ptr() as *const _,
                rc_flat.len() * size_of::<KoalaBear>(),
                cudart_sys::CudaMemoryCopyKind::HostToDevice,
                stream.into(),
            );
        }
        stream.synchronize().unwrap();

        // GPU timing (kernel only)
        let gpu_start = Instant::now();
        if event_size > 0 {
            unsafe {
                pico_gpu_api::cuda_riscv_global_generate_extra_record_and_main(
                    NUM_GLOBAL_COLS,
                    event_size,
                    trace_size,
                    preallocated_gpu_memory
                        .d_global_events
                        .as_mut()
                        .unwrap()
                        .as_mut_ptr() as *mut _,
                    d_trace.as_mut_ptr() as *mut _,
                    stream.into(),
                    preallocated_gpu_memory
                        .d_byte_trace
                        .as_mut()
                        .unwrap()
                        .as_mut_ptr() as *mut _,
                    preallocated_gpu_memory
                        .d_poseidon2_events
                        .as_mut()
                        .unwrap()
                        .as_mut_ptr() as *mut _,
                    prepared_gpu_events
                        .event_counter
                        .start_indices
                        .global_extra_poseidon2_start_index,
                    d_round_constants.as_ptr() as *const _,
                );
            }
        }
        stream.synchronize().unwrap();
        let gpu_ms = gpu_start.elapsed().as_secs_f64() * 1000.0;

        if is_warmup {
            println!("{:<12} {:>12} {:>12} {:>12}", n, "warmup", "warmup", "—");
            continue;
        }

        // Verify CPU == GPU (D2H + compare, not timed)
        let gpu_trace = TraceData::<F>::Gpu(NUM_GLOBAL_COLS, d_trace).to_host(stream);
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

/// Pins the zerocheck rule count of `GcsBindAir`: one rule per DAG node reachable from the
/// constraint roots. A different septic expression shape changes this number.
#[test]
fn gcs_bind_reachable_rule_count() {
    use crate::{
        chips::tests::reachable_constraint_nodes,
        mle::machine::air::{GcsBindAir, GCS_DIGEST_LEN},
        primitives::consts::MAX_NUM_PVS,
    };
    use p3_air::BaseAir;
    use pico_mle_core::{
        air::symbolic::{get_symbolic_builder_with_public_values, SymbolicConstraintsDag},
        keygen::types::TraceWidth,
    };

    let width = TraceWidth {
        preprocessed: None,
        cached_mains: vec![],
        common_main: BaseAir::<F>::width(&GcsBindAir::<F>::default()),
    };
    let builder = get_symbolic_builder_with_public_values::<F, _>(
        &GcsBindAir::<F>::default(),
        &width,
        GCS_DIGEST_LEN + MAX_NUM_PVS,
    );
    let constraints = builder.constraints();
    // The degree fixes the round-0 zerocheck coset count and the interaction count fixes the
    // LogUp side; neither is reachable from the constraint roots, so the rule count below would
    // not notice a change in either.
    assert_eq!(constraints.max_constraint_degree(), 3);
    assert_eq!(constraints.interactions.len(), 8);
    let dag: SymbolicConstraintsDag<F> = constraints.into();
    assert_eq!(reachable_constraint_nodes(&dag.constraints), 836);
}
