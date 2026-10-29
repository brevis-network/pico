#[cfg(feature = "cuda")]
use super::{
    columns::{
        RISCV_NUM_POSEIDON2_COLS, RISCV_NUM_POSEIDON2_VALUE_COLS, RISCV_POSEIDON2_NUM_INPUTS,
    },
    dummy_row::RISCV_DUMMY_ROW_KB,
    Poseidon2ChipP3,
};
#[cfg(feature = "cuda")]
use crate::{
    chips::{chips::riscv_poseidon2::Poseidon2Event, tests::init_test_stream, trace::TraceData},
    cuda_adaptor::resource_pool::mem_pool::get_global_mem_pool,
    emulator::riscv::{
        cpu_event_pool::{init_cpu_event_buffer_pool, is_pool_initialized},
        event_pool::HostAllocFlags,
        record::EmulationRecord,
    },
    machine::{
        chip::{ChipBehavior, GpuChipBehavior},
        field::FieldSpecificPoseidon2Config,
    },
    primitives::consts::{KoalaBearConfig, PERMUTATION_WIDTH},
};
#[cfg(feature = "cuda")]
use cudart::{
    memory_pools::DevicePoolAllocation,
    slice::{CudaSlice, CudaSliceMut},
};
#[cfg(feature = "cuda")]
use cudart_sys::*;
#[cfg(feature = "cuda")]
use p3_field::{PrimeCharacteristicRing, PrimeField32};
#[cfg(feature = "cuda")]
use p3_koala_bear::KoalaBear;
#[cfg(feature = "cuda")]
use p3_matrix::dense::RowMajorMatrix;
#[cfg(feature = "cuda")]
use p3_symmetric::Permutation;
#[cfg(feature = "cuda")]
use pico_gpu_api::cuda_riscv_poseidon2_generate_main;
#[cfg(feature = "cuda")]
use rand::{rng, RngExt};
#[cfg(feature = "cuda")]
use std::{sync::LazyLock, time::Instant};

#[cfg(feature = "cuda")]
type F = KoalaBear;
#[cfg(feature = "cuda")]
type LinearLayers = <F as FieldSpecificPoseidon2Config>::RiscvLinearLayers;
#[cfg(feature = "cuda")]
type Config = KoalaBearConfig;

#[cfg(feature = "cuda")]
// Not a multiple of the 4-slot row: the last real row carries dummy slots and the trace is padded
// with dummy rows, so `RISCV_DUMMY_ROW_KB` / `pad_dummy_rows_kernel` are exercised too.
static SHARD: LazyLock<EmulationRecord> = LazyLock::new(|| make_shard((1 << 10) + 3));

#[cfg(feature = "cuda")]
fn cpu_generate_main(
    chip: &Poseidon2ChipP3<F, LinearLayers, Config>,
    input: &EmulationRecord,
) -> RowMajorMatrix<F> {
    chip.generate_main(input, &mut EmulationRecord::default())
}

#[cfg(feature = "cuda")]
fn gpu_generate_main(
    chip: &Poseidon2ChipP3<F, LinearLayers, Config>,
    input: &EmulationRecord,
) -> RowMajorMatrix<F> {
    let stream = init_test_stream();
    let trace = chip.gpu_generate_main(0, input, &mut EmulationRecord::default());
    trace.to_host(stream)
}

#[cfg(feature = "cuda")]
fn make_shard(num_iters: usize) -> EmulationRecord {
    if !is_pool_initialized() {
        init_cpu_event_buffer_pool(50, HostAllocFlags::DEFAULT);
    }

    let mut rec = EmulationRecord::default();
    let perm = KoalaBear::permutation();
    let mut rng = rng();

    for _ in 0..num_iters {
        // Rate-8 sponge input: the riscv chip's only producer (the Global chip's hash-to-curve)
        // feeds lanes 8..16 as zero, and the AIR treats them as constants -- so the fixture must
        // do the same (`populate_perm_riscv` asserts it).
        let input_f: [F; PERMUTATION_WIDTH] = std::array::from_fn(|i| {
            if i < RISCV_POSEIDON2_NUM_INPUTS {
                rng.random::<F>()
            } else {
                F::ZERO
            }
        });
        let output_f = perm.permute(input_f);
        let input: [u32; PERMUTATION_WIDTH] =
            input_f.map(|x| x.as_canonical_u32()).try_into().unwrap();
        let output: [u32; PERMUTATION_WIDTH] =
            output_f.map(|x| x.as_canonical_u32()).try_into().unwrap();
        let event = Poseidon2Event { input, output };
        rec.poseidon2_events.push(event);
    }

    rec
}

#[cfg(feature = "cuda")]
#[test]
fn test_riscv_poseidon2_gpu_generate_main() {
    let chunk = LazyLock::force(&SHARD);

    let chip = Poseidon2ChipP3::<F, LinearLayers, Config>::default();
    let cpu_trace = cpu_generate_main(&chip, chunk);
    let gpu_trace = gpu_generate_main(&chip, chunk);

    assert_eq!(cpu_trace.values.len(), gpu_trace.values.len());
    assert_eq!(cpu_trace, gpu_trace);

    let non_zero_count = cpu_trace.values.iter().filter(|&&v| v != F::ZERO).count();
    assert!(
        non_zero_count > 0,
        "main trace is all zeros — both CPU and GPU may be broken"
    );

    println!(
        "riscv_poseidon2: main trace size: {} cols × {} rows, non-zero: {}/{}",
        cpu_trace.width,
        cpu_trace.values.len() / cpu_trace.width,
        non_zero_count,
        cpu_trace.values.len(),
    );
}

#[cfg(feature = "cuda")]
#[test]
fn bench_riscv_poseidon2_cpu_vs_gpu() {
    if !is_pool_initialized() {
        init_cpu_event_buffer_pool(50, HostAllocFlags::DEFAULT);
    }

    let warmup_sizes: Vec<usize> = vec![1 << 14];
    let bench_sizes: Vec<usize> = vec![1 << 14, 1 << 16, 1 << 18, 1 << 20];

    let total_cols = RISCV_NUM_POSEIDON2_COLS::<Config>;
    let value_cols = RISCV_NUM_POSEIDON2_VALUE_COLS::<Config>;
    let datapar = 4usize; // RISCV_POSEIDON2_DATAPAR

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
        let record = make_shard(n);
        let chip = Poseidon2ChipP3::<F, LinearLayers, Config>::default();

        let nrows = n.div_ceil(datapar);
        let log2 = (nrows as f64).log2().ceil() as usize + 1;

        let mut cpu_record = record.clone();
        cpu_record.shape =
            Some(crate::instances::compiler::shapes::riscv_shape::RiscvPadShape::default());
        cpu_record
            .shape
            .as_mut()
            .unwrap()
            .inner
            .insert(chip.name(), log2);

        // ── CPU ──
        let cpu_start = Instant::now();
        let cpu_trace = cpu_generate_main(&chip, &cpu_record);
        let cpu_ms = cpu_start.elapsed().as_secs_f64() * 1000.0;

        // ── GPU (kernel only: exclude H2D and D2H) ──
        let stream = init_test_stream();
        let sync_mem_pool = get_global_mem_pool(0);
        let mem_pool = &sync_mem_pool.0;

        let events = &record.poseidon2_events;
        let event_size = events.len();
        let padded_nrows = 1 << log2;
        let trace_size = padded_nrows * total_cols;

        let mut d_events = DevicePoolAllocation::<Poseidon2Event>::alloc_from_pool_async(
            event_size, mem_pool, stream,
        )
        .unwrap();
        let dummy_row_size = RISCV_DUMMY_ROW_KB.len();
        let mut d_dummy_row = DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(
            dummy_row_size,
            mem_pool,
            stream,
        )
        .unwrap();
        let rc_flat = chip.constants.flatten_for_gpu();
        let mut d_round_constants = DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(
            rc_flat.len(),
            mem_pool,
            stream,
        )
        .unwrap();
        unsafe {
            let _ = cudaMemcpyAsync(
                d_round_constants.as_mut_c_void_ptr(),
                rc_flat.as_ptr() as *const _,
                rc_flat.len() * size_of::<KoalaBear>(),
                CudaMemoryCopyKind::HostToDevice,
                stream.into(),
            );
            let _ = cudaMemcpyAsync(
                d_events.as_mut_c_void_ptr(),
                events.as_ptr() as *const _,
                event_size * size_of::<Poseidon2Event>(),
                CudaMemoryCopyKind::HostToDevice,
                stream.into(),
            );
            let _ = cudaMemcpyAsync(
                d_dummy_row.as_mut_c_void_ptr(),
                RISCV_DUMMY_ROW_KB.as_ptr() as *const _,
                dummy_row_size * size_of::<KoalaBear>(),
                CudaMemoryCopyKind::HostToDevice,
                stream.into(),
            );
        }
        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .unwrap();
        stream.synchronize().unwrap();

        let gpu_start = Instant::now();
        unsafe {
            cuda_riscv_poseidon2_generate_main(
                value_cols,
                event_size,
                trace_size,
                d_events.as_ptr() as *const _,
                d_trace.as_mut_ptr() as *mut _,
                d_dummy_row.as_ptr() as *const _,
                d_round_constants.as_ptr() as *const _,
                stream.into(),
            );
        }
        stream.synchronize().unwrap();
        let gpu_ms = gpu_start.elapsed().as_secs_f64() * 1000.0;

        if is_warmup {
            println!("{:<12} {:>12} {:>12} {:>12}", n, "warmup", "warmup", "—");
            continue;
        }

        // ── Verify CPU == GPU (D2H + compare, not timed) ──
        let gpu_trace = TraceData::<F>::Gpu(total_cols, d_trace).to_host(stream);
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
