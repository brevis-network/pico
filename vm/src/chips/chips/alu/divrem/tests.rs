use crate::{
    chips::chips::alu::{
        divrem::{utils::get_quotient_and_remainder, DivRemChip},
        event::AluEvent,
    },
    compiler::riscv::opcode::Opcode,
    emulator::riscv::record::EmulationRecord,
    machine::chip::ChipBehavior,
};
#[cfg(feature = "cuda")]
use crate::{
    chips::{
        chips::{
            alu::divrem::columns::NUM_DIVREM_COLS,
            byte::{columns::NUM_BYTE_MULT_COLS, ByteChip},
        },
        tests::init_test_stream,
        trace::TraceData,
    },
    cuda_adaptor::resource_pool::mem_pool::get_global_mem_pool,
    emulator::riscv::{
        alu_event_pool::{init_alu_event_buffer_pool, is_alu_pool_initialized},
        event_pool::HostAllocFlags,
    },
    instances::{
        compiler::shapes::riscv_shape::RiscvPadShape,
        preparer::{
            gpu_allocate_and_copy_add_sub_events, gpu_allocate_and_copy_lt_events,
            gpu_allocate_byte_trace, gpu_finalize_byte_trace, precompute_event_size,
            verify_add_sub_events, verify_lt_events, DivremExtraEventIndices,
            PreallocatedGpuMemory, PreparedGpuEvents,
        },
    },
    machine::chip::GpuChipBehavior,
    primitives::consts::DIVREM_DATAPAR,
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
use pico_gpu_api::cuda_divrem_generate_extra_record_and_main;
use rand::{rng, seq::IndexedRandom, RngExt};
#[cfg(feature = "cuda")]
use std::{sync::LazyLock, time::Instant};

#[cfg(feature = "cuda")]
type F = KoalaBear;

#[cfg(feature = "cuda")]
static GPU_TEST_RECORD: LazyLock<EmulationRecord> =
    LazyLock::new(|| generate_gpu_test_record(1 << 20));

#[cfg(feature = "cuda")]
fn cpu_generate_main(chip: &DivRemChip<F>, input: &EmulationRecord) -> RowMajorMatrix<F> {
    chip.generate_main(input, &mut EmulationRecord::default())
}

#[cfg(feature = "cuda")]
fn generate_gpu_test_record(event_count: u64) -> EmulationRecord {
    let rng = &mut rng();
    let all_ops = [
        Opcode::DIV,
        Opcode::DIVU,
        Opcode::REM,
        Opcode::REMU,
        Opcode::DIVW,
        Opcode::DIVUW,
        Opcode::REMW,
        Opcode::REMUW,
    ];
    let divrem_events = (0..event_count)
        .map(|i| {
            let op = *all_ops.choose(rng).unwrap();
            let b: u64 = rng.random();
            let c: u64 = rng.random_range(1..u64::MAX);
            let (quotient, remainder) = get_quotient_and_remainder(b, c, op);
            let a = match op {
                Opcode::DIV | Opcode::DIVU | Opcode::DIVW | Opcode::DIVUW => quotient,
                Opcode::REM | Opcode::REMU | Opcode::REMW | Opcode::REMUW => remainder,
                _ => unreachable!(),
            };
            let is_imm = false;
            AluEvent::new(i, op, a, b, c, is_imm)
        })
        .collect();

    let mut record = EmulationRecord::default();
    record.divrem_events = divrem_events;
    record
}

#[cfg(feature = "cuda")]
fn gpu_generate_extra_record_and_main(
    chip: &DivRemChip<F>,
    input: &EmulationRecord,
    prepared_gpu_events: &PreparedGpuEvents,
    preallocated_gpu_memory: &mut PreallocatedGpuMemory,
) -> RowMajorMatrix<F> {
    let stream = init_test_stream();
    let trace = chip.gpu_generate_extra_record_and_main(
        0,
        input,
        prepared_gpu_events,
        preallocated_gpu_memory,
    );
    trace.to_host(stream)
}

#[cfg(feature = "cuda")]
#[test]
fn test_divrem_gpu_generate_extra_record_and_main() {
    if !is_alu_pool_initialized() {
        init_alu_event_buffer_pool(50, HostAllocFlags::DEFAULT);
    }
    let original_record = LazyLock::force(&GPU_TEST_RECORD);

    let chip = DivRemChip::default();

    let mut complete_record = original_record.clone();
    chip.extra_record(&original_record, &mut complete_record);
    let mut counted_record = original_record.clone();
    let event_counter = precompute_event_size::<F>(&mut counted_record);
    event_counter.assert_event_counts_match(&complete_record);

    complete_record.shape = Some(RiscvPadShape::default());
    complete_record
        .shape
        .as_mut()
        .unwrap()
        .inner
        .insert(chip.name(), 21);
    counted_record.shape = Some(RiscvPadShape::default());
    counted_record
        .shape
        .as_mut()
        .unwrap()
        .inner
        .insert(chip.name(), 21);

    let cpu_trace = cpu_generate_main(&chip, &complete_record);
    let byte_chip = ByteChip::<F>::default();
    let cpu_byte_trace = byte_chip.generate_main(&complete_record, &mut EmulationRecord::default());

    let stream = init_test_stream();
    let prepared_gpu_events = PreparedGpuEvents::new(&counted_record, event_counter.clone());
    let mut preallocated_gpu_memory = PreallocatedGpuMemory {
        d_add_sub_events: gpu_allocate_and_copy_add_sub_events(
            &stream,
            0,
            &counted_record,
            &prepared_gpu_events,
        )
        .unwrap(),
        d_lt_events: gpu_allocate_and_copy_lt_events(
            &stream,
            0,
            &counted_record,
            &prepared_gpu_events,
        )
        .unwrap(),
        d_byte_trace: gpu_allocate_byte_trace(&stream, 0).unwrap(),
        ..Default::default()
    };

    let gpu_trace = gpu_generate_extra_record_and_main(
        &chip,
        &counted_record,
        &prepared_gpu_events,
        &mut preallocated_gpu_memory,
    );
    // Debug: find first mismatch
    let width = NUM_DIVREM_COLS;
    let nrows = cpu_trace.values.len() / width;
    let mut found = false;
    for row in 0..nrows {
        for col in 0..width {
            let idx = row * width + col;
            if cpu_trace.values[idx] != gpu_trace.values[idx] {
                if !found {
                    println!(
                        "FIRST MISMATCH at row={}, col={}: cpu={:?}, gpu={:?}",
                        row, col, cpu_trace.values[idx], gpu_trace.values[idx]
                    );
                    found = true;
                }
                println!(
                    "  row={} col={}: cpu={:?} gpu={:?}",
                    row, col, cpu_trace.values[idx], gpu_trace.values[idx]
                );
            }
        }
        if found {
            break;
        }
    }
    if !found {
        println!("No main trace mismatches found!");
    }
    assert_eq!(cpu_trace, gpu_trace);

    let non_zero_main = cpu_trace.values.iter().filter(|&&v| v != F::ZERO).count();
    assert!(
        non_zero_main > 0,
        "main trace is all zeros — both CPU and GPU may be broken"
    );

    verify_add_sub_events(
        &preallocated_gpu_memory.d_add_sub_events,
        &event_counter,
        &complete_record,
        &stream,
    );
    // DivRem emits no lt events (`lt: 0`), so this returns false without checking anything; it is
    // kept as a smoke call. The shared `LtWordU16Gadget` regression is covered by the trace
    // equality above, not by this.
    let _ = verify_lt_events(
        &preallocated_gpu_memory.d_lt_events,
        event_counter.num_lt_events,
        &complete_record,
        &stream,
    );

    gpu_finalize_byte_trace(&stream, &mut preallocated_gpu_memory).unwrap();
    stream.synchronize().unwrap();

    let d_byte_trace = preallocated_gpu_memory.d_byte_trace.take().unwrap();
    let host_gpu_byte_trace =
        TraceData::<F>::Gpu(NUM_BYTE_MULT_COLS, d_byte_trace).to_host(&stream);
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
        "divrem: main trace non-zero elements: {}/{}, byte trace non-zero: {}/{}",
        non_zero_main,
        cpu_trace.values.len(),
        non_zero_byte,
        cpu_byte_trace.values.len(),
    );
}

#[cfg(feature = "cuda")]
/// Construct a Program with DIV/REM (signed 64-bit) instructions.
#[test]
fn bench_divrem_cpu_vs_gpu() {
    if !is_alu_pool_initialized() {
        init_alu_event_buffer_pool(50, HostAllocFlags::DEFAULT);
    }

    let warmup_sizes: Vec<u64> = vec![1 << 16];
    let bench_sizes: Vec<u64> = vec![1 << 16, 1 << 18, 1 << 20, 1 << 22];

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
        let chip = DivRemChip::<F>::default();

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

        // ── CPU ──
        let cpu_start = Instant::now();
        let cpu_trace = cpu_generate_main(&chip, &complete_record);
        let cpu_ms = cpu_start.elapsed().as_secs_f64() * 1000.0;

        // ── GPU (kernel only: exclude H2D and D2H) ──
        let stream = init_test_stream();
        let sync_mem_pool = get_global_mem_pool(0);
        let mem_pool = &sync_mem_pool.0;

        let events = &counted_record.divrem_events;
        let event_size = events.len();
        let _nrows = event_size.div_ceil(DIVREM_DATAPAR);
        let padded_nrows = 1 << log2;
        let trace_size = padded_nrows * NUM_DIVREM_COLS;

        let mut d_events =
            DevicePoolAllocation::<AluEvent>::alloc_from_pool_async(event_size, mem_pool, stream)
                .unwrap();
        unsafe {
            let _ = cudaMemcpyAsync(
                d_events.as_mut_c_void_ptr(),
                events.as_ptr() as *const _,
                event_size * size_of::<AluEvent>(),
                CudaMemoryCopyKind::HostToDevice,
                stream.into(),
            );
        }

        let mut d_extra_indices =
            DevicePoolAllocation::<DivremExtraEventIndices>::alloc_from_pool_async(
                event_size, mem_pool, stream,
            )
            .unwrap();
        unsafe {
            let _ = cudaMemcpyAsync(
                d_extra_indices.as_mut_c_void_ptr(),
                event_counter.divrem_extra_event_indices.as_ptr() as *const _,
                event_size * size_of::<DivremExtraEventIndices>(),
                CudaMemoryCopyKind::HostToDevice,
                stream.into(),
            );
        }

        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .unwrap();

        let prepared_gpu_events = PreparedGpuEvents::new(&counted_record, event_counter.clone());

        let mut d_add_sub_events =
            gpu_allocate_and_copy_add_sub_events(stream, 0, &counted_record, &prepared_gpu_events)
                .unwrap()
                .unwrap();
        let mut d_byte_trace = gpu_allocate_byte_trace(stream, 0).unwrap().unwrap();

        stream.synchronize().unwrap();

        let gpu_start = Instant::now();
        unsafe {
            cuda_divrem_generate_extra_record_and_main(
                NUM_DIVREM_COLS,
                event_size,
                trace_size,
                d_events.as_ptr() as *const _,
                d_trace.as_mut_ptr() as *mut _,
                stream.into(),
                d_extra_indices.as_ptr() as *const _,
                d_byte_trace.as_mut_ptr() as *mut _,
                d_add_sub_events.as_mut_ptr() as *mut _,
                prepared_gpu_events
                    .event_counter
                    .start_indices
                    .divrem_extra_add_sub_start_index,
            );
        }
        stream.synchronize().unwrap();
        let gpu_ms = gpu_start.elapsed().as_secs_f64() * 1000.0;

        if is_warmup {
            println!("{:<12} {:>12} {:>12} {:>12}", n, "warmup", "warmup", "—");
            continue;
        }

        // ── Verify CPU == GPU (D2H + compare, not timed) ──
        let gpu_trace = TraceData::<F>::Gpu(NUM_DIVREM_COLS, d_trace).to_host(stream);
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

/// CPU-only test with large random u64 values.
/// Exposes LtUnsignedGadget::populate bug: byte_flags has WORD_SIZE=4 entries
/// but populate iterates over 8 bytes and accesses byte_flags[i] with i up to 7.
#[test]
fn test_divrem_cpu_large_random_values() {
    type F = KoalaBear;
    let rng = &mut rng();
    let all_ops = [
        Opcode::DIV,
        Opcode::DIVU,
        Opcode::REM,
        Opcode::REMU,
        Opcode::DIVW,
        Opcode::DIVUW,
        Opcode::REMW,
        Opcode::REMUW,
    ];
    let divrem_events: Vec<AluEvent> = (0..1024u64)
        .map(|i| {
            let op = *all_ops.choose(rng).unwrap();
            let b: u64 = rng.random();
            let c: u64 = rng.random_range(1..u64::MAX);
            let (quotient, remainder) = get_quotient_and_remainder(b, c, op);
            let a = match op {
                Opcode::DIV | Opcode::DIVU | Opcode::DIVW | Opcode::DIVUW => quotient,
                Opcode::REM | Opcode::REMU | Opcode::REMW | Opcode::REMUW => remainder,
                _ => unreachable!(),
            };
            AluEvent::new(i, op, a, b, c, false)
        })
        .collect();

    let mut record = EmulationRecord::default();
    record.divrem_events = divrem_events;

    let chip = DivRemChip::<F>::default();
    // This will panic with "index out of bounds: the len is 4 but the index is ..."
    // if LtUnsignedGadget::populate has the byte indexing bug.
    let _trace = chip.generate_main(&record, &mut EmulationRecord::default());
    println!("CPU trace generation with large random u64 values succeeded");
}
