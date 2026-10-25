use crate::{
    chips::{
        chips::{
            alu::{
                bitwise::{
                    columns::{NUM_BITWISE_COLS, NUM_BITWISE_VALUE_COLS},
                    BitwiseChip,
                },
                event::AluEvent,
            },
            byte::{columns::NUM_BYTE_MULT_COLS, ByteChip},
        },
        tests::init_test_stream,
        trace::TraceData,
    },
    compiler::riscv::opcode::Opcode,
    instances::{
        compiler::shapes::riscv_shape::RiscvPadShape,
        preparer::{
            gpu_allocate_and_copy_alu_events, gpu_allocate_byte_trace, gpu_finalize_byte_trace,
            precompute_event_size, PreallocatedGpuMemory, PreparedGpuEvents,
        },
    },
    machine::chip::ChipBehavior,
};
use cudart::{memory::CudaHostAllocFlags, memory_pools::DevicePoolAllocation, slice::CudaSliceMut};
use cudart_sys::*;
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
use p3_matrix::dense::RowMajorMatrix;
use pico_gpu_api::cuda_bitwise_generate_extra_record_and_main_u64;
use rand::{rng, RngExt};
use std::{sync::LazyLock, time::Instant};

use crate::emulator::riscv::{
    alu_event_pool::{init_alu_event_buffer_pool, is_alu_pool_initialized},
    record::EmulationRecord,
};

type F = KoalaBear;

static GPU_TEST_RECORD: LazyLock<EmulationRecord> =
    LazyLock::new(|| generate_gpu_test_record(1 << 20));

fn cpu_generate_main(chip: &BitwiseChip<F>, input: &EmulationRecord) -> RowMajorMatrix<F> {
    chip.generate_main(input, &mut EmulationRecord::default())
}

fn generate_gpu_test_record(event_count: u64) -> EmulationRecord {
    if !is_alu_pool_initialized() {
        init_alu_event_buffer_pool(50, CudaHostAllocFlags::DEFAULT);
    }

    let rng = &mut rng();
    let opcodes = [Opcode::XOR, Opcode::OR, Opcode::AND];
    let bitwise_events: Vec<AluEvent> = (0..event_count)
        .map(|i| {
            let b: u64 = rng.random();
            let c: u64 = rng.random();
            let op = opcodes[(i % 3) as usize];
            let a = match op {
                Opcode::XOR => b ^ c,
                Opcode::OR => b | c,
                Opcode::AND => b & c,
                _ => b ^ c,
            };
            AluEvent::new(i, op, a, b, c, false)
        })
        .collect();

    let mut record = EmulationRecord::default();
    record.bitwise_events = bitwise_events;
    record
}

fn gpu_generate_extra_record_and_main(
    chip: &BitwiseChip<F>,
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

#[test]
fn test_bitwise_gpu_generate_extra_record_and_main() {
    let original_record = LazyLock::force(&GPU_TEST_RECORD);

    let chip = BitwiseChip::default();

    let mut complete_record = original_record.clone();
    chip.extra_record(original_record, &mut complete_record);
    let mut counted_record = original_record.clone();
    let event_counter = precompute_event_size::<F>(&mut counted_record);

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
    let (d_add_sub_events, d_lt_events, d_mul_events) =
        gpu_allocate_and_copy_alu_events(stream, 0, &counted_record, &prepared_gpu_events)
            .expect("ALU events alloc failed");

    let mut preallocated_gpu_memory = PreallocatedGpuMemory {
        d_add_sub_events,
        d_lt_events,
        d_mul_events,
        d_byte_trace: gpu_allocate_byte_trace(stream, 0).unwrap(),
        ..Default::default()
    };

    let gpu_trace = gpu_generate_extra_record_and_main(
        &chip,
        &counted_record,
        &prepared_gpu_events,
        &mut preallocated_gpu_memory,
    );
    assert_eq!(cpu_trace, gpu_trace);

    let non_zero_main = cpu_trace.values.iter().filter(|&&v| v != F::ZERO).count();
    assert!(
        non_zero_main > 0,
        "main trace is all zeros — both CPU and GPU may be broken"
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
        "bitwise: main trace non-zero elements: {}/{}, byte trace non-zero: {}/{}",
        non_zero_main,
        cpu_trace.values.len(),
        non_zero_byte,
        cpu_byte_trace.values.len(),
    );
}

#[test]
fn bench_bitwise_cpu_vs_gpu() {
    if !is_alu_pool_initialized() {
        init_alu_event_buffer_pool(50, CudaHostAllocFlags::DEFAULT);
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
        let chip = BitwiseChip::<F>::default();

        let mut complete_record = original_record.clone();
        chip.extra_record(&original_record, &mut complete_record);
        let counted_record = original_record.clone();

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
        let sync_mem_pool = crate::cuda_adaptor::resource_pool::mem_pool::get_global_mem_pool(0);
        let mem_pool = &sync_mem_pool.0;

        let bitwise_events = &counted_record.bitwise_events;
        let event_size = bitwise_events.len();
        let padded_nrows = 1 << log2;
        let trace_size = padded_nrows * NUM_BITWISE_COLS;

        let mut d_events =
            DevicePoolAllocation::<AluEvent>::alloc_from_pool_async(event_size, mem_pool, stream)
                .unwrap();
        unsafe {
            let _ = cudaMemcpyAsync(
                d_events.as_mut_c_void_ptr(),
                bitwise_events.as_ptr() as *const _,
                event_size * std::mem::size_of::<AluEvent>(),
                CudaMemoryCopyKind::HostToDevice,
                stream.into(),
            );
        }
        let mut d_trace =
            DevicePoolAllocation::<KoalaBear>::alloc_from_pool_async(trace_size, mem_pool, stream)
                .unwrap();
        let mut d_byte_trace_alloc = gpu_allocate_byte_trace(stream, 0).unwrap().unwrap();
        stream.synchronize().unwrap();

        let gpu_start = Instant::now();
        unsafe {
            cuda_bitwise_generate_extra_record_and_main_u64(
                NUM_BITWISE_VALUE_COLS,
                event_size,
                trace_size,
                d_events.as_ptr() as *const _,
                d_trace.as_mut_ptr() as *mut _,
                d_byte_trace_alloc.as_mut_ptr() as *mut _,
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
        let gpu_trace = TraceData::<F>::Gpu(NUM_BITWISE_COLS, d_trace).to_host(stream);
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
