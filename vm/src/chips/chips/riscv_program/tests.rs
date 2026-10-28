use crate::{
    chips::chips::riscv_program::{
        columns::{ProgramPreprocessedCols, NUM_PROGRAM_PREPROCESSED_COLS},
        ProgramChip,
    },
    compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
    machine::chip::ChipBehavior,
};
#[cfg(feature = "cuda")]
use crate::{
    chips::{
        chips::riscv_program::columns::NUM_PROGRAM_MULT_COLS, tests::init_test_stream,
        trace::TraceData,
    },
    cuda_adaptor::resource_pool::mem_pool::get_global_mem_pool,
    emulator::riscv::{
        cpu_event_pool::{init_cpu_event_buffer_pool, is_pool_initialized},
        event_pool::HostAllocFlags,
        record::EmulationRecord,
    },
    instances::{
        compiler::shapes::riscv_shape::RiscvPadShape,
        preparer::{
            gpu_allocate_cpu_events, precompute_event_size, PreallocatedGpuMemory,
            PreparedGpuEvents,
        },
    },
    machine::chip::GpuChipBehavior,
};
#[cfg(feature = "cuda")]
use cudart::{memory_pools::DevicePoolAllocation, slice::CudaSliceMut};
#[cfg(feature = "cuda")]
use cudart_sys::*;
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear;
#[cfg(feature = "cuda")]
use p3_matrix::dense::RowMajorMatrix;
#[cfg(feature = "cuda")]
use pico_gpu_api::cuda_riscv_program_generate_main_u64;
#[cfg(feature = "cuda")]
use rand::{rng, RngExt};
use std::borrow::Borrow;
#[cfg(feature = "cuda")]
use std::{
    sync::{Arc, LazyLock},
    time::Instant,
};

type F = KoalaBear;

#[cfg(feature = "cuda")]
static GPU_TEST_RECORD: LazyLock<EmulationRecord> =
    LazyLock::new(|| generate_gpu_test_record(1 << 20));

#[cfg(feature = "cuda")]
fn cpu_generate_main(chip: &ProgramChip<F>, input: &EmulationRecord) -> RowMajorMatrix<F> {
    chip.generate_main(input, &mut EmulationRecord::default())
}

#[cfg(feature = "cuda")]
fn generate_gpu_test_record(event_count: usize) -> EmulationRecord {
    if !is_pool_initialized() {
        init_cpu_event_buffer_pool(50, HostAllocFlags::DEFAULT);
    }

    let num_instrs = 1 << 16;
    // A pc has two u16 limbs (`Pc::try_from` rejects 2^32 and above), so the fixture's base sits
    // inside the guest range like a real program's.
    let pc_base: u64 = 0x1000_0000;
    let instructions: Vec<Instruction> = (0..num_instrs)
        .map(|_| Instruction::new(Opcode::ADD, 0, 0, 0, false, false))
        .collect();
    let program = Arc::new(Program::new(instructions, pc_base, pc_base));

    let rng = &mut rng();
    let cpu_events: Vec<crate::chips::chips::riscv_cpu::event::CpuEvent> = (0..event_count)
        .map(|i| {
            let instr_idx: usize = rng.random_range(0..num_instrs);
            let pc = pc_base + (instr_idx as u64 * 4);
            let mut event = crate::chips::chips::riscv_cpu::event::CpuEvent::default();
            event.clk = i as u64;
            event.pc = pc;
            event
        })
        .collect();

    let mut record = EmulationRecord::new(program);
    record.add_cpu_events(&cpu_events).unwrap();
    record
}

#[cfg(feature = "cuda")]
fn gpu_generate_extra_record_and_main(
    chip: &ProgramChip<F>,
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
fn gpu_generate_preprocessed(chip: &ProgramChip<F>, program: &Program) -> RowMajorMatrix<F> {
    let stream = init_test_stream();
    let trace = chip.gpu_generate_preprocessed(0, program).unwrap();
    trace.to_host(stream)
}

#[cfg(feature = "cuda")]
#[test]
fn test_riscv_program_gpu_generate_preprocessed() {
    let original_record = LazyLock::force(&GPU_TEST_RECORD);
    let chip = ProgramChip::<F>::default();
    let program = original_record.program.clone();

    let cpu_trace = chip.generate_preprocessed(&program).unwrap();
    let gpu_trace = gpu_generate_preprocessed(&chip, &program);

    assert_eq!(cpu_trace.values.len(), gpu_trace.values.len());
    assert_eq!(cpu_trace, gpu_trace);

    let non_zero_count = cpu_trace.values.iter().filter(|&&v| v != F::ZERO).count();
    assert!(
        non_zero_count > 0,
        "preprocessed trace is all zeros — both CPU and GPU may be broken"
    );

    let num_rows = cpu_trace.values.len() / chip.preprocessed_width();
    println!(
        "riscv_program: preprocessed trace size: {} cols × {} rows, non-zero: {}/{}",
        chip.preprocessed_width(),
        num_rows,
        non_zero_count,
        cpu_trace.values.len(),
    );
}

#[cfg(feature = "cuda")]
#[test]
fn test_riscv_program_gpu_generate_extra_record_and_main() {
    let original_record = LazyLock::force(&GPU_TEST_RECORD);

    let chip = ProgramChip::<F>::default();

    let mut complete_record = original_record.clone();
    let mut counted_record = original_record.clone();
    let event_counter = precompute_event_size::<F>(&mut counted_record);

    let log2 = (original_record.program.instructions.len() as f64)
        .log2()
        .ceil() as usize
        + 1;
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
    // `generate_main`'s GPU half *reads* the CPU event stream off the device
    // (`riscv_program/traces.rs:331` unwraps `d_cpu_events`, `:356` passes it to the kernel).
    // In production the buffer is shared: the Cpu chip runs first and uploads it itself
    // (`riscv_cpu/traces.rs:330-345`), and MemoryReadWrite reuses it. A standalone Program
    // fixture has no such predecessor, so it must both allocate and fill the buffer.
    // `gpu_allocate_cpu_events` only allocates -- allocating without copying leaves the kernel
    // reading zeros and produces an all-zero trace, which is a silent wrong answer rather than
    // a crash.
    let mut preallocated_gpu_memory = PreallocatedGpuMemory {
        d_cpu_events: gpu_allocate_cpu_events(stream, 0, &prepared_gpu_events).unwrap(),
        ..Default::default()
    };
    {
        use crate::chips::chips::riscv_cpu::event::CpuEvent;
        let event_size = event_counter.num_cpu_events;
        let src = counted_record.cpu_events.as_slice();
        assert_eq!(
            src.len(),
            event_size,
            "fixture must upload exactly the events the kernel is told to read"
        );
        let d = preallocated_gpu_memory.d_cpu_events.as_mut().unwrap();
        // Same house style as the production copies (`riscv_cpu/traces.rs:256` etc.): the
        // async return is ignored and the following synchronize surfaces any failure.
        unsafe {
            let _ = cudaMemcpyAsync(
                d.as_mut_ptr() as *mut _,
                src.as_ptr() as *const _,
                event_size * size_of::<CpuEvent>(),
                CudaMemoryCopyKind::HostToDevice,
                stream.into(),
            );
        }
        stream.synchronize().unwrap();
    }

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

    println!(
        "riscv_program: main trace non-zero elements: {}/{}",
        non_zero_main,
        cpu_trace.values.len(),
    );
}

#[cfg(feature = "cuda")]
#[test]
fn bench_riscv_program_cpu_vs_gpu() {
    if !is_pool_initialized() {
        init_cpu_event_buffer_pool(50, HostAllocFlags::DEFAULT);
    }

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
        let chip = ProgramChip::<F>::default();

        let mut complete_record = original_record.clone();

        let num_instrs = original_record.program.instructions.len();
        let log2 = (num_instrs as f64).log2().ceil() as usize + 1;
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

        let event_size = complete_record.cpu_events.len();
        let padded_nrows = 1 << log2;
        let trace_size = padded_nrows * NUM_PROGRAM_MULT_COLS;

        use crate::chips::chips::riscv_cpu::event::CpuEvent;
        let mut d_events =
            DevicePoolAllocation::<CpuEvent>::alloc_from_pool_async(event_size, mem_pool, stream)
                .unwrap();
        unsafe {
            let _ = cudaMemcpyAsync(
                d_events.as_mut_c_void_ptr(),
                complete_record.cpu_events.as_slice().as_ptr() as *const _,
                event_size * size_of::<CpuEvent>(),
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
        stream.synchronize().unwrap();

        let gpu_start = Instant::now();
        unsafe {
            cuda_riscv_program_generate_main_u64(
                NUM_PROGRAM_MULT_COLS,
                event_size,
                trace_size,
                complete_record.program.pc_base,
                d_events.as_ptr() as *const _,
                d_trace.as_mut_ptr() as *mut _,
                stream.into(),
                num_instrs,
            );
        }
        stream.synchronize().unwrap();
        let gpu_ms = gpu_start.elapsed().as_secs_f64() * 1000.0;

        if is_warmup {
            println!("{:<12} {:>12} {:>12} {:>12}", n, "warmup", "warmup", "—");
            continue;
        }

        // ── Verify CPU == GPU (D2H + compare, not timed) ──
        let gpu_trace = TraceData::<F>::Gpu(NUM_PROGRAM_MULT_COLS, d_trace).to_host(stream);
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

/// A hand-built program with a trap at index 1 and 3: `[ADD, UNIMP, ADD, EBREAK]`.
fn program_with_traps() -> Program {
    let pc_base: u64 = 0x1000_0000;
    let instructions = vec![
        Instruction::new(Opcode::ADD, 1, 2, 3, false, false),
        Instruction::new(Opcode::UNIMP, 0, 0, 0, true, true),
        Instruction::new(Opcode::ADD, 4, 5, 6, false, false),
        Instruction::new(Opcode::EBREAK, 0, 0, 0, false, false),
    ];
    Program::new(instructions, pc_base, pc_base)
}

/// The preprocessed table writes row 0 in place of every trap instruction, whole row included
/// (pc, instruction and selectors), and leaves the other rows alone.
#[test]
fn preprocessed_table_writes_row_zero_for_trap_instructions() {
    let chip = ProgramChip::<F>::default();
    let program = program_with_traps();
    let trace = chip.generate_preprocessed(&program).unwrap();
    let w = NUM_PROGRAM_PREPROCESSED_COLS;
    assert_eq!(trace.values.len() % w, 0);
    let rows = trace.values.len() / w;
    assert!(rows >= 4, "{rows} rows for 4 instructions");
    let row = |i: usize| &trace.values[i * w..(i + 1) * w];

    assert_eq!(row(1), row(0), "the UNIMP row must be a copy of row 0");
    assert_eq!(row(3), row(0), "the EBREAK row must be a copy of row 0");
    assert_ne!(row(2), row(0));
    // Padding rows repeat row 0 as well (the trap rows and the padding share one filler).
    for i in 4..rows {
        assert_eq!(row(i), row(0), "padding row {i} must be a copy of row 0");
    }

    let cols2: &ProgramPreprocessedCols<F> = row(2).borrow();
    let pc2 = program.pc_base + 8;
    assert_eq!(
        cols2.pc.0,
        [
            F::from_u16((pc2 & 0xFFFF) as u16),
            F::from_u16(((pc2 >> 16) & 0xFFFF) as u16)
        ]
    );
    assert_eq!(cols2.instruction.opcode, Opcode::ADD.as_field::<F>());
    assert_eq!(cols2.instruction.op_a, F::from_u8(4));
    assert_eq!(cols2.selectors.imm_b, F::ZERO);
    assert_eq!(cols2.selectors.is_ecall, F::ZERO);

    assert!(Opcode::UNIMP.is_trap() && Opcode::EBREAK.is_trap());
    assert!(!Opcode::ADD.is_trap() && !Opcode::ECALL.is_trap() && !Opcode::JAL.is_trap());
}

#[cfg(feature = "cuda")]
/// The CUDA kernel applies the trap rule by opcode value; the two tables must agree cell by cell
/// or the app preprocessed commitments differ.
#[test]
fn test_riscv_program_gpu_generate_preprocessed_with_traps() {
    let chip = ProgramChip::<F>::default();
    let program = program_with_traps();
    let cpu_trace = chip.generate_preprocessed(&program).unwrap();
    let gpu_trace = gpu_generate_preprocessed(&chip, &program);
    assert_eq!(cpu_trace.values.len(), gpu_trace.values.len());
    assert_eq!(cpu_trace, gpu_trace);
}

#[test]
#[should_panic(expected = "instruction 0 (UNIMP) is a trap")]
fn preprocessed_table_rejects_a_trap_at_instruction_zero() {
    let chip = ProgramChip::<F>::default();
    let pc_base: u64 = 0x1000_0000;
    let program = Program::new(
        vec![
            Instruction::new(Opcode::UNIMP, 0, 0, 0, true, true),
            Instruction::new(Opcode::ADD, 1, 2, 3, false, false),
        ],
        pc_base,
        pc_base,
    );
    let _ = chip.generate_preprocessed(&program);
}
