//! Performance comparison tool for batch mode (next_state_batch).

use pico_vm::{
    compiler::riscv::compiler::{Compiler, SourceType},
    configs::config::StarkGenericConfig,
    emulator::{
        emulator::MetaEmulator,
        opts::EmulatorOpts,
        riscv::{memory::GLOBAL_MEMORY_RECYCLER, state::RiscvEmulationState},
    },
    instances::{
        chiptype::riscv_chiptype::RiscvChipType, configs::riscv_kb_config::StarkConfig as RiscvKBSC,
    },
    machine::witness::ProvingWitness,
    proverchain::{InitialProverSetup, RiscvProver},
};
use reth_lib::{create_stdin, load_block_input, load_reth_elf, parse_block_arg, validate_block};
use std::time::Instant;

#[cfg(feature = "aot")]
use reth_aot::{AotRun, RethEmulator};

const WARMUP_RUNS: usize = 1;
const BENCH_RUNS: usize = 5;

/// Run baseline interpreter in batch mode.
fn run_baseline_bench(elf_bytes: &[u8], block_input: &[u8]) -> (u64, std::time::Duration) {
    let riscv_opts = EmulatorOpts::bench_riscv_ops();
    let riscv = RiscvProver::new_initial_prover((RiscvKBSC::new(), elf_bytes), riscv_opts, None);
    let riscv_opts = EmulatorOpts::bench_riscv_ops();

    // Create stdin from raw block input bytes (not a serialized EmulatorStdinBuilder)
    let stdin = create_stdin::<RiscvKBSC>(block_input).expect("Failed to create stdin");

    let witness = ProvingWitness::<
        RiscvKBSC,
        RiscvChipType<<RiscvKBSC as StarkGenericConfig>::Val>,
        _,
    >::setup_for_riscv(
        riscv.get_program(),
        stdin,
        riscv_opts,
        riscv.pk().clone(),
        riscv.vk().clone(),
    );
    let mut emu = MetaEmulator::setup_riscv(&witness, None);

    let start = Instant::now();
    loop {
        let (_snapshot, report) = emu.next_state_batch(true, &mut |_rec| {}).unwrap();
        if report.done {
            break;
        }
    }
    let duration = start.elapsed();
    let cycles = emu.cycles();
    (cycles, duration)
}

/// Run AOT emulator in batch mode.
#[cfg(feature = "aot")]
fn run_aot_bench(elf_bytes: &[u8], block_input: &[u8]) -> (u64, std::time::Duration, u32) {
    let compiler = Compiler::new(SourceType::RISCV, elf_bytes);
    let program = compiler.compile();

    // Create stdin from raw block input bytes (not a serialized EmulatorStdinBuilder)
    let stdin = create_stdin::<RiscvKBSC>(block_input).expect("Failed to create stdin");
    let input_stream = stdin.inputs.to_vec();

    let opts = EmulatorOpts::bench_riscv_ops();
    for _ in 0..WARMUP_RUNS {
        let mut emu = RethEmulator::new(program.clone(), input_stream.clone());
        loop {
            let (snapshot, report) = emu
                .next_state_batch(opts)
                .expect("AOT next_state_batch failed");
            recycle_snapshot_memory(snapshot);
            if report.done {
                break;
            }
        }
    }

    let mut emu = RethEmulator::new(program, input_stream);
    let start = Instant::now();
    let mut batch_count = 0;
    loop {
        let (snapshot, report) = emu
            .next_state_batch(opts)
            .expect("AOT next_state_batch failed");
        recycle_snapshot_memory(snapshot);
        batch_count += 1;
        if report.done {
            break;
        }
    }
    let duration = start.elapsed();

    (emu.insn_count, duration, batch_count)
}

#[cfg(not(feature = "aot"))]
fn run_aot_bench(_elf_bytes: &[u8], _block_input: &[u8]) -> (u64, std::time::Duration, u32) {
    panic!("AOT feature not enabled. Build with: cargo run --features aot --bin compare");
}

fn recycle_snapshot_memory(snapshot: RiscvEmulationState) {
    let RiscvEmulationState { memory, .. } = snapshot;
    let _ = GLOBAL_MEMORY_RECYCLER.send((memory, true));
}

fn main() {
    let block_number = parse_block_arg();

    println!("Reth Batch Performance Comparison");
    println!("==================================\n");
    println!("Block number: {}\n", block_number);

    if let Err(e) = validate_block(block_number) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    let elf_bytes = match load_reth_elf() {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Error loading ELF: {}", e);
            std::process::exit(1);
        }
    };

    let block_input = match load_block_input(block_number) {
        Ok(input) => input,
        Err(e) => {
            eprintln!("Error loading block input: {}", e);
            std::process::exit(1);
        }
    };

    println!("Program loaded: {} bytes", elf_bytes.len());
    println!("Block input size: {} bytes", block_input.len());
    println!("Benchmark runs: {}\n", BENCH_RUNS);

    if WARMUP_RUNS > 0 {
        println!("Warming up baseline ({} run)...", WARMUP_RUNS);
        for _ in 0..WARMUP_RUNS {
            let _ = run_baseline_bench(&elf_bytes, &block_input);
        }
    }

    // Run baseline benchmarks
    println!("\nBenchmarking baseline (interpreter)...");
    let mut baseline_results = Vec::with_capacity(BENCH_RUNS);
    for i in 0..BENCH_RUNS {
        let (insns, time) = run_baseline_bench(&elf_bytes, &block_input);
        baseline_results.push((insns, time));
        println!("  Run {}: {} instructions in {:?}", i + 1, insns, time);
    }

    // Run AOT benchmarks
    println!("\nBenchmarking AOT emulator...");
    let mut aot_results = Vec::with_capacity(BENCH_RUNS);
    for i in 0..BENCH_RUNS {
        let (insns, time, batches) = run_aot_bench(&elf_bytes, &block_input);
        aot_results.push((insns, time, batches));
        println!(
            "  Run {}: {} instructions, {} batches in {:?}",
            i + 1,
            insns,
            batches,
            time
        );
    }

    // Assert consistency across runs
    let baseline_insns = baseline_results[0].0;
    for (i, (insns, _)) in baseline_results.iter().enumerate() {
        assert_eq!(
            *insns,
            baseline_insns,
            "Baseline instruction count mismatch in run {}: expected {}, got {}",
            i + 1,
            baseline_insns,
            insns
        );
    }

    let (aot_insns, _, aot_batches) = aot_results[0];
    for (i, (insns, _, batches)) in aot_results.iter().enumerate() {
        assert_eq!(
            *insns,
            aot_insns,
            "AOT instruction count mismatch in run {}: expected {}, got {}",
            i + 1,
            aot_insns,
            insns
        );
        assert_eq!(
            *batches,
            aot_batches,
            "AOT batch count mismatch in run {}: expected {}, got {}",
            i + 1,
            aot_batches,
            batches
        );
    }

    assert_eq!(
        baseline_insns, aot_insns,
        "Instruction count mismatch: baseline={}, aot={}",
        baseline_insns, aot_insns
    );

    // Calculate averages
    let baseline_avg_time = baseline_results
        .iter()
        .map(|(_, t)| t.as_secs_f64())
        .sum::<f64>()
        / BENCH_RUNS as f64;
    let aot_avg_time = aot_results
        .iter()
        .map(|(_, t, _)| t.as_secs_f64())
        .sum::<f64>()
        / BENCH_RUNS as f64;

    let baseline_avg_throughput = baseline_insns as f64 / baseline_avg_time / 1_000_000.0;
    let aot_avg_throughput = aot_insns as f64 / aot_avg_time / 1_000_000.0;

    // Print summary
    println!("\n");
    println!("{}", "=".repeat(70));
    println!("Batch Results (Average of {} runs)", BENCH_RUNS);
    println!("{}", "=".repeat(70));
    println!("\nInstructions executed: {}\n", baseline_insns);

    println!("Baseline (Interpreter):");
    println!("  Avg Duration:  {:.3}s", baseline_avg_time);
    println!("  Avg Throughput: {:.2}M insn/s", baseline_avg_throughput);

    println!("\nAOT Emulator:");
    println!("  Avg Duration:  {:.3}s", aot_avg_time);
    println!("  Batches:   {}", aot_batches);
    println!("  Avg Throughput: {:.2}M insn/s", aot_avg_throughput);

    let speedup = baseline_avg_time / aot_avg_time;
    println!("\nSpeedup (Baseline / AOT): {:.2}x", speedup);
    println!("\n{}", "=".repeat(70));
}
