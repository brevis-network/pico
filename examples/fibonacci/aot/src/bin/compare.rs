//! Performance comparison tool for batch mode (next_state_batch).

use pico_vm::{
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    configs::config::StarkGenericConfig,
    emulator::{
        emulator::MetaEmulator,
        opts::EmulatorOpts,
        riscv::{memory::GLOBAL_MEMORY_RECYCLER, state::RiscvEmulationState},
        stdin::EmulatorStdin,
    },
    instances::{
        chiptype::riscv_chiptype::RiscvChipType, configs::riscv_kb_config::StarkConfig as RiscvKBSC,
    },
    machine::witness::ProvingWitness,
    proverchain::{InitialProverSetup, RiscvProver},
};
use std::time::Instant;

#[cfg(feature = "aot")]
use aot::{AotRun, FibonacciEmulator};

const WARMUP_RUNS: usize = 1;
const BENCH_RUNS: usize = 5;
const INPUT_VALUE: u32 = 9_000_000u32;

/// Run baseline interpreter in batch mode.
fn run_baseline_bench(elf_bytes: &[u8]) -> (u64, std::time::Duration) {
    let riscv_opts = EmulatorOpts::bench_riscv_ops();
    let riscv = RiscvProver::new_initial_prover((RiscvKBSC::new(), elf_bytes), riscv_opts, None);
    let riscv_opts = EmulatorOpts::bench_riscv_ops();

    let n = INPUT_VALUE;
    let build_emulator = || {
        let mut stdin_builder = EmulatorStdin::<Program, Vec<u8>>::new_builder::<RiscvKBSC>();
        stdin_builder.write(&n);
        let (stdin, _deferred_proof) = stdin_builder.finalize::<Program>();

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
        MetaEmulator::setup_riscv(&witness, None)
    };

    for _ in 0..WARMUP_RUNS {
        let mut emu = build_emulator();
        loop {
            let (snapshot, report) = emu.next_state_batch(true, &mut |_rec| {}).unwrap();
            recycle_snapshot_memory(snapshot);
            if report.done {
                break;
            }
        }
    }

    let mut emu = build_emulator();
    let start = Instant::now();
    loop {
        let (snapshot, report) = emu.next_state_batch(true, &mut |_rec| {}).unwrap();
        recycle_snapshot_memory(snapshot);
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
fn run_aot_bench(elf_bytes: &[u8]) -> (u64, std::time::Duration, u32) {
    let compiler = Compiler::new(SourceType::RISCV, elf_bytes);
    let program = compiler.compile();

    let n = INPUT_VALUE;
    let mut stdin_builder = EmulatorStdin::<Program, Vec<u8>>::new_builder::<RiscvKBSC>();
    stdin_builder.write(&n);
    let (stdin, _) = stdin_builder.finalize::<Program>();
    let input_stream = stdin.inputs.to_vec();

    let opts = EmulatorOpts::bench_riscv_ops();
    for _ in 0..WARMUP_RUNS {
        let mut emu = FibonacciEmulator::new(program.clone(), input_stream.clone());
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

    let mut emu = FibonacciEmulator::new(program, input_stream);
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
fn run_aot_bench(_elf_bytes: &[u8]) -> (u64, std::time::Duration, u32) {
    panic!("AOT feature not enabled. Build with: cargo run --features aot --bin compare");
}

fn recycle_snapshot_memory(snapshot: RiscvEmulationState) {
    let RiscvEmulationState { memory, .. } = snapshot;
    let _ = GLOBAL_MEMORY_RECYCLER.send((memory, true));
}

fn main() {
    println!("Fibonacci Batch Performance Comparison");
    println!("=======================================\n");

    let elf_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../app/elf/riscv32im-pico-zkvm-elf"
    );
    let elf_bytes = std::fs::read(elf_path).expect("Failed to read ELF file");

    println!("Program loaded: {} bytes", elf_bytes.len());
    println!("Input: n = {}", INPUT_VALUE);
    println!("Benchmark runs: {}\n", BENCH_RUNS);

    // Run baseline benchmarks
    println!("Benchmarking baseline (interpreter)...");
    let mut baseline_results = Vec::with_capacity(BENCH_RUNS);
    for i in 0..BENCH_RUNS {
        let (insns, time) = run_baseline_bench(&elf_bytes);
        baseline_results.push((insns, time));
        println!("  Run {}: {} instructions in {:?}", i + 1, insns, time);
    }

    // Run AOT benchmarks
    println!("\nBenchmarking AOT emulator...");
    let mut aot_results = Vec::with_capacity(BENCH_RUNS);
    for i in 0..BENCH_RUNS {
        let (insns, time, batches) = run_aot_bench(&elf_bytes);
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
