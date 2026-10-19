//! Run the Fibonacci program using AOT emulation (next_state_batch).

#[cfg(not(feature = "aot"))]
compile_error!(
    "This binary requires the 'aot' feature. Build with: cargo run --features aot --bin run"
);

#[cfg(feature = "aot")]
use aot::AotEmulatorCore;
#[cfg(feature = "aot")]
use aot_common::{recycle_snapshot_memory, AotRun};
use pico_vm::{
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    configs::stark_config::KoalaBearPoseidon2 as RiscvKBSC,
    emulator::{opts::EmulatorOpts, stdin::EmulatorStdin},
};
use std::time::Instant;

const DEFAULT_WARMUP_RUNS: usize = 1;
const DEFAULT_BENCH_RUNS: usize = 5;

fn env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(default)
}

fn main() {
    let warmup_runs = env_usize("AOT_ONLY_BENCH_WARMUP_RUNS", DEFAULT_WARMUP_RUNS);
    let bench_runs = env_usize("AOT_ONLY_BENCH_RUNS", DEFAULT_BENCH_RUNS);
    assert!(
        bench_runs > 0,
        "AOT_ONLY_BENCH_RUNS must be greater than zero"
    );

    println!("Fibonacci AOT Emulator");
    println!("=====================\n");

    // The fixture the validate tests read and `aot-generated` is generated from: AOT dispatch is
    // keyed by pc alone, so blocks compiled from one ELF must never run under another.
    let elf_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../perf/bench_data/rv64/fib-elf"
    );
    let elf_bytes = std::fs::read(elf_path).expect("Failed to read ELF file");

    let compiler =
        Compiler::new(SourceType::RISCV, &elf_bytes).expect("Failed to create RISC-V compiler");
    let program = compiler.compile();

    println!("Loaded program:");
    println!("  Entry point: {:#x}", program.pc_start);
    println!("  Instructions: {}", program.instructions.len());
    println!("  Memory size: {} words\n", program.memory_image.len());

    // Prepare stdin with fibonacci input
    let n = 9_000_000u32;
    println!("Input: n = {}", n);
    println!("Warmup runs: {}", warmup_runs);
    println!("Benchmark runs: {}\n", bench_runs);

    let mut stdin_builder = EmulatorStdin::<Program, Vec<u8>>::new_builder::<RiscvKBSC>();
    stdin_builder.write(&n);
    let stdin = stdin_builder.finalize::<Program>();
    let input_stream = stdin.inputs.to_vec();

    let opts = EmulatorOpts::bench_riscv_ops();
    let run_aot_once = |input_stream: &[Vec<u8>], opts: EmulatorOpts| -> (u64, u32) {
        let mut emu = AotEmulatorCore::new(program.clone(), input_stream.to_vec());
        let mut batch_count = 0;
        loop {
            // NOTE: caller must recycle returned snapshot memory.
            let (snapshot, report) = emu
                .next_state_batch(opts)
                .expect("AOT next_state_batch failed");
            recycle_snapshot_memory(snapshot);
            batch_count += 1;
            if report.done {
                break;
            }
        }
        (emu.insn_count, batch_count)
    };

    let run_aot_timed =
        |input_stream: &[Vec<u8>], opts: EmulatorOpts| -> (u64, std::time::Duration, u32) {
            let start = Instant::now();
            let (insn_count, batch_count) = run_aot_once(input_stream, opts);
            let duration = start.elapsed();
            (insn_count, duration, batch_count)
        };

    if warmup_runs > 0 {
        println!("Warming up ({} run)...", warmup_runs);
    }
    for _ in 0..warmup_runs {
        let _ = run_aot_once(&input_stream, opts);
    }

    println!("\nRunning benchmarks...");
    let mut results = Vec::with_capacity(bench_runs);
    for i in 0..bench_runs {
        let (insn_count, duration, batch_count) = run_aot_timed(&input_stream, opts);
        results.push((insn_count, duration, batch_count));
        println!(
            "  Run {}: {} instructions, {} batches in {:?}",
            i + 1,
            insn_count,
            batch_count,
            duration
        );
        println!(
            "AOT_ONLY_BENCH target=fibonacci run={} secs={:.6} cycles={} batches={} throughput_mcyc={:.2}",
            i + 1,
            duration.as_secs_f64(),
            insn_count,
            batch_count,
            insn_count as f64 / duration.as_secs_f64() / 1_000_000.0,
        );
    }

    // Assert consistency across runs
    let (first_insns, _, first_batches) = results[0];
    for (i, (insns, _, batches)) in results.iter().enumerate() {
        assert_eq!(
            *insns,
            first_insns,
            "Instruction count mismatch in run {}: expected {}, got {}",
            i + 1,
            first_insns,
            insns
        );
        assert_eq!(
            *batches,
            first_batches,
            "Batch count mismatch in run {}: expected {}, got {}",
            i + 1,
            first_batches,
            batches
        );
    }

    // Calculate averages
    let avg_time = results.iter().map(|(_, t, _)| t.as_secs_f64()).sum::<f64>() / bench_runs as f64;
    let avg_throughput = first_insns as f64 / avg_time / 1_000_000.0;

    println!("\n✓ Execution completed successfully");
    println!("  Instructions: {}", first_insns);
    println!("  Batches: {}", first_batches);
    println!("  Avg Wall time: {:.3}s", avg_time);
    println!("  Avg Throughput: {:.2}M insn/s", avg_throughput);
    println!(
        "AOT_ONLY_SUMMARY target=fibonacci avg_secs={:.6} cycles={} batches={} avg_throughput_mcyc={:.2}",
        avg_time,
        first_insns,
        first_batches,
        avg_throughput,
    );
}
