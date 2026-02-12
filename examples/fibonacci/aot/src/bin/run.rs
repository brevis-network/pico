//! Run the Fibonacci program using AOT emulation (next_state_batch).

#[cfg(not(feature = "aot"))]
compile_error!(
    "This binary requires the 'aot' feature. Build with: cargo run --features aot --bin run"
);

#[cfg(feature = "aot")]
use aot::{AotRun, FibonacciEmulator};
use pico_vm::{
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    emulator::{
        opts::EmulatorOpts,
        riscv::{memory::GLOBAL_MEMORY_RECYCLER, state::RiscvEmulationState},
        stdin::EmulatorStdin,
    },
    instances::configs::riscv_kb_config::StarkConfig as RiscvKBSC,
};
use std::time::Instant;

const WARMUP_RUNS: usize = 1;
const BENCH_RUNS: usize = 5;

fn recycle_snapshot_memory(snapshot: RiscvEmulationState) {
    let RiscvEmulationState { memory, .. } = snapshot;
    let _ = GLOBAL_MEMORY_RECYCLER.send((memory, true));
}

fn main() {
    println!("Fibonacci AOT Emulator");
    println!("=====================\n");

    // Load program
    let elf_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../app/elf/riscv32im-pico-zkvm-elf"
    );
    let elf_bytes = std::fs::read(elf_path).expect("Failed to read ELF file");

    let compiler = Compiler::new(SourceType::RISCV, &elf_bytes);
    let program = compiler.compile();

    println!("Loaded program:");
    println!("  Entry point: {:#x}", program.pc_start);
    println!("  Instructions: {}", program.instructions.len());
    println!("  Memory size: {} words\n", program.memory_image.len());

    // Prepare stdin with fibonacci input
    let n = 9_000_000u32;
    println!("Input: n = {}", n);
    println!("Benchmark runs: {}\n", BENCH_RUNS);

    let mut stdin_builder = EmulatorStdin::<Program, Vec<u8>>::new_builder::<RiscvKBSC>();
    stdin_builder.write(&n);
    let (stdin, _) = stdin_builder.finalize::<Program>();
    let input_stream = stdin.inputs.to_vec();

    let opts = EmulatorOpts::bench_riscv_ops();
    let run_aot_once = |input_stream: &[Vec<u8>], opts: EmulatorOpts| -> (u64, u32) {
        let mut emu = FibonacciEmulator::new(program.clone(), input_stream.to_vec());
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
        (emu.insn_count, batch_count)
    };

    let run_aot_timed =
        |input_stream: &[Vec<u8>], opts: EmulatorOpts| -> (u64, std::time::Duration, u32) {
            let start = Instant::now();
            let (insn_count, batch_count) = run_aot_once(input_stream, opts);
            let duration = start.elapsed();
            (insn_count, duration, batch_count)
        };

    if WARMUP_RUNS > 0 {
        println!("Warming up ({} run)...", WARMUP_RUNS);
    }
    for _ in 0..WARMUP_RUNS {
        let _ = run_aot_once(&input_stream, opts);
    }

    println!("\nRunning benchmarks...");
    let mut results = Vec::with_capacity(BENCH_RUNS);
    for i in 0..BENCH_RUNS {
        let (insn_count, duration, batch_count) = run_aot_timed(&input_stream, opts);
        results.push((insn_count, duration, batch_count));
        println!(
            "  Run {}: {} instructions, {} batches in {:?}",
            i + 1,
            insn_count,
            batch_count,
            duration
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
    let avg_time = results.iter().map(|(_, t, _)| t.as_secs_f64()).sum::<f64>() / BENCH_RUNS as f64;
    let avg_throughput = first_insns as f64 / avg_time / 1_000_000.0;

    println!("\n✓ Execution completed successfully");
    println!("  Instructions: {}", first_insns);
    println!("  Batches: {}", first_batches);
    println!("  Avg Wall time: {:.3}s", avg_time);
    println!("  Avg Throughput: {:.2}M insn/s", avg_throughput);
}
