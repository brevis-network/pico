//! Run the Reth program using AOT emulation (next_state_batch).

#[cfg(not(feature = "aot"))]
compile_error!(
    "This binary requires the 'aot' feature. Build with: cargo run --features aot --bin run"
);

use pico_vm::{
    compiler::riscv::compiler::{Compiler, SourceType},
    emulator::{
        opts::EmulatorOpts,
        riscv::{memory::GLOBAL_MEMORY_RECYCLER, state::RiscvEmulationState},
    },
    instances::configs::riscv_kb_config::StarkConfig as RiscvKBSC,
};
#[cfg(feature = "aot")]
use reth_aot::{AotRun, RethEmulator};
use reth_lib::{create_stdin, load_block_input, load_reth_elf, parse_block_arg, validate_block};
use std::time::Instant;

const WARMUP_RUNS: usize = 1;
const BENCH_RUNS: usize = 5;

fn main() {
    let block_number = parse_block_arg();

    println!("Reth AOT Emulator");
    println!("=================\n");
    println!("Block number: {}\n", block_number);

    // Validate block input exists
    if let Err(e) = validate_block(block_number) {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    // Load ELF binary
    let elf_bytes = match load_reth_elf() {
        Ok(bytes) => bytes,
        Err(e) => {
            eprintln!("Error loading ELF: {}", e);
            std::process::exit(1);
        }
    };

    let compiler = Compiler::new(SourceType::RISCV, &elf_bytes);
    let program = compiler.compile();

    println!("Loaded program:");
    println!("  Entry point: {:#x}", program.pc_start);
    println!("  Instructions: {}", program.instructions.len());
    println!("  Memory size: {} words\n", program.memory_image.len());

    // Load block input
    let block_input = match load_block_input(block_number) {
        Ok(input) => input,
        Err(e) => {
            eprintln!("Error loading block input: {}", e);
            std::process::exit(1);
        }
    };

    println!("Block input size: {} bytes", block_input.len());
    println!("Benchmark runs: {}\n", BENCH_RUNS);

    let stdin = create_stdin::<RiscvKBSC>(&block_input).expect("Failed to create stdin");
    let input_stream = stdin.inputs.to_vec();

    let opts = EmulatorOpts::bench_riscv_ops();
    let run_aot_once = |input_stream: &[Vec<u8>], opts: EmulatorOpts| -> (u64, u32) {
        let mut emu = RethEmulator::new(program.clone(), input_stream.to_vec());
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

fn recycle_snapshot_memory(snapshot: RiscvEmulationState) {
    let RiscvEmulationState { memory, .. } = snapshot;
    let _ = GLOBAL_MEMORY_RECYCLER.send((memory, true));
}
