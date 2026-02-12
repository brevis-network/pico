//! Run the Reth program using Pico's baseline interpreter (next_state_batch).

use pico_vm::{
    configs::config::StarkGenericConfig,
    emulator::{emulator::MetaEmulator, opts::EmulatorOpts},
    instances::{
        chiptype::riscv_chiptype::RiscvChipType, configs::riscv_kb_config::StarkConfig as RiscvKBSC,
    },
    machine::witness::ProvingWitness,
    proverchain::{InitialProverSetup, RiscvProver},
};
use reth_lib::{create_stdin, load_block_input, load_reth_elf, parse_block_arg, validate_block};
use std::time::Instant;

const WARMUP_RUNS: usize = 1;
const BENCH_RUNS: usize = 5;

fn main() {
    let block_number = parse_block_arg();

    println!("Reth Baseline (Interpreter)");
    println!("============================\n");
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

    let riscv_opts = EmulatorOpts::bench_riscv_ops();
    let riscv = RiscvProver::new_initial_prover((RiscvKBSC::new(), &elf_bytes), riscv_opts, None);
    let riscv_opts = EmulatorOpts::bench_riscv_ops();

    println!("Program loaded:");
    println!("  Entry point: {:#x}", riscv.get_program().pc_start);
    println!("  Instructions: {}", riscv.get_program().instructions.len());
    println!(
        "  Memory size: {} words\n",
        riscv.get_program().memory_image.len()
    );

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

    let build_emulator = || {
        // Create stdin from raw block input bytes (not a serialized EmulatorStdinBuilder)
        let stdin = create_stdin::<RiscvKBSC>(&block_input).expect("Failed to create stdin");

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

    if WARMUP_RUNS > 0 {
        println!("Warming up ({} run)...", WARMUP_RUNS);
    }
    for _ in 0..WARMUP_RUNS {
        let mut emu = build_emulator();
        loop {
            let (_snapshot, report) = emu.next_state_batch(true, &mut |_rec| {}).unwrap();
            if report.done {
                break;
            }
        }
    }

    println!("\nRunning benchmarks...");
    let mut results = Vec::with_capacity(BENCH_RUNS);
    for i in 0..BENCH_RUNS {
        let mut emu = build_emulator();
        let start = Instant::now();
        loop {
            let (_snapshot, report) = emu.next_state_batch(true, &mut |_rec| {}).unwrap();
            if report.done {
                break;
            }
        }
        let duration = start.elapsed();
        let cycles = emu.cycles();
        results.push((cycles, duration));
        println!("  Run {}: {} instructions in {:?}", i + 1, cycles, duration);
    }

    // Assert consistency across runs
    let first_cycles = results[0].0;
    for (i, (cycles, _)) in results.iter().enumerate() {
        assert_eq!(
            *cycles,
            first_cycles,
            "Instruction count mismatch in run {}: expected {}, got {}",
            i + 1,
            first_cycles,
            cycles
        );
    }

    // Calculate averages
    let avg_time = results.iter().map(|(_, t)| t.as_secs_f64()).sum::<f64>() / BENCH_RUNS as f64;
    let avg_throughput = first_cycles as f64 / avg_time / 1_000_000.0;

    println!("\n✓ Execution completed successfully");
    println!("  Instructions: {}", first_cycles);
    println!("  Avg Wall time: {:.3}s", avg_time);
    println!("  Avg Throughput: {:.2}M insn/s", avg_throughput);
}
