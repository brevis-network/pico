//! Validation test comparing AOT emulator against baseline interpreter.
//! Compares snapshots and memory images for every chunk to ensure identical outputs.
//! Phase 0 intentionally repoints this harness to the existing RV64 Fibonacci
//! benchmark ELF so the validation gate reflects the real migration target,
//! even before the AOT stack is widened enough to pass.

use pico_vm::{
    chips::chips::riscv_memory::event::MemoryRecord,
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    emulator::{
        opts::EmulatorOpts, riscv::state::RiscvEmulationState,
        stdin::EmulatorStdin,
    },
    instances::configs::riscv_kb_config::StarkConfig as RiscvKBSC,
    machine::report::EmulationReport,
    primitives::consts::{DIGEST_SIZE, PV_DIGEST_NUM_WORDS},
};

use aot::{AotRun, FibonacciEmulator};
use pico_vm::emulator::riscv::{
    emulator::RiscvEmulator,
    memory::GLOBAL_MEMORY_RECYCLER,
};

const INPUT_VALUE: u32 = 10_000_000u32;

/// Chunk data collected during emulation.
/// Compares the snapshot contract fields of RiscvEmulationState between baseline and AOT.
fn compare_snapshots(
    chunk_idx: usize,
    baseline: &RiscvEmulationState,
    aot: &RiscvEmulationState,
    compare_accessed_memory: bool,
) {
    // Header fields - control flow and timing
    assert_eq!(
        baseline.global_clk, aot.global_clk,
        "Chunk {}: global_clk mismatch",
        chunk_idx
    );
    assert_eq!(
        baseline.current_batch, aot.current_batch,
        "Chunk {}: current_batch mismatch",
        chunk_idx
    );
    assert_eq!(
        baseline.current_chunk, aot.current_chunk,
        "Chunk {}: current_chunk mismatch",
        chunk_idx
    );

    assert_eq!(baseline.clk, aot.clk, "Chunk {}: clk mismatch", chunk_idx);
    assert_eq!(baseline.pc, aot.pc, "Chunk {}: pc mismatch", chunk_idx);

    // Input stream - must match exactly for syscall determinism
    assert_eq!(
        baseline.input_stream, aot.input_stream,
        "Chunk {}: input_stream mismatch",
        chunk_idx
    );
    assert_eq!(
        baseline.input_stream_ptr, aot.input_stream_ptr,
        "Chunk {}: input_stream_ptr mismatch",
        chunk_idx
    );

    // Public values stream - proving pipeline output
    assert_eq!(
        baseline.public_values_stream, aot.public_values_stream,
        "Chunk {}: public_values_stream mismatch",
        chunk_idx
    );

    // NOTE: syscall_counts is NOT compared here. This field is pure telemetry (never read
    // or used functionally), only incremented for debugging/profiling. Not part of the
    // correctness contract. See CLAUDE.md for details.

    // Memory comparison - registers and main memory
    if compare_accessed_memory {
        compare_memory(chunk_idx, baseline, aot);
    }

    // Uninitialized memory - affects HINT_READ behavior
    compare_uninitialized_memory(chunk_idx, baseline, aot);
}

/// Compares memory state including registers and main memory with full metadata.
/// This is critical for trace-mode compatibility.
fn compare_memory(chunk_idx: usize, baseline: &RiscvEmulationState, aot: &RiscvEmulationState) {
    // Compare register values and metadata from the snapshot contract.
    for i in 0..32 {
        let baseline_reg = baseline.registers[i];
        let aot_reg = aot.registers[i];

        if baseline_reg == Default::default() && aot_reg == Default::default() {
            continue;
        }

        assert_eq!(
            baseline_reg.value, aot_reg.value,
            "Chunk {}: register x{} value mismatch",
            chunk_idx, i
        );
        assert_eq!(
            baseline_reg.chunk, aot_reg.chunk,
            "Chunk {}: register x{} chunk mismatch",
            chunk_idx, i
        );
        assert_eq!(
            baseline_reg.timestamp, aot_reg.timestamp,
            "Chunk {}: register x{} timestamp mismatch",
            chunk_idx, i
        );
    }

    // Compare main memory (addr >= 128) without building large maps.
    for (addr, value, chunk, timestamp) in baseline.memory.iter_accessed_entries() {
        if addr < 32 {
            continue;
        }
        let baseline_rec = MemoryRecord {
            value,
            chunk,
            timestamp,
        };
        let aot_rec = aot.memory.get(addr);
        assert_eq!(
            baseline_rec.value, aot_rec.value,
            "Chunk {}: memory value mismatch at {:#x}",
            chunk_idx, addr
        );
        assert_eq!(
            baseline_rec.chunk, aot_rec.chunk,
            "Chunk {}: memory chunk mismatch at {:#x}",
            chunk_idx, addr
        );
        assert_eq!(
            baseline_rec.timestamp, aot_rec.timestamp,
            "Chunk {}: memory timestamp mismatch at {:#x}",
            chunk_idx, addr
        );
    }

    for (addr, value, chunk, timestamp) in aot.memory.iter_accessed_entries() {
        if addr < 32 {
            continue;
        }
        let aot_rec = MemoryRecord {
            value,
            chunk,
            timestamp,
        };
        let baseline_rec = baseline.memory.get(addr);
        assert_eq!(
            baseline_rec.value, aot_rec.value,
            "Chunk {}: extra memory in AOT at {:#x} (value)",
            chunk_idx, addr
        );
        assert_eq!(
            baseline_rec.chunk, aot_rec.chunk,
            "Chunk {}: extra memory in AOT at {:#x} (chunk)",
            chunk_idx, addr
        );
        assert_eq!(
            baseline_rec.timestamp, aot_rec.timestamp,
            "Chunk {}: extra memory in AOT at {:#x} (timestamp)",
            chunk_idx, addr
        );
    }
}

/// Compares uninitialized memory between baseline and AOT.
fn compare_uninitialized_memory(
    chunk_idx: usize,
    baseline: &RiscvEmulationState,
    aot: &RiscvEmulationState,
) {
    for i in 0..32 {
        let baseline_reg = baseline.uninitialized_memory.registers.get(i as u32);
        let aot_reg = aot.uninitialized_memory.registers.get(i as u32);
        assert_eq!(
            baseline_reg, aot_reg,
            "Chunk {}: uninitialized_memory register x{} mismatch",
            chunk_idx, i
        );
    }

    for addr in baseline.uninitialized_memory.page_table.keys() {
        let baseline_val = baseline.uninitialized_memory.page_table.get(addr).copied();
        let aot_val = aot.uninitialized_memory.page_table.get(addr).copied();
        assert_eq!(
            baseline_val, aot_val,
            "Chunk {}: uninitialized_memory mismatch at {:#x}",
            chunk_idx, addr
        );
    }

    for addr in aot.uninitialized_memory.page_table.keys() {
        let baseline_val = baseline.uninitialized_memory.page_table.get(addr).copied();
        let aot_val = aot.uninitialized_memory.page_table.get(addr).copied();
        assert_eq!(
            baseline_val, aot_val,
            "Chunk {}: uninitialized_memory extra entry at {:#x}",
            chunk_idx, addr
        );
    }
}

fn recycle_snapshot_memory(snapshot: RiscvEmulationState) {
    let RiscvEmulationState { memory, .. } = snapshot;
    let _ = GLOBAL_MEMORY_RECYCLER.send((memory, true));
}

/// Compares EmulationReport fields between baseline and AOT.
fn compare_reports(chunk_idx: usize, baseline: &EmulationReport, aot: &EmulationReport) {
    assert_eq!(
        baseline.current_cycle, aot.current_cycle,
        "Chunk {}: current_cycle mismatch",
        chunk_idx
    );
    assert_eq!(
        baseline.start_chunk, aot.start_chunk,
        "Chunk {}: start_chunk mismatch",
        chunk_idx
    );
    assert_eq!(
        baseline.done, aot.done,
        "Chunk {}: done flag mismatch",
        chunk_idx
    );

    // Note: cycle_tracker and host_cycle_estimator are implementation-specific
    // and not part of the correctness contract, so we don't compare them.
}

/// Runs baseline interpreter and AOT emulator together, comparing each chunk on the fly.
///
/// Bypasses `RiscvProver` / `ProvingWitness` to avoid chip `eval()` calls during
/// `MetaChip::new()` — some chips have pending u64 upgrade stubs that would panic.
fn run_and_compare_chunks(
    elf_bytes: &[u8],
    _validate_every_chunk: bool,
) -> ([u32; PV_DIGEST_NUM_WORDS], [u32; DIGEST_SIZE]) {
    use p3_koala_bear::KoalaBear;

    let opts = EmulatorOpts::test_opts();

    // Compile the ELF into a Program without creating a full prover (which would
    // trigger chip constraint compilation and hit pending todo!() stubs).
    let program =
        Compiler::new(SourceType::RISCV, elf_bytes)
            .expect("failed to parse RISC-V ELF")
            .compile();

    // Set up baseline emulator directly.
    let mut stdin_builder = EmulatorStdin::<Program, Vec<u8>>::new_builder::<RiscvKBSC>();
    stdin_builder.write(&INPUT_VALUE);
    let (stdin, _deferred_proof) = stdin_builder.finalize::<Program>();

    let mut baseline_emu =
        RiscvEmulator::new_single::<KoalaBear>(program.clone(), opts, None);
    baseline_emu.write_stdin(&stdin);

    // Set up AOT emulator.
    let mut stdin_builder = EmulatorStdin::<Program, Vec<u8>>::new_builder::<RiscvKBSC>();
    stdin_builder.write(&INPUT_VALUE);
    let (stdin, _) = stdin_builder.finalize::<Program>();
    let input_stream = stdin.inputs.to_vec();

    let mut aot_emu = FibonacciEmulator::new(program, input_stream);

    let mut chunk_idx = 0usize;

    loop {
        let (baseline_snapshot, baseline_report) = baseline_emu
            .emulate_state(true, &mut |_rec| {})
            .expect("baseline emulate_state failed");
        let (aot_snapshot, aot_report) = aot_emu
            .next_state_batch(opts)
            .expect("AOT next_state_batch failed");

        let compare_accessed_memory = true;
        compare_snapshots(
            chunk_idx,
            &baseline_snapshot,
            &aot_snapshot,
            compare_accessed_memory,
        );
        compare_reports(chunk_idx, &baseline_report, &aot_report);

        let done = baseline_report.done;
        recycle_snapshot_memory(baseline_snapshot);
        recycle_snapshot_memory(aot_snapshot);
        if done {
            break;
        }
        chunk_idx += 1;
    }

    let committed_digest = baseline_emu
        .record
        .public_values
        .committed_value_digest;
    let deferred_digest = baseline_emu
        .record
        .public_values
        .deferred_proofs_digest;

    assert_eq!(
        committed_digest, aot_emu.committed_value_digest,
        "Final committed_value_digest mismatch"
    );
    assert_eq!(
        deferred_digest, aot_emu.deferred_proofs_digest,
        "Final deferred_proofs_digest mismatch"
    );

    (committed_digest, deferred_digest)
}

#[test]
fn test_correctness() {
    let elf_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../perf/bench_data/rv64/fib-elf"
    );
    let elf_bytes = std::fs::read(elf_path).expect("Failed to read ELF file");

    println!("\n=== AOT Correctness Validation ===");

    let validate_every_chunk = std::env::var("AOT_VALIDATE_EACH_CHUNK")
        .ok()
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    run_and_compare_chunks(&elf_bytes, validate_every_chunk);

    println!("✓ All chunks validated successfully");
    println!("✓ Snapshots, memory records, and digests match exactly");
}
