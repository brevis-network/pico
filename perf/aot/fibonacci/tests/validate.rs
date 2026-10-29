//! Validation test comparing AOT emulator against baseline interpreter.
//! Compares snapshots and memory images for every chunk to ensure identical outputs.
//! Phase 0 intentionally repoints this harness to the existing RV64 Fibonacci
//! benchmark ELF so the validation gate reflects the real migration target,
//! even before the AOT stack is widened enough to pass.

use aot::AotEmulatorCore;
use aot_common::{compare_reports, compare_snapshots, recycle_snapshot_memory, AotRun};
use pico_vm::{
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    configs::stark_config::KoalaBearPoseidon2 as RiscvKBSC,
    emulator::{
        opts::EmulatorOpts,
        riscv::{
            cpu_event_pool::{init_cpu_event_buffer_pool, is_pool_initialized},
            emulator::RiscvEmulator,
            event_pool::HostAllocFlags,
            public_values::RecordFinalPvsState,
        },
        stdin::EmulatorStdin,
    },
    primitives::consts::{DIGEST_SIZE, PV_DIGEST_NUM_WORDS},
};
use std::sync::Arc;

const INPUT_VALUE: u32 = 10_000_000u32;
/// Runs baseline interpreter and AOT emulator together, comparing each chunk on the fly.
///
/// Bypasses `RiscvProver` / `ProvingWitness` to avoid chip `eval()` calls during
/// `MetaChip::new()` — some chips have pending u64 upgrade stubs that would panic.
fn run_and_compare_chunks(
    elf_bytes: &[u8],
    _validate_every_chunk: bool,
) -> ([u32; PV_DIGEST_NUM_WORDS], [u32; DIGEST_SIZE]) {
    use p3_koala_bear::KoalaBear;

    if !is_pool_initialized() {
        init_cpu_event_buffer_pool(50, HostAllocFlags::DEFAULT);
    }

    let opts = EmulatorOpts::test_opts();

    // Compile the ELF into a Program without creating a full prover (which would
    // trigger chip constraint compilation and hit pending todo!() stubs).
    let program = Compiler::new(SourceType::RISCV, elf_bytes)
        .expect("failed to parse RISC-V ELF")
        .compile();

    // Set up baseline emulator directly.
    let mut stdin_builder = EmulatorStdin::<Program, Vec<u8>>::new_builder::<RiscvKBSC>();
    stdin_builder.write(&INPUT_VALUE);
    let stdin = stdin_builder.finalize::<Program>();

    let mut baseline_emu = RiscvEmulator::new_single::<KoalaBear>(
        program.clone(),
        Arc::new(RecordFinalPvsState::default()),
        opts,
        None,
    );
    baseline_emu.write_stdin(&stdin);

    // Set up AOT emulator.
    let mut stdin_builder = EmulatorStdin::<Program, Vec<u8>>::new_builder::<RiscvKBSC>();
    stdin_builder.write(&INPUT_VALUE);
    let stdin = stdin_builder.finalize::<Program>();
    let input_stream = stdin.inputs.to_vec();

    let mut aot_emu = AotEmulatorCore::new(program, input_stream);

    let mut chunk_idx = 0usize;

    loop {
        let (baseline_snapshot, baseline_report) = baseline_emu
            .emulate_state(true, &mut |_rec| {})
            .expect("baseline emulate_state failed");
        // NOTE: caller must recycle returned snapshot memory.
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

    let committed_digest = baseline_emu.record.public_values.committed_value_digest;
    let deferred_digest = baseline_emu.record.public_values.deferred_proofs_digest;

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
