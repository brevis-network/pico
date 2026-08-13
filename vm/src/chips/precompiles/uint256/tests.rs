//! Unit tests for the Uint256Mul chip.
//!
//! Uses **reth-elf** + **reth-23993050.bin** block data.
//! All tests are marked `#[ignore]` because the reth ELF is ~50 MB and emulation
//! is too slow for CI.

use crate::{
    chips::tests::{
        count_events, count_total_events, find_record_with_events, run_extra_records,
        test_rv64_emulate, test_rv64_prove_and_verify_chunk,
    },
    compiler::riscv::compiler::{Compiler, SourceType},
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{riscv::syscalls::SyscallCode, stdin::EmulatorStdin},
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::chip::MetaChip,
};
use p3_koala_bear::KoalaBear;
use std::sync::Arc;

use crate::compiler::riscv::program::Program;

// ──────────────────────────────────────────────────────────────
// Common helpers
// ──────────────────────────────────────────────────────────────

fn workspace_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("vm/ has a parent")
        .to_path_buf()
}

/// Load reth-elf and reth-23993050.bin, returning (program, stdin).
fn setup_reth_23993050() -> (Arc<Program>, EmulatorStdin<Program, Vec<u8>>) {
    let elf_path = workspace_root().join("perf/bench_data/rv64/reth-elf");
    let elf_bytes = std::fs::read(&elf_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", elf_path.display()));
    let compiler =
        Compiler::new(SourceType::RISCV, &elf_bytes).expect("failed to compile reth-elf");
    let program = compiler.compile();

    let input_path = workspace_root().join("perf/bench_data/rv64/reth-23993050.bin");
    let input_bytes = std::fs::read(&input_path)
        .unwrap_or_else(|e| panic!("failed to read {}: {e}", input_path.display()));

    let mut stdin = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    stdin.write_slice(&input_bytes);
    let (stdin, _) = stdin.finalize();
    (program, stdin)
}

// ══════════════════════════════════════════════════════════════
// reth-elf test suite (reth-23993050, ignored for CI)
// ══════════════════════════════════════════════════════════════

/// Run: cargo test --release -p pico-vm test_reth_uint256_mul_event_counts -- --ignored --nocapture
#[test]
#[ignore = "requires rv64 reth ELF + block inputs in perf/bench_data/rv64/"]
fn test_reth_uint256_mul_event_counts() {
    let (program, stdin) = setup_reth_23993050();
    let all_records = test_rv64_emulate(program, stdin);

    let total_mul = count_total_events(&all_records, SyscallCode::UINT256_MUL);

    println!("Total UINT256_MUL events: {}", total_mul);
    assert!(
        total_mul > 0,
        "reth-23993050 must produce UINT256_MUL events"
    );
}

/// Run: cargo test --release -p pico-vm test_reth_uint256_mul_prove_verify -- --ignored --nocapture
#[test]
#[ignore = "requires rv64 reth ELF + block inputs in perf/bench_data/rv64/"]
fn test_reth_uint256_mul_prove_verify() {
    let (program, stdin) = setup_reth_23993050();
    let all_records = test_rv64_emulate(program.clone(), stdin);
    let mut record = find_record_with_events(all_records, SyscallCode::UINT256_MUL);

    let count = count_events(&record, SyscallCode::UINT256_MUL);
    assert!(count > 0, "Should have UINT256_MUL events");
    println!("UINT256_MUL events: {}", count);

    let chips = vec![
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Program(Default::default())),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::U256Mul(Default::default())),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::MemoryLocal(Default::default())),
    ];

    run_extra_records(&chips, &mut record);
    test_rv64_prove_and_verify_chunk(program, chips, record);
}

#[test]
fn test_uint256_mul_chip_simple_eval() {
    use super::Uint256MulChip;
    use crate::machine::{
        builder::PublicValuesBuilder, chip::ChipBehavior, folder::SymbolicConstraintFolder,
    };
    use p3_air::{Air, BaseAir};
    use p3_koala_bear::KoalaBear;

    let chip: Uint256MulChip<KoalaBear> = Uint256MulChip::default();
    let (preprocessed_width, width) = (chip.preprocessed_width(), chip.width());
    let mut builder = SymbolicConstraintFolder::new(preprocessed_width, width);
    chip.eval(&mut builder);

    assert_eq!(builder.num_constraints(), 270);
    assert_eq!(builder.public_values().len(), 119);
    assert_eq!(builder.num_lookups(), 237);
}
