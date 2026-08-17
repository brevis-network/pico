//! Unit tests for the Weierstrass Add/Double/Decompress chips.
//!
//! Three test suites:
//! - **k256-elf**: Small ELF for CI. Uses hardcoded ecdsa parameters (no stdin).
//! - **bls12381-elf**: CI-friendly ELF for BLS12-381 add/double/decompress.
//! - **bn254-elf**: CI-friendly ELF for BN254 add/double.

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

// ══════════════════════════════════════════════════════════════
// k256-elf test suite (CI-friendly, small ELF)
// ══════════════════════════════════════════════════════════════

const K256_ELF: &[u8] = include_bytes!("../../../../../perf/bench_data/rv64/k256-elf");

/// Compile k256-elf and return (program, empty stdin).
fn setup_k256() -> (Arc<Program>, EmulatorStdin<Program, Vec<u8>>) {
    let compiler = Compiler::new(SourceType::RISCV, K256_ELF).expect("failed to compile k256-elf");
    let program = compiler.compile();
    let stdin_builder = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    let (stdin, _) = stdin_builder.finalize();
    (program, stdin)
}

#[test]
fn test_k256_secp256k1_add_prove_verify() {
    let (program, stdin) = setup_k256();
    let all_records = test_rv64_emulate(program.clone(), stdin);
    let mut record = find_record_with_events(all_records, SyscallCode::SECP256K1_ADD);

    let count = count_events(&record, SyscallCode::SECP256K1_ADD);
    assert!(count > 0, "Should have SECP256K1_ADD events");
    println!("SECP256K1_ADD events: {}", count);

    let chips = vec![
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Program(Default::default())),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::WsSecp256k1Add(
            Default::default(),
        )),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::MemoryLocal(Default::default())),
    ];

    run_extra_records(&chips, &mut record);
    test_rv64_prove_and_verify_chunk(program, chips, record);
}

#[test]
fn test_k256_secp256k1_double_prove_verify() {
    let (program, stdin) = setup_k256();
    let all_records = test_rv64_emulate(program.clone(), stdin);
    let mut record = find_record_with_events(all_records, SyscallCode::SECP256K1_DOUBLE);

    let count = count_events(&record, SyscallCode::SECP256K1_DOUBLE);
    assert!(count > 0, "Should have SECP256K1_DOUBLE events");
    println!("SECP256K1_DOUBLE events: {}", count);

    let chips = vec![
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Program(Default::default())),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::WsDoubleSecp256k1(
            Default::default(),
        )),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::MemoryLocal(Default::default())),
    ];

    run_extra_records(&chips, &mut record);
    test_rv64_prove_and_verify_chunk(program, chips, record);
}

// NOTE: k256-elf (ecdsa-core ecrecover) does NOT produce SECP256K1_DECOMPRESS events.
#[test]
fn test_k256_secp256k1_event_counts() {
    let (program, stdin) = setup_k256();
    let all_records = test_rv64_emulate(program, stdin);

    let total_add = count_total_events(&all_records, SyscallCode::SECP256K1_ADD);
    let total_double = count_total_events(&all_records, SyscallCode::SECP256K1_DOUBLE);
    let total_decompress = count_total_events(&all_records, SyscallCode::SECP256K1_DECOMPRESS);

    println!("Total SECP256K1_ADD events: {}", total_add);
    println!("Total SECP256K1_DOUBLE events: {}", total_double);
    println!("Total SECP256K1_DECOMPRESS events: {}", total_decompress);

    assert!(total_add > 0, "ecdsa recovery must use secp256k1 add");
    assert!(total_double > 0, "ecdsa recovery must use secp256k1 double");
    // NOTE: k256-elf ecrecover does NOT produce decompress events.
    // Decompress is verified via reth-elf tests.
    println!(
        "(decompress events = {} — expected 0 for k256-elf)",
        total_decompress
    );
}

// ══════════════════════════════════════════════════════════════
// bls12381-elf test suite (CI-friendly, includes add/double/decompress)
// ══════════════════════════════════════════════════════════════

const BLS12381_ELF: &[u8] =
    include_bytes!("../../../../../perf/bench_data/rv64/bls12381-elf-ws-add-double-decompress");

/// Compile bls12381-elf and return (program, empty stdin).
fn setup_bls12381() -> (Arc<Program>, EmulatorStdin<Program, Vec<u8>>) {
    let compiler =
        Compiler::new(SourceType::RISCV, BLS12381_ELF).expect("failed to compile bls12381-elf");
    let program = compiler.compile();
    let stdin_builder = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    let (stdin, _) = stdin_builder.finalize();
    (program, stdin)
}

#[test]
fn test_bls12381_event_counts() {
    let (program, stdin) = setup_bls12381();
    let all_records = test_rv64_emulate(program, stdin);

    let total_add = count_total_events(&all_records, SyscallCode::BLS12381_ADD);
    let total_double = count_total_events(&all_records, SyscallCode::BLS12381_DOUBLE);
    let total_decompress = count_total_events(&all_records, SyscallCode::BLS12381_DECOMPRESS);

    println!("Total BLS12381_ADD events: {}", total_add);
    println!("Total BLS12381_DOUBLE events: {}", total_double);
    println!("Total BLS12381_DECOMPRESS events: {}", total_decompress);

    assert!(
        total_add > 0,
        "bls12381-elf must produce BLS12381_ADD events"
    );
    assert!(
        total_double > 0,
        "bls12381-elf must produce BLS12381_DOUBLE events"
    );
    assert!(
        total_decompress > 0,
        "bls12381-elf must produce BLS12381_DECOMPRESS events"
    );
}

#[test]
fn test_bls12381_add_prove_verify() {
    let (program, stdin) = setup_bls12381();
    let all_records = test_rv64_emulate(program.clone(), stdin);
    let mut record = find_record_with_events(all_records, SyscallCode::BLS12381_ADD);

    let count = count_events(&record, SyscallCode::BLS12381_ADD);
    assert!(count > 0, "Should have BLS12381_ADD events");
    println!("BLS12381_ADD events: {}", count);

    let chips = vec![
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Program(Default::default())),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::WsBls381Add(Default::default())),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::MemoryLocal(Default::default())),
    ];

    run_extra_records(&chips, &mut record);
    test_rv64_prove_and_verify_chunk(program, chips, record);
}

#[test]
fn test_bls12381_double_prove_verify() {
    let (program, stdin) = setup_bls12381();
    let all_records = test_rv64_emulate(program.clone(), stdin);
    let mut record = find_record_with_events(all_records, SyscallCode::BLS12381_DOUBLE);

    let count = count_events(&record, SyscallCode::BLS12381_DOUBLE);
    assert!(count > 0, "Should have BLS12381_DOUBLE events");
    println!("BLS12381_DOUBLE events: {}", count);

    let chips = vec![
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Program(Default::default())),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::WsDoubleBls381(
            Default::default(),
        )),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::MemoryLocal(Default::default())),
    ];

    run_extra_records(&chips, &mut record);
    test_rv64_prove_and_verify_chunk(program, chips, record);
}

#[test]
fn test_bls12381_decompress_prove_verify() {
    let (program, stdin) = setup_bls12381();
    let all_records = test_rv64_emulate(program.clone(), stdin);
    let mut record = find_record_with_events(all_records, SyscallCode::BLS12381_DECOMPRESS);

    let count = count_events(&record, SyscallCode::BLS12381_DECOMPRESS);
    assert!(count > 0, "Should have BLS12381_DECOMPRESS events");
    println!("BLS12381_DECOMPRESS events: {}", count);

    let chips = vec![
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Program(Default::default())),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::WsDecompressBls381(
            Default::default(),
        )),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::MemoryLocal(Default::default())),
    ];

    run_extra_records(&chips, &mut record);
    test_rv64_prove_and_verify_chunk(program, chips, record);
}

// ══════════════════════════════════════════════════════════════
// bn254-elf test suite (substrate-bn, add + double)
// ══════════════════════════════════════════════════════════════

const BN254_ELF: &[u8] =
    include_bytes!("../../../../../perf/bench_data/rv64/bn254-elf-ws-add-double");

/// Compile bn254-elf and return (program, empty stdin).
fn setup_bn254() -> (Arc<Program>, EmulatorStdin<Program, Vec<u8>>) {
    let compiler =
        Compiler::new(SourceType::RISCV, BN254_ELF).expect("failed to compile bn254-elf");
    let program = compiler.compile();
    let stdin_builder = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    let (stdin, _) = stdin_builder.finalize();
    (program, stdin)
}

#[test]
fn test_bn254_event_counts() {
    let (program, stdin) = setup_bn254();
    let all_records = test_rv64_emulate(program, stdin);

    let total_add = count_total_events(&all_records, SyscallCode::BN254_ADD);
    let total_double = count_total_events(&all_records, SyscallCode::BN254_DOUBLE);

    println!("Total BN254_ADD events: {}", total_add);
    println!("Total BN254_DOUBLE events: {}", total_double);

    assert!(total_add > 0, "bn254-elf must produce BN254_ADD events");
    assert!(
        total_double > 0,
        "bn254-elf must produce BN254_DOUBLE events"
    );
}

#[test]
fn test_bn254_add_prove_verify() {
    let (program, stdin) = setup_bn254();
    let all_records = test_rv64_emulate(program.clone(), stdin);
    let mut record = find_record_with_events(all_records, SyscallCode::BN254_ADD);

    let count = count_events(&record, SyscallCode::BN254_ADD);
    assert!(count > 0, "Should have BN254_ADD events");
    println!("BN254_ADD events: {}", count);

    let chips = vec![
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Program(Default::default())),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::WsBn254Add(Default::default())),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::MemoryLocal(Default::default())),
    ];

    run_extra_records(&chips, &mut record);
    test_rv64_prove_and_verify_chunk(program, chips, record);
}

#[test]
fn test_bn254_double_prove_verify() {
    let (program, stdin) = setup_bn254();
    let all_records = test_rv64_emulate(program.clone(), stdin);
    let mut record = find_record_with_events(all_records, SyscallCode::BN254_DOUBLE);

    let count = count_events(&record, SyscallCode::BN254_DOUBLE);
    assert!(count > 0, "Should have BN254_DOUBLE events");
    println!("BN254_DOUBLE events: {}", count);

    let chips = vec![
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Program(Default::default())),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::WsDoubleBn254(Default::default())),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::MemoryLocal(Default::default())),
    ];

    run_extra_records(&chips, &mut record);
    test_rv64_prove_and_verify_chunk(program, chips, record);
}

#[test]
fn test_ws_secp256k1_add_chip_simple_eval() {
    use super::weierstrass_add::WeierstrassAddAssignChip;
    use crate::{
        chips::gadgets::curves::weierstrass::Secp256k1,
        machine::{
            builder::PublicValuesBuilder, chip::ChipBehavior, folder::SymbolicConstraintFolder,
        },
    };
    use p3_air::{Air, BaseAir};
    use p3_koala_bear::KoalaBear;

    let chip: WeierstrassAddAssignChip<KoalaBear, Secp256k1> = WeierstrassAddAssignChip::default();
    let (preprocessed_width, width) = (chip.preprocessed_width(), chip.width());
    let mut builder = SymbolicConstraintFolder::new(preprocessed_width, width);
    chip.eval(&mut builder);

    assert_eq!(builder.num_constraints(), 950);
    assert_eq!(builder.public_values().len(), 119);
    assert_eq!(builder.num_lookups(), 1127);
}

#[test]
fn test_ws_secp256k1_double_chip_simple_eval() {
    use super::weierstrass_double::WeierstrassDoubleAssignChip;
    use crate::{
        chips::gadgets::curves::weierstrass::Secp256k1,
        machine::{
            builder::PublicValuesBuilder, chip::ChipBehavior, folder::SymbolicConstraintFolder,
        },
    };
    use p3_air::{Air, BaseAir};
    use p3_koala_bear::KoalaBear;

    let chip: WeierstrassDoubleAssignChip<KoalaBear, Secp256k1> =
        WeierstrassDoubleAssignChip::default();
    let (preprocessed_width, width) = (chip.preprocessed_width(), chip.width());
    let mut builder = SymbolicConstraintFolder::new(preprocessed_width, width);
    chip.eval(&mut builder);

    assert_eq!(builder.num_constraints(), 999);
    assert_eq!(builder.public_values().len(), 119);
    assert_eq!(builder.num_lookups(), 1223);
}

#[test]
fn test_ws_secp256k1_decompress_chip_simple_eval() {
    use super::weierstrass_decompress::WeierstrassDecompressChip;
    use crate::{
        chips::gadgets::curves::weierstrass::Secp256k1,
        machine::{
            builder::PublicValuesBuilder, chip::ChipBehavior, folder::SymbolicConstraintFolder,
        },
    };
    use p3_air::{Air, BaseAir};
    use p3_koala_bear::KoalaBear;

    let chip: WeierstrassDecompressChip<KoalaBear, Secp256k1> =
        WeierstrassDecompressChip::default();
    let (preprocessed_width, width) = (chip.preprocessed_width(), chip.width());
    let mut builder = SymbolicConstraintFolder::new(preprocessed_width, width);
    chip.eval(&mut builder);

    assert_eq!(builder.num_constraints(), 691);
    assert_eq!(builder.public_values().len(), 119);
    assert_eq!(builder.num_lookups(), 677);
}

#[test]
fn test_ws_bls12381_add_chip_simple_eval() {
    use super::weierstrass_add::WeierstrassAddAssignChip;
    use crate::{
        chips::gadgets::curves::weierstrass::Bls12381,
        machine::{
            builder::PublicValuesBuilder, chip::ChipBehavior, folder::SymbolicConstraintFolder,
        },
    };
    use p3_air::{Air, BaseAir};
    use p3_koala_bear::KoalaBear;

    let chip: WeierstrassAddAssignChip<KoalaBear, Bls12381> = WeierstrassAddAssignChip::default();
    let (preprocessed_width, width) = (chip.preprocessed_width(), chip.width());
    let mut builder = SymbolicConstraintFolder::new(preprocessed_width, width);
    chip.eval(&mut builder);

    assert_eq!(builder.num_constraints(), 1422);
    assert_eq!(builder.public_values().len(), 119);
    assert_eq!(builder.num_lookups(), 1695);
}

#[test]
fn test_ws_bn254_add_chip_simple_eval() {
    use super::weierstrass_add::WeierstrassAddAssignChip;
    use crate::{
        chips::gadgets::curves::weierstrass::Bn254,
        machine::{
            builder::PublicValuesBuilder, chip::ChipBehavior, folder::SymbolicConstraintFolder,
        },
    };
    use p3_air::{Air, BaseAir};
    use p3_koala_bear::KoalaBear;

    let chip: WeierstrassAddAssignChip<KoalaBear, Bn254> = WeierstrassAddAssignChip::default();
    let (preprocessed_width, width) = (chip.preprocessed_width(), chip.width());
    let mut builder = SymbolicConstraintFolder::new(preprocessed_width, width);
    chip.eval(&mut builder);

    assert_eq!(builder.num_constraints(), 950);
    assert_eq!(builder.public_values().len(), 119);
    assert_eq!(builder.num_lookups(), 1127);
}
