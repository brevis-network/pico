//! Unit tests for the Memory module chips (MemoryReadWrite + MemoryLocal).
//!
//! These tests reuse `chips::tests::run_test` which includes both MemoryReadWrite
//! and MemoryLocal in the chip set, so every test here exercises both chips.

use crate::{
    chips::tests::{run_test, test_rv64_prove_and_verify},
    compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
};

// ──────────────────────────────────────────────────────────────
// Test 1: SD + LD (64-bit store / load)
// ──────────────────────────────────────────────────────────────

#[test]
fn test_rv64_sd_ld() {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, 0x20000, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 0xDEAD_BEEF_CAFE_BABE_u64, false, true),
        Instruction::new(Opcode::SD, 11, 10, 0, false, true),
        Instruction::new(Opcode::LD, 12, 10, 0, false, true),
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    run_test(Program::new(instructions, 0x10000, 0x10000), "sd_ld");
}

// ──────────────────────────────────────────────────────────────
// Test 2: SW + LW + LWU (32-bit store, signed/unsigned word loads)
// ──────────────────────────────────────────────────────────────

#[test]
fn test_rv64_sw_lw_lwu() {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, 0x20000, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 0x8000_1234_u64, false, true),
        Instruction::new(Opcode::SD, 0, 10, 0, false, true),
        Instruction::new(Opcode::SW, 11, 10, 0, false, true),
        Instruction::new(Opcode::LW, 12, 10, 0, false, true),
        Instruction::new(Opcode::LWU, 13, 10, 0, false, true),
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    run_test(Program::new(instructions, 0x10000, 0x10000), "sw_lw_lwu");
}

// ──────────────────────────────────────────────────────────────
// Test 3: SH + LH + LHU (16-bit store, signed/unsigned halfword)
// ──────────────────────────────────────────────────────────────

#[test]
fn test_rv64_sh_lh_lhu() {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, 0x20000, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 0xF123_u64, false, true),
        Instruction::new(Opcode::SD, 0, 10, 0, false, true),
        Instruction::new(Opcode::SH, 11, 10, 0, false, true),
        Instruction::new(Opcode::LH, 12, 10, 0, false, true),
        Instruction::new(Opcode::LHU, 13, 10, 0, false, true),
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    run_test(Program::new(instructions, 0x10000, 0x10000), "sh_lh_lhu");
}

// ──────────────────────────────────────────────────────────────
// Test 4: SB + LB + LBU (8-bit store, signed/unsigned byte)
// ──────────────────────────────────────────────────────────────

#[test]
fn test_rv64_sb_lb_lbu() {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, 0x20000, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 0xAB_u64, false, true),
        Instruction::new(Opcode::SD, 0, 10, 0, false, true),
        Instruction::new(Opcode::SB, 11, 10, 0, false, true),
        Instruction::new(Opcode::LB, 12, 10, 0, false, true),
        Instruction::new(Opcode::LBU, 13, 10, 0, false, true),
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    run_test(Program::new(instructions, 0x10000, 0x10000), "sb_lb_lbu");
}

// ──────────────────────────────────────────────────────────────
// Test 5: Chained mixed load/store with non-zero offsets
// ──────────────────────────────────────────────────────────────

#[test]
fn test_rv64_memory_chained() {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, 0x20000, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 42, false, true),
        Instruction::new(Opcode::SD, 11, 10, 0, false, true),
        Instruction::new(Opcode::LD, 12, 10, 0, false, true),
        Instruction::new(Opcode::SD, 0, 10, 8, false, true),
        Instruction::new(Opcode::SW, 12, 10, 8, false, true),
        Instruction::new(Opcode::LW, 13, 10, 8, false, true),
        Instruction::new(Opcode::SB, 11, 10, 1, false, true),
        Instruction::new(Opcode::LBU, 14, 10, 1, false, true),
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    run_test(
        Program::new(instructions, 0x10000, 0x10000),
        "memory_chained",
    );
}

// ──────────────────────────────────────────────────────────────
// Test 6: ELF integration — fib-elf (first record: regular chips)
// ──────────────────────────────────────────────────────────────

const FIB_ELF: &[u8] = include_bytes!("../../../../../perf/bench_data/rv64/fib-elf");

#[test]
fn test_rv64_memory_with_elf() {
    use crate::{
        compiler::riscv::compiler::{Compiler, SourceType},
        configs::stark_config::KoalaBearPoseidon2,
        emulator::stdin::EmulatorStdin,
        instances::chiptype::riscv_chiptype::RiscvChipType,
        machine::chip::MetaChip,
    };
    use p3_koala_bear::KoalaBear;

    let compiler = Compiler::new(SourceType::RISCV, FIB_ELF).expect("failed to create compiler");
    let program = compiler.compile();

    let mut stdin_builder = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    stdin_builder.write(&10u64);
    let (stdin, _proofs) = stdin_builder.finalize();

    let chips = vec![
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Program(Default::default())),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Add(Default::default())),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Sub(Default::default())),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Addw(Default::default())),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Subw(Default::default())),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::DivRem(Default::default())),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::MemoryReadWrite(
            Default::default(),
        )),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::MemoryLocal(Default::default())),
    ];

    test_rv64_prove_and_verify(program, stdin, chips);
}

// ──────────────────────────────────────────────────────────────
// Test 7: ELF integration — fib-elf (last record: MemoryInitFinalize + Global)
// ──────────────────────────────────────────────────────────────

#[test]
fn test_rv64_memory_init_finalize_with_elf() {
    use crate::{
        chips::{
            chips::riscv_memory::initialize_finalize::{
                MemoryChipType, MemoryInitializeFinalizeChip,
            },
            tests::{run_extra_records, test_rv64_emulate, test_rv64_prove_and_verify_chunk},
        },
        compiler::riscv::compiler::{Compiler, SourceType},
        configs::stark_config::KoalaBearPoseidon2,
        emulator::stdin::EmulatorStdin,
        instances::chiptype::riscv_chiptype::RiscvChipType,
        machine::chip::MetaChip,
    };
    use p3_koala_bear::KoalaBear;

    let compiler = Compiler::new(SourceType::RISCV, FIB_ELF).expect("failed to create compiler");
    let program = compiler.compile();

    let mut stdin_builder = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    stdin_builder.write(&10u64);
    let (stdin, _proofs) = stdin_builder.finalize();

    let all_records = test_rv64_emulate(program.clone(), stdin);
    assert!(
        all_records.len() > 1,
        "Expected multiple records; last record should contain init/finalize events"
    );

    let mut record = all_records.last().cloned().unwrap();
    println!(
        "Last record: init events = {}, finalize events = {}",
        record.memory_initialize_events.len(),
        record.memory_finalize_events.len(),
    );
    assert!(
        !record.memory_initialize_events.is_empty(),
        "Last record should contain memory initialize events"
    );

    // Chips for MemoryInitFinalize test.
    // Program chip is needed as a preprocessed chip.
    // NOTE: GlobalChip cannot be tested with test_no_lookup because
    // MemoryInitFinalize's eval sends global-scope lookups that create
    // a non-zero cumulative sum which test_no_lookup cannot balance.
    let chips = vec![
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Program(Default::default())),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::MemoryInitialize(
            MemoryInitializeFinalizeChip::new(MemoryChipType::Initialize),
        )),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::MemoryFinalize(
            MemoryInitializeFinalizeChip::new(MemoryChipType::Finalize),
        )),
    ];

    // Chain extra_record to populate global_lookup_events from MemoryInitFinalize.
    run_extra_records(&chips, &mut record);
    println!(
        "After extra_record: global events = {}",
        record.global_lookup_events.len(),
    );

    test_rv64_prove_and_verify_chunk(program, chips, record);
}

// ──────────────────────────────────────────────────────────────
// Test 8: Load into x0 (exercises op_a_0 = 1 path)
// ──────────────────────────────────────────────────────────────

#[test]
fn test_rv64_load_to_x0() {
    // Store a negative-MSB byte, then load into x0 — exercises op_a_0=1 path.
    // LB 0xAB into x0: op_a_0=1, msb=1, but mem_value_is_neg_not_x0=0
    // LBU 0xAB into x0: op_a_0=1, msb=0, mem_value_is_pos_not_x0=0
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, 0x20000, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 0xAB_u64, false, true),
        Instruction::new(Opcode::SD, 0, 10, 0, false, true), // zero-init memory
        Instruction::new(Opcode::SB, 11, 10, 0, false, true), // store byte 0xAB
        Instruction::new(Opcode::LB, 0, 10, 0, false, true), // LB into x0 (signed, MSB=1)
        Instruction::new(Opcode::LBU, 0, 10, 0, false, true), // LBU into x0 (unsigned)
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    run_test(Program::new(instructions, 0x10000, 0x10000), "load_to_x0");
}

// ──────────────────────────────────────────────────────────────
// Test 9: SW/SH at non-zero offsets (upper-half writes)
// ──────────────────────────────────────────────────────────────

#[test]
fn test_rv64_store_upper_half() {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, 0x20000, false, true), // base addr (8-byte aligned)
        // SD to zero-init 8 bytes at base
        Instruction::new(Opcode::SD, 0, 10, 0, false, true),
        // SW at offset 4 → bit2=1, writes to upper 32-bit half
        Instruction::new(Opcode::ADD, 11, 0, 0xCAFE_BABE_u64, false, true),
        Instruction::new(Opcode::SW, 11, 10, 4, false, true),
        // LWU at offset 4 → should read back 0xCAFE_BABE
        Instruction::new(Opcode::LWU, 12, 10, 4, false, true),
        // SH at offset 2 → bit1=1, writes to limb[1] of the low 32-bit half
        Instruction::new(Opcode::ADD, 13, 0, 0x1234_u64, false, true),
        Instruction::new(Opcode::SH, 13, 10, 2, false, true),
        // LHU at offset 2 → should read back 0x1234
        Instruction::new(Opcode::LHU, 14, 10, 2, false, true),
        // SH at offset 6 → bit1=1, bit2=1, writes to limb[3]
        Instruction::new(Opcode::ADD, 15, 0, 0x5678_u64, false, true),
        Instruction::new(Opcode::SH, 15, 10, 6, false, true),
        Instruction::new(Opcode::LHU, 16, 10, 6, false, true),
        // cleanup
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    run_test(
        Program::new(instructions, 0x10000, 0x10000),
        "store_upper_half",
    );
}

// ──────────────────────────────────────────────────────────────
// Test 10: High address (both addr[0] and addr[1] non-zero)
// ──────────────────────────────────────────────────────────────

#[test]
fn test_rv64_large_address() {
    // Address 0x7000_0100: addr[0]=0x0100, addr[1]=0x7000
    // Stack guard: addr_top_two_limb_inv = 1/0x7000
    // (Emulator limits to VALUES_SIZE=0x7800_0000, so addr[2] is always 0.
    //  This test exercises addr[1] being large and addr[0] being non-zero.)
    let high_addr = 0x7000_0100_u64;
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, high_addr, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 0xDEAD_BEEF_u64, false, true),
        Instruction::new(Opcode::SD, 11, 10, 0, false, true),
        Instruction::new(Opcode::LD, 12, 10, 0, false, true),
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    run_test(
        Program::new(instructions, 0x10000, 0x10000),
        "large_address",
    );
}

// ──────────────────────────────────────────────────────────────
// Test 11: MemoryInitFinalize — PV connection assertions (IF8, IF11)
// ──────────────────────────────────────────────────────────────

#[test]
fn test_rv64_init_finalize_pv_connection() {
    use crate::{
        chips::{
            chips::riscv_memory::initialize_finalize::{
                MemoryChipType, MemoryInitializeFinalizeChip,
            },
            tests::{run_extra_records, test_rv64_emulate, test_rv64_prove_and_verify_chunk},
        },
        compiler::riscv::compiler::{Compiler, SourceType},
        configs::stark_config::KoalaBearPoseidon2,
        emulator::stdin::EmulatorStdin,
        instances::chiptype::riscv_chiptype::RiscvChipType,
        machine::chip::MetaChip,
    };
    use p3_koala_bear::KoalaBear;

    let compiler = Compiler::new(SourceType::RISCV, FIB_ELF).expect("failed to create compiler");
    let program = compiler.compile();

    let mut stdin_builder = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    stdin_builder.write(&10u64);
    let (stdin, _proofs) = stdin_builder.finalize();

    let all_records = test_rv64_emulate(program.clone(), stdin);
    assert!(
        all_records.len() > 1,
        "Expected multiple records; last record should contain init/finalize events"
    );

    let mut record = all_records.last().cloned().unwrap();

    // ── Verify PV ↔ event address relationship for Initialize ──
    let mut sorted_init: Vec<_> = record.memory_initialize_events.clone();
    sorted_init.sort_by_key(|e| e.addr);

    let pv_prev_init: u64 = (record.public_values.previous_init_addr_limbs[0] as u64)
        | ((record.public_values.previous_init_addr_limbs[1] as u64) << 16)
        | ((record.public_values.previous_init_addr_limbs[2] as u64) << 32);
    let pv_last_init: u64 = (record.public_values.last_init_addr_limbs[0] as u64)
        | ((record.public_values.last_init_addr_limbs[1] as u64) << 16)
        | ((record.public_values.last_init_addr_limbs[2] as u64) << 32);

    println!("PV previous_init_addr: 0x{:x}", pv_prev_init);
    println!(
        "First init event addr: 0x{:x}",
        sorted_init.first().unwrap().addr
    );
    println!(
        "Last init event addr:  0x{:x}",
        sorted_init.last().unwrap().addr
    );
    println!("PV last_init_addr:     0x{:x}", pv_last_init);

    // IF8: first event addr must be > pv_prev_init (or == 0 if pv_prev_init == 0)
    if pv_prev_init == 0 {
        assert_eq!(
            sorted_init.first().unwrap().addr,
            0,
            "When PV prev_addr=0, first event addr must be 0 (x0)"
        );
    } else {
        assert!(
            sorted_init.first().unwrap().addr > pv_prev_init,
            "First init event addr must be > PV prev_addr"
        );
    }
    // IF11: last event addr must == pv_last_init
    assert_eq!(
        sorted_init.last().unwrap().addr,
        pv_last_init,
        "Last init event addr must match PV last_init_addr"
    );

    // ── Verify PV ↔ event address relationship for Finalize ──
    let mut sorted_fin: Vec<_> = record.memory_finalize_events.clone();
    sorted_fin.sort_by_key(|e| e.addr);

    let pv_prev_fin: u64 = (record.public_values.previous_finalize_addr_limbs[0] as u64)
        | ((record.public_values.previous_finalize_addr_limbs[1] as u64) << 16)
        | ((record.public_values.previous_finalize_addr_limbs[2] as u64) << 32);
    let pv_last_fin: u64 = (record.public_values.last_finalize_addr_limbs[0] as u64)
        | ((record.public_values.last_finalize_addr_limbs[1] as u64) << 16)
        | ((record.public_values.last_finalize_addr_limbs[2] as u64) << 32);

    println!("PV previous_finalize_addr: 0x{:x}", pv_prev_fin);
    println!(
        "First finalize event addr: 0x{:x}",
        sorted_fin.first().unwrap().addr
    );
    println!(
        "Last finalize event addr:  0x{:x}",
        sorted_fin.last().unwrap().addr
    );
    println!("PV last_finalize_addr:     0x{:x}", pv_last_fin);

    if pv_prev_fin == 0 {
        assert_eq!(
            sorted_fin.first().unwrap().addr,
            0,
            "When PV prev_finalize_addr=0, first event addr must be 0 (x0)"
        );
    } else {
        assert!(
            sorted_fin.first().unwrap().addr > pv_prev_fin,
            "First finalize event addr must be > PV prev_finalize_addr"
        );
    }
    assert_eq!(
        sorted_fin.last().unwrap().addr,
        pv_last_fin,
        "Last finalize event addr must match PV last_finalize_addr"
    );

    // prove+verify
    let chips = vec![
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Program(Default::default())),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::MemoryInitialize(
            MemoryInitializeFinalizeChip::new(MemoryChipType::Initialize),
        )),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::MemoryFinalize(
            MemoryInitializeFinalizeChip::new(MemoryChipType::Finalize),
        )),
    ];

    run_extra_records(&chips, &mut record);
    test_rv64_prove_and_verify_chunk(program, chips, record);
}

// ──────────────────────────────────────────────────────────────
// Test 12: MemoryInitFinalize — x0 handling (IF9, IF10)
// ──────────────────────────────────────────────────────────────

#[test]
fn test_rv64_init_finalize_x0_handling() {
    use crate::{
        chips::{
            chips::riscv_memory::initialize_finalize::{
                MemoryChipType, MemoryInitializeFinalizeChip,
            },
            tests::{run_extra_records, test_rv64_emulate, test_rv64_prove_and_verify_chunk},
        },
        compiler::riscv::compiler::{Compiler, SourceType},
        configs::stark_config::KoalaBearPoseidon2,
        emulator::stdin::EmulatorStdin,
        instances::chiptype::riscv_chiptype::RiscvChipType,
        machine::chip::MetaChip,
    };
    use p3_koala_bear::KoalaBear;

    let compiler = Compiler::new(SourceType::RISCV, FIB_ELF).expect("failed to create compiler");
    let program = compiler.compile();

    let mut stdin_builder = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    stdin_builder.write(&10u64);
    let (stdin, _proofs) = stdin_builder.finalize();

    let all_records = test_rv64_emulate(program.clone(), stdin);
    let mut record = all_records.last().cloned().unwrap();

    // ── Verify x0 (addr=0) is in initialize events with value=0 ──
    let x0_init = record.memory_initialize_events.iter().find(|e| e.addr == 0);
    assert!(
        x0_init.is_some(),
        "x0 (addr=0) should be in memory initialize events"
    );
    assert_eq!(
        x0_init.unwrap().value,
        0,
        "x0 value must be 0 (RISC-V invariant)"
    );

    // ── Verify PV previous_init_addr_limbs is [0,0,0] for first chunk ──
    // (The last record's PV may have non-zero prev_addr if it's not the first chunk.
    //  For first-chunk checking, we verify the first record instead.)
    let first_record = all_records.first().unwrap();
    assert_eq!(
        first_record.public_values.previous_init_addr_limbs,
        [0, 0, 0],
        "First chunk's previous_init_addr should be [0,0,0]"
    );

    println!(
        "x0 init event confirmed: addr=0x{:x}, value=0x{:x}",
        x0_init.unwrap().addr,
        x0_init.unwrap().value,
    );

    // prove+verify with the last record
    let chips = vec![
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Program(Default::default())),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::MemoryInitialize(
            MemoryInitializeFinalizeChip::new(MemoryChipType::Initialize),
        )),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::MemoryFinalize(
            MemoryInitializeFinalizeChip::new(MemoryChipType::Finalize),
        )),
    ];

    run_extra_records(&chips, &mut record);
    test_rv64_prove_and_verify_chunk(program, chips, record);
}

// ──────────────────────────────────────────────────────────────
// Test 13: MemoryInitFinalize — multi-chunk (IF4: non-zero chunk)
// ──────────────────────────────────────────────────────────────

#[test]
fn test_rv64_init_finalize_multi_chunk() {
    use crate::{
        chips::{
            chips::riscv_memory::initialize_finalize::{
                MemoryChipType, MemoryInitializeFinalizeChip,
            },
            tests::{
                run_extra_records, test_rv64_emulate_with_opts, test_rv64_prove_and_verify_chunk,
            },
        },
        compiler::riscv::compiler::{Compiler, SourceType},
        configs::stark_config::KoalaBearPoseidon2,
        emulator::{opts::EmulatorOpts, stdin::EmulatorStdin},
        instances::chiptype::riscv_chiptype::RiscvChipType,
        machine::chip::MetaChip,
    };
    use p3_koala_bear::KoalaBear;

    let compiler = Compiler::new(SourceType::RISCV, FIB_ELF).expect("failed to create compiler");
    let program = compiler.compile();

    let mut stdin_builder = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    stdin_builder.write(&10u64);
    let (stdin, _proofs) = stdin_builder.finalize();

    // Use small chunk_size to force multiple chunks
    let opts = EmulatorOpts {
        chunk_size: 512,
        ..EmulatorOpts::default()
    };

    let all_records = test_rv64_emulate_with_opts(program.clone(), stdin, opts);
    println!("Total records (chunks): {}", all_records.len());
    assert!(
        all_records.len() > 1,
        "Need multiple chunks; got only {}. Try smaller chunk_size.",
        all_records.len()
    );

    let mut record = all_records.last().cloned().unwrap();

    // ── Verify finalize events have chunk > 0 ──
    let max_fin_chunk = record
        .memory_finalize_events
        .iter()
        .map(|e| e.chunk)
        .max()
        .unwrap_or(0);
    println!(
        "Last record: init={}, finalize={}, max_finalize_chunk={}",
        record.memory_initialize_events.len(),
        record.memory_finalize_events.len(),
        max_fin_chunk,
    );
    assert!(
        max_fin_chunk > 0,
        "Finalize events should have non-zero chunk in multi-chunk scenario"
    );

    // ── PV connection assertions (same as Test 11) ──
    let mut sorted_init: Vec<_> = record.memory_initialize_events.clone();
    sorted_init.sort_by_key(|e| e.addr);

    let pv_prev_init: u64 = (record.public_values.previous_init_addr_limbs[0] as u64)
        | ((record.public_values.previous_init_addr_limbs[1] as u64) << 16)
        | ((record.public_values.previous_init_addr_limbs[2] as u64) << 32);
    let pv_last_init: u64 = (record.public_values.last_init_addr_limbs[0] as u64)
        | ((record.public_values.last_init_addr_limbs[1] as u64) << 16)
        | ((record.public_values.last_init_addr_limbs[2] as u64) << 32);

    println!("PV previous_init_addr: 0x{:x}", pv_prev_init);
    println!("PV last_init_addr:     0x{:x}", pv_last_init);

    if !sorted_init.is_empty() {
        if pv_prev_init == 0 {
            assert_eq!(sorted_init.first().unwrap().addr, 0);
        } else {
            assert!(sorted_init.first().unwrap().addr > pv_prev_init);
        }
        assert_eq!(sorted_init.last().unwrap().addr, pv_last_init);
    }

    // prove+verify
    let chips = vec![
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Program(Default::default())),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::MemoryInitialize(
            MemoryInitializeFinalizeChip::new(MemoryChipType::Initialize),
        )),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::MemoryFinalize(
            MemoryInitializeFinalizeChip::new(MemoryChipType::Finalize),
        )),
    ];

    run_extra_records(&chips, &mut record);
    test_rv64_prove_and_verify_chunk(program, chips, record);
}
