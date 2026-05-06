use crate::{
    chips::{chips::alu::sll::traces::SLLChip, tests::test_rv64_prove_and_verify},
    compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
    configs::stark_config::KoalaBearPoseidon2,
    emulator::stdin::EmulatorStdin,
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::{
        builder::PublicValuesBuilder,
        chip::{ChipBehavior, MetaChip},
        folder::SymbolicConstraintFolder,
    },
};
use p3_air::{Air, BaseAir};
use p3_koala_bear::KoalaBear;
use std::sync::Arc;

#[test]
fn test_sll_chip_simple_eval() {
    let chip: SLLChip<KoalaBear> = SLLChip::default();
    let preprocessed_width = chip.preprocessed_width();
    let width = chip.width();
    let mut builder = SymbolicConstraintFolder::new(preprocessed_width, width);
    chip.eval(&mut builder);

    assert_eq!(builder.num_constraints(), 45);
    assert_eq!(builder.public_values().len(), 119);
    assert_eq!(builder.num_lookups(), 11);
}

fn run_test(program: Program) {
    let program = Arc::new(program);
    let stdin_builder = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    let (stdin, _proofs) = stdin_builder.finalize();
    let chips = vec![
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Program(Default::default())),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::SLL(Default::default())),
    ];
    test_rv64_prove_and_verify(program, stdin, chips);
}

/// Basic SLL: 1 << 3 = 8.
fn create_sll_basic_program() -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, 1, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 3, false, true),
        Instruction::new(Opcode::SLL, 12, 10, 11, false, false),
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// SLL by zero: 42 << 0 = 42 (shift amount = 0, result unchanged).
fn create_sll_by_zero_program() -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, 42, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 0, false, true),
        Instruction::new(Opcode::SLL, 12, 10, 11, false, false),
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// SLL cross-limb: 1 << 16 = 0x10000 (result spans the u16 limb boundary).
fn create_sll_cross_limb_program() -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, 1, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 16, false, true),
        Instruction::new(Opcode::SLL, 12, 10, 11, false, false),
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// SLL large shift: 1 << 32 = 0x100000000.
fn create_sll_large_shift_program() -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, 1, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 32, false, true),
        Instruction::new(Opcode::SLL, 12, 10, 11, false, false),
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// SLL max shift: 1 << 63 = 0x8000000000000000 (only the MSB is set).
fn create_sll_max_shift_program() -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, 1, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 63, false, true),
        Instruction::new(Opcode::SLL, 12, 10, 11, false, false),
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// SLL shift-amount masking: shift amount is masked to lower 6 bits (0x3F).
/// rs2 = 67 = 64 + 3, effective shift = 67 & 0x3F = 3, so 1 << 3 = 8.
fn create_sll_shift_mask_program() -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, 1, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 67, false, true), // 67 & 0x3F = 3
        Instruction::new(Opcode::SLL, 12, 10, 11, false, false),
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// Basic SLLW: 1 << 3 = 8, sign-extended to 64 bits.
fn create_sllw_basic_program() -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, 1, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 3, false, true),
        Instruction::new(Opcode::SLLW, 12, 10, 11, false, false),
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// SLLW overflow: 1 << 31 = 0x80000000 (i32::MIN), sign-extended to 0xFFFFFFFF80000000.
fn create_sllw_overflow_program() -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, 1, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 31, false, true),
        Instruction::new(Opcode::SLLW, 12, 10, 11, false, false),
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// SLLW by zero: 42 << 0 = 42, sign-extended.
fn create_sllw_by_zero_program() -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, 42, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 0, false, true),
        Instruction::new(Opcode::SLLW, 12, 10, 11, false, false),
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

#[test]
fn test_sll_basic() {
    run_test(create_sll_basic_program());
}

#[test]
fn test_sll_by_zero() {
    run_test(create_sll_by_zero_program());
}

#[test]
fn test_sll_cross_limb() {
    run_test(create_sll_cross_limb_program());
}

#[test]
fn test_sll_large_shift() {
    run_test(create_sll_large_shift_program());
}

#[test]
fn test_sll_max_shift() {
    run_test(create_sll_max_shift_program());
}

#[test]
fn test_sll_shift_mask() {
    run_test(create_sll_shift_mask_program());
}

#[test]
fn test_sllw_basic() {
    run_test(create_sllw_basic_program());
}

#[test]
fn test_sllw_overflow() {
    run_test(create_sllw_overflow_program());
}

#[test]
fn test_sllw_by_zero() {
    run_test(create_sllw_by_zero_program());
}
