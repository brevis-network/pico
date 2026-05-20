use crate::{
    chips::{chips::alu::sr::traces::ShiftRightChip, tests::run_test},
    compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
    machine::{builder::PublicValuesBuilder, chip::ChipBehavior, folder::SymbolicConstraintFolder},
};
use p3_air::{Air, BaseAir};
use p3_koala_bear::KoalaBear;

#[test]
fn test_shift_right_chip_simple_eval() {
    let chip: ShiftRightChip<KoalaBear> = ShiftRightChip::default();
    let preprocessed_width = chip.preprocessed_width();
    let width = chip.width();
    let mut builder = SymbolicConstraintFolder::new(preprocessed_width, width);
    chip.eval(&mut builder);

    assert_eq!(builder.num_constraints(), 55);
    assert_eq!(builder.public_values().len(), 119);
    assert_eq!(builder.num_lookups(), 13);
}

/// Construct a Program with SRL (Shift Right Logical 64-bit) instructions.
fn create_srl_program() -> Program {
    let instructions = vec![
        // Setup: x10 = 16 (0b10000), x11 = 2
        Instruction::new(Opcode::ADD, 10, 0, 16, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 2, false, true),
        // SRL: x12 = 16 >> 2 = 4
        Instruction::new(Opcode::SRL, 12, 10, 11, false, false),
        // Exit with code 0
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// Construct a Program with SRA (Shift Right Arithmetic 64-bit) instructions.
fn create_sra_program() -> Program {
    let instructions = vec![
        // Setup: x10 = -16 (as u32), x11 = 2
        // -16 in two's complement is u32::MAX - 15 = 0xFFFFFFF0
        Instruction::new(Opcode::ADD, 10, 0, 0xFFFFFFF0, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 2, false, true),
        // SRA: x12 = (-16) >> 2 = -4 (arithmetic, preserves sign)
        Instruction::new(Opcode::SRA, 12, 10, 11, false, false),
        // Exit with code 0
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// Construct a Program with SRLW (Shift Right Logical Word 32-bit) instructions.
fn create_srlw_program() -> Program {
    let instructions = vec![
        // Setup: x10 = 16, x11 = 2
        Instruction::new(Opcode::ADD, 10, 0, 16, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 2, false, true),
        // SRLW: x12 = 16 >> 2 = 4 (32-bit word)
        Instruction::new(Opcode::SRLW, 12, 10, 11, false, false),
        // Exit with code 0
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// Construct a Program with SRAW (Shift Right Arithmetic Word 32-bit) instructions.
fn create_sraw_program() -> Program {
    let instructions = vec![
        // Setup: x10 = -16 (as u32), x11 = 2
        Instruction::new(Opcode::ADD, 10, 0, 0xFFFFFFF0, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 2, false, true),
        // SRAW: x12 = (-16) >> 2 = -4 (32-bit word, arithmetic)
        Instruction::new(Opcode::SRAW, 12, 10, 11, false, false),
        // Exit with code 0
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

#[test]
fn test_rv64_srl() {
    run_test(create_srl_program(), "SRL");
}

#[test]
fn test_rv64_sra() {
    run_test(create_sra_program(), "SRA");
}

#[test]
fn test_rv64_srlw() {
    run_test(create_srlw_program(), "SRLW");
}

#[test]
fn test_rv64_sraw() {
    run_test(create_sraw_program(), "SRAW");
}

/// SRAW: 0x80000000 >> 16 — exercises shift_u16[1] (a[0] is assigned from limb_result[1])
#[test]
fn test_rv64_sraw_word_cross_boundary() {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, 0x80000000, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 16, false, true),
        Instruction::new(Opcode::SRAW, 12, 10, 11, false, false),
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    let program = Program::new(instructions, 0x10000, 0x10000);
    run_test(program, "SRAW: word boundary");
}
