use crate::{
    chips::tests::run_test,
    compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
};

/// Basic 32-bit addition with sign extension: 20 + 665535 = 665555.
fn create_addw_program() -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, 20, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 665535, false, true),
        Instruction::new(Opcode::ADDW, 12, 10, 11, false, false),
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// Adding zero: 42 + 0 = 42, result sign-extended.
fn create_addw_zero_program() -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, 42, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 0, false, true),
        Instruction::new(Opcode::ADDW, 12, 10, 11, false, false),
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// 32-bit signed overflow: i32::MAX + 1 = i32::MIN, sign-extended to 64 bits.
/// 0x7FFFFFFF + 1 → lower 32 bits = 0x80000000, sign-extended = 0xFFFFFFFF80000000.
fn create_addw_overflow_program() -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, 0x7FFF_FFFF_u64, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 1, false, true),
        Instruction::new(Opcode::ADDW, 12, 10, 11, false, false),
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// Same operand: ADDW x11, x10, x10 → x11 = 5 + 5 = 10 (sign-extended).
fn create_addw_same_operand_program() -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, 5, false, true),
        Instruction::new(Opcode::ADDW, 11, 10, 10, false, false),
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

#[test]
fn test_rv64_addw() {
    run_test(create_addw_program(), "addw");
}

#[test]
fn test_rv64_addw_zero() {
    run_test(create_addw_zero_program(), "addw zero");
}

#[test]
fn test_rv64_addw_overflow() {
    run_test(create_addw_overflow_program(), "addw overflow");
}

#[test]
fn test_rv64_addw_same_operand() {
    run_test(create_addw_same_operand_program(), "addw same operand");
}
