use crate::{
    chips::tests::run_test,
    compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
};

/// Basic addition: 20 + 23 = 43.
fn create_add_program() -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, 20, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 23, false, true),
        Instruction::new(Opcode::ADD, 12, 10, 11, false, false),
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// Adding zero: 100 + 0 = 100.
fn create_add_zero_program() -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, 100, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 0, false, true),
        Instruction::new(Opcode::ADD, 12, 10, 11, false, false),
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// Same operand: ADD x11, x10, x10 → x11 = 7 + 7 = 14.
fn create_add_same_operand_program() -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, 7, false, true),
        Instruction::new(Opcode::ADD, 11, 10, 10, false, false),
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// 64-bit wrapping overflow: u64::MAX + 1 = 0.
fn create_add_overflow_program() -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, u64::MAX, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 1, false, true),
        Instruction::new(Opcode::ADD, 12, 10, 11, false, false),
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// Chained additions: x10=10, x11=20, x12=x10+x11=30, x13=x12+x11=50.
fn create_add_chained_program() -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, 10, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 20, false, true),
        Instruction::new(Opcode::ADD, 12, 10, 11, false, false),
        Instruction::new(Opcode::ADD, 13, 12, 11, false, false),
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

#[test]
fn test_rv64_add() {
    run_test(create_add_program(), "add");
}

#[test]
fn test_rv64_add_zero() {
    run_test(create_add_zero_program(), "add zero");
}

#[test]
fn test_rv64_add_same_operand() {
    run_test(create_add_same_operand_program(), "add same operand");
}

#[test]
fn test_rv64_add_overflow_wrapping() {
    run_test(create_add_overflow_program(), "add overflow wrapping");
}

#[test]
fn test_rv64_add_chained() {
    run_test(create_add_chained_program(), "add chained");
}
