use crate::{
    chips::tests::run_test,
    compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
};

/// Basic subtraction: 50 - 30 = 20.
fn create_sub_program() -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, 50, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 30, false, true),
        Instruction::new(Opcode::SUB, 12, 10, 11, false, false),
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// Subtracting zero: 100 - 0 = 100.
fn create_sub_zero_program() -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, 100, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 0, false, true),
        Instruction::new(Opcode::SUB, 12, 10, 11, false, false),
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// Equal operands: SUB x11, x10, x10 → x11 = 0.
fn create_sub_equal_program() -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, 42, false, true),
        Instruction::new(Opcode::SUB, 11, 10, 10, false, false),
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// 64-bit wrapping underflow: 0 - 1 = u64::MAX.
fn create_sub_underflow_program() -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 1, false, true),
        Instruction::new(Opcode::SUB, 12, 10, 11, false, false),
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// Negative result: 10 - 20 = -10 (wrapping as u64).
fn create_sub_negative_program() -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, 10, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 20, false, true),
        Instruction::new(Opcode::SUB, 12, 10, 11, false, false),
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

#[test]
fn test_rv64_sub() {
    run_test(create_sub_program(), "sub");
}

#[test]
fn test_rv64_sub_zero() {
    run_test(create_sub_zero_program(), "sub zero");
}

#[test]
fn test_rv64_sub_equal() {
    run_test(create_sub_equal_program(), "sub equal");
}

#[test]
fn test_rv64_sub_underflow_wrapping() {
    run_test(create_sub_underflow_program(), "sub underflow wrapping");
}

#[test]
fn test_rv64_sub_negative_result() {
    run_test(create_sub_negative_program(), "sub negative result");
}
