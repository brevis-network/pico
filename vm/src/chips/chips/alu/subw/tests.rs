use crate::{
    chips::tests::run_test,
    compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
};

/// Basic 32-bit subtraction: 201 - 101 = 100, sign-extended.
fn create_subw_program() -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, 201, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 101, false, true),
        Instruction::new(Opcode::SUBW, 12, 10, 11, false, false),
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// Subtracting zero: 100 - 0 = 100, sign-extended.
fn create_subw_zero_program() -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, 100, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 0, false, true),
        Instruction::new(Opcode::SUBW, 12, 10, 11, false, false),
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// Equal operands: SUBW x11, x10, x10 → x11 = 0.
fn create_subw_equal_program() -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, 99, false, true),
        Instruction::new(Opcode::SUBW, 11, 10, 10, false, false),
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// Negative 32-bit result: 10 - 20 = -10, sign-extended to 64 bits.
fn create_subw_negative_program() -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, 10, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 20, false, true),
        Instruction::new(Opcode::SUBW, 12, 10, 11, false, false),
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// 32-bit wrapping underflow: 0 - 1 = -1 in 32 bits, sign-extended to 0xFFFFFFFFFFFFFFFF.
fn create_subw_underflow_program() -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 1, false, true),
        Instruction::new(Opcode::SUBW, 12, 10, 11, false, false),
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

#[test]
fn test_rv64_subw() {
    run_test(create_subw_program(), "subw");
}

#[test]
fn test_rv64_subw_zero() {
    run_test(create_subw_zero_program(), "subw zero");
}

#[test]
fn test_rv64_subw_equal() {
    run_test(create_subw_equal_program(), "subw equal");
}

#[test]
fn test_rv64_subw_negative_result() {
    run_test(create_subw_negative_program(), "subw negative result");
}

#[test]
fn test_rv64_subw_underflow_wrapping() {
    run_test(create_subw_underflow_program(), "subw underflow wrapping");
}
