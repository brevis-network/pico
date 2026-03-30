use crate::{
    chips::tests::run_test,
    compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
};

/// Construct a Program with XOR instructions.
fn create_xor_program() -> Program {
    let instructions = vec![
        // Setup: x10 = 0xF0F0, x11 = 0x0F0F
        Instruction::new(Opcode::ADD, 10, 0, 0xF0F0, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 0x0F0F, false, true),
        // XOR: x12 = 0xF0F0 ^ 0x0F0F = 0xFFFF
        Instruction::new(Opcode::XOR, 12, 10, 11, false, false),
        // Exit with code 0
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// Construct a Program with XORI (immediate) instructions.
fn create_xori_program() -> Program {
    let instructions = vec![
        // Setup: x10 = 0xF0F0
        Instruction::new(Opcode::ADD, 10, 0, 0xF0F0, false, true),
        // XORI: x11 = 0xF0F0 ^ 0x0F0F = 0xFFFF (immediate)
        Instruction::new(Opcode::XOR, 11, 10, 0x0F0F, true, false),
        // Exit with code 0
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// Construct a Program with OR instructions.
fn create_or_program() -> Program {
    let instructions = vec![
        // Setup: x10 = 0xF0F0, x11 = 0x0F0F
        Instruction::new(Opcode::ADD, 10, 0, 0xF0F0, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 0x0F0F, false, true),
        // OR: x12 = 0xF0F0 | 0x0F0F = 0xFFFF
        Instruction::new(Opcode::OR, 12, 10, 11, false, false),
        // Exit with code 0
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// Construct a Program with ORI (immediate) instructions.
fn create_ori_program() -> Program {
    let instructions = vec![
        // Setup: x10 = 0xF0F0
        Instruction::new(Opcode::ADD, 10, 0, 0xF0F0, false, true),
        // ORI: x11 = 0xF0F0 | 0x0F0F = 0xFFFF (immediate)
        Instruction::new(Opcode::OR, 11, 10, 0x0F0F, true, false),
        // Exit with code 0
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// Construct a Program with AND instructions.
fn create_and_program() -> Program {
    let instructions = vec![
        // Setup: x10 = 0xF0F0, x11 = 0xFF0F
        Instruction::new(Opcode::ADD, 10, 0, 0xF0F0, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 0xFF0F, false, true),
        // AND: x12 = 0xF0F0 & 0xFF0F = 0xF00F
        Instruction::new(Opcode::AND, 12, 10, 11, false, false),
        // Exit with code 0
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// Construct a Program with ANDI (immediate) instructions.
/// Note: Using small immediate values that work with the test infrastructure.
fn create_andi_program() -> Program {
    let instructions = vec![
        // Setup: x10 = 15
        Instruction::new(Opcode::ADD, 10, 0, 15, false, true),
        // ANDI: x11 = 15 & 12 = 12 (immediate)
        Instruction::new(Opcode::AND, 11, 10, 12, true, false),
        // Exit with code 0
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// Construct a Program with XOR (result = 0) instructions.
fn create_xor_zero_program() -> Program {
    let instructions = vec![
        // Setup: x10 = 0xFFFFFFFF, x11 = 0xFFFFFFFF
        Instruction::new(Opcode::ADD, 10, 0, 0xFFFFFFFF, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 0xFFFFFFFF, false, true),
        // XOR: x12 = 0xFFFFFFFF ^ 0xFFFFFFFF = 0
        Instruction::new(Opcode::XOR, 12, 10, 11, false, false),
        // Exit with code 0
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// Construct a Program with OR (all ones) instructions.
fn create_or_all_ones_program() -> Program {
    let instructions = vec![
        // Setup: x10 = 0, x11 = 0xFFFFFFFF
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 0xFFFFFFFF, false, true),
        // OR: x12 = 0 | 0xFFFFFFFF = 0xFFFFFFFF
        Instruction::new(Opcode::OR, 12, 10, 11, false, false),
        // Exit with code 0
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// Construct a Program with AND (all zeros) instructions.
fn create_and_zero_program() -> Program {
    let instructions = vec![
        // Setup: x10 = 0xF0F0, x11 = 0
        Instruction::new(Opcode::ADD, 10, 0, 0xF0F0, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 0, false, true),
        // AND: x12 = 0xF0F0 & 0 = 0
        Instruction::new(Opcode::AND, 12, 10, 11, false, false),
        // Exit with code 0
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

#[test]
fn test_rv64_xor() {
    run_test(create_xor_program(), "XOR");
}

#[test]
fn test_rv64_xori() {
    run_test(create_xori_program(), "XORI");
}

#[test]
fn test_rv64_or() {
    run_test(create_or_program(), "OR");
}

#[test]
fn test_rv64_ori() {
    run_test(create_ori_program(), "ORI");
}

#[test]
fn test_rv64_and() {
    run_test(create_and_program(), "AND");
}

#[test]
fn test_rv64_andi() {
    run_test(create_andi_program(), "ANDI");
}

#[test]
fn test_rv64_xor_zero() {
    run_test(create_xor_zero_program(), "XOR zero");
}

#[test]
fn test_rv64_or_all_ones() {
    run_test(create_or_all_ones_program(), "OR all ones");
}

#[test]
fn test_rv64_and_zero() {
    run_test(create_and_zero_program(), "AND zero");
}
