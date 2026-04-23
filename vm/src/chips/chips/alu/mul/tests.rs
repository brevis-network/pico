use crate::{
    chips::tests::run_test,
    compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
};

/// Construct a Program with MUL (signed 64-bit) instructions.
fn create_mul_program() -> Program {
    let instructions = vec![
        // Setup: x10 = 10, x11 = 3
        Instruction::new(Opcode::ADD, 10, 0, 10, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 3, false, true),
        // MUL: x12 = 10 * 3 = 30
        Instruction::new(Opcode::MUL, 12, 10, 11, false, false),
        // Exit with code 0
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// Construct a Program with MULH (signed high 64-bit) instructions.
fn create_mulh_program() -> Program {
    let instructions = vec![
        // Setup: x10 = 10, x11 = 3
        Instruction::new(Opcode::ADD, 10, 0, 10, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 3, false, true),
        // MULH: x12 = upper 32 bits of signed(10) * signed(3) = 0
        Instruction::new(Opcode::MULH, 12, 10, 11, false, false),
        // Exit with code 0
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// Construct a Program with MULHU (unsigned high 64-bit) instructions.
fn create_mulhu_program() -> Program {
    let instructions = vec![
        // Setup: x10 = 10, x11 = 3
        Instruction::new(Opcode::ADD, 10, 0, 10, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 3, false, true),
        // MULHU: x12 = upper 32 bits of unsigned(10) * unsigned(3) = 0
        Instruction::new(Opcode::MULHU, 12, 10, 11, false, false),
        // Exit with code 0
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// Construct a Program with MULHSU (signed * unsigned high 64-bit) instructions.
fn create_mulhsu_program() -> Program {
    let instructions = vec![
        // Setup: x10 = 10, x11 = 3
        Instruction::new(Opcode::ADD, 10, 0, 10, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 3, false, true),
        // MULHSU: x12 = upper 32 bits of signed(10) * unsigned(3) = 0
        Instruction::new(Opcode::MULHSU, 12, 10, 11, false, false),
        // Exit with code 0
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// Construct a Program with MULW (signed 32-bit word) instructions.
fn create_mulw_program() -> Program {
    let instructions = vec![
        // Setup: x10 = 10, x11 = 3
        Instruction::new(Opcode::ADD, 10, 0, 10, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 3, false, true),
        // MULW: x12 = signed(10) * signed(3) = 30
        Instruction::new(Opcode::MULW, 12, 10, 11, false, false),
        // Exit with code 0
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

#[test]
fn test_rv64_mul() {
    run_test(create_mul_program(), "MUL");
}

#[test]
fn test_rv64_mulh() {
    run_test(create_mulh_program(), "MULH");
}

#[test]
fn test_rv64_mulhu() {
    run_test(create_mulhu_program(), "MULHU");
}

#[test]
fn test_rv64_mulhsu() {
    run_test(create_mulhsu_program(), "MULHSU");
}

#[test]
fn test_rv64_mulw() {
    run_test(create_mulw_program(), "MULW");
}
