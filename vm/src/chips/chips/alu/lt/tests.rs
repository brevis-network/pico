use crate::{
    chips::tests::run_test,
    compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
};

/// Construct a Program with SLT (signed less-than 64-bit) instructions.
fn create_slt_program() -> Program {
    let instructions = vec![
        // Setup: x10 = 10, x11 = 3
        Instruction::new(Opcode::ADD, 10, 0, 10, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 3, false, true),
        // SLT (signed 64-bit): x12 = 10 < 3 = 0
        Instruction::new(Opcode::SLT, 12, 10, 11, false, false),
        // Exit with code 0
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// Construct a Program with SLTU (unsigned less-than 64-bit) instructions.
fn create_sltu_program() -> Program {
    let instructions = vec![
        // Setup: x10 = 10, x11 = 3
        Instruction::new(Opcode::ADD, 10, 0, 10, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 3, false, true),
        // SLTU (unsigned 64-bit): x12 = 10 < 3 = 0
        Instruction::new(Opcode::SLTU, 12, 10, 11, false, false),
        // Exit with code 0
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// Construct a Program with SLT (signed, immediate - uses same opcode as SLT with imm flag)
/// Note: In this VM, immediate is handled by the Instruction, not separate opcodes
fn create_slti_program() -> Program {
    let instructions = vec![
        // Setup: x10 = 10
        Instruction::new(Opcode::ADD, 10, 0, 10, false, true),
        // SLTI: x11 = 10 < 5 = 0 (immediate)
        Instruction::new(Opcode::SLT, 11, 10, 5, true, false),
        // Exit with code 0
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// Construct a Program with SLTIU (unsigned, immediate - uses same opcode as SLTU with imm flag)
fn create_sltiu_program() -> Program {
    let instructions = vec![
        // Setup: x10 = 10
        Instruction::new(Opcode::ADD, 10, 0, 10, false, true),
        // SLTIU: x11 = 10 < 5 = 0 (immediate, unsigned)
        Instruction::new(Opcode::SLTU, 11, 10, 5, true, false),
        // Exit with code 0
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// Construct a Program with SLT (signed, result = 1) instructions.
fn create_slt_true_program() -> Program {
    let instructions = vec![
        // Setup: x10 = 3, x11 = 10
        Instruction::new(Opcode::ADD, 10, 0, 3, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 10, false, true),
        // SLT: x12 = 3 < 10 = 1
        Instruction::new(Opcode::SLT, 12, 10, 11, false, false),
        // Exit with code 0
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// Construct a Program with SLT (equal values) instructions.
fn create_slt_equal_program() -> Program {
    let instructions = vec![
        // Setup: x10 = 5, x11 = 5
        Instruction::new(Opcode::ADD, 10, 0, 5, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 5, false, true),
        // SLT: x12 = 5 < 5 = 0
        Instruction::new(Opcode::SLT, 12, 10, 11, false, false),
        // Exit with code 0
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

#[test]
fn test_rv64_slt() {
    run_test(create_slt_program(), "SLT");
}

#[test]
fn test_rv64_sltu() {
    run_test(create_sltu_program(), "SLTU");
}

#[test]
fn test_rv64_slti() {
    run_test(create_slti_program(), "SLTI");
}

#[test]
fn test_rv64_sltiu() {
    run_test(create_sltiu_program(), "SLTIU");
}

#[test]
fn test_rv64_slt_true() {
    run_test(create_slt_true_program(), "SLT true");
}

#[test]
fn test_rv64_slt_equal() {
    run_test(create_slt_equal_program(), "SLT equal");
}

#[test]
fn test_lt_chip_simple_eval() {
    use crate::machine::{
        builder::PublicValuesBuilder, chip::ChipBehavior, folder::SymbolicConstraintFolder,
    };
    use p3_air::{Air, BaseAir};
    use p3_koala_bear::KoalaBear;

    let chip: crate::chips::chips::alu::lt::traces::LtChip<KoalaBear> =
        crate::chips::chips::alu::lt::traces::LtChip::default();
    let preprocessed_width = chip.preprocessed_width();
    let width = chip.width();
    let mut builder = SymbolicConstraintFolder::new(preprocessed_width, width);
    chip.eval(&mut builder);

    assert_eq!(builder.num_constraints(), 30);
    assert_eq!(builder.public_values().len(), 119);
    assert_eq!(builder.num_lookups(), 4);
}
