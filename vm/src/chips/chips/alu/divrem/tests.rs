use crate::{
    chips::{
        chips::alu::{
            divrem::{utils::get_quotient_and_remainder, DivRemChip},
            event::AluEvent,
        },
        tests::run_test,
    },
    compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
    emulator::riscv::record::EmulationRecord,
    machine::{builder::PublicValuesBuilder, chip::ChipBehavior, folder::SymbolicConstraintFolder},
};
use p3_air::{Air, BaseAir};
use p3_koala_bear::KoalaBear;
use rand::{prelude::SliceRandom, thread_rng, Rng};

#[test]
fn test_divrem_chip_simple_eval() {
    let chip: DivRemChip<KoalaBear> = DivRemChip::default();
    let preprocessed_width = chip.preprocessed_width();
    let width = chip.width();
    let mut builder = SymbolicConstraintFolder::new(preprocessed_width, width);
    chip.eval(&mut builder);

    assert_eq!(builder.num_constraints(), 339);
    assert_eq!(builder.public_values().len(), 119);
    assert_eq!(builder.num_lookups(), 121);
}

/// Construct a Program with DIV/REM (signed 64-bit) instructions.
fn create_div_rem_program() -> Program {
    let instructions = vec![
        // Setup: x10 = 10, x11 = 3
        Instruction::new(Opcode::ADD, 10, 0, 10, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 3, false, true),
        // DIV (signed 64-bit): x12 = 10 / 3 = 3
        Instruction::new(Opcode::DIV, 12, 10, 11, false, false),
        // REM (signed 64-bit): x13 = 10 % 3 = 1
        Instruction::new(Opcode::REM, 13, 10, 11, false, false),
        // Exit with code 0
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// Construct a Program with DIVU/REMU (unsigned 64-bit) instructions.
fn create_divu_remu_program() -> Program {
    let instructions = vec![
        // Setup: x10 = 10, x11 = 3
        Instruction::new(Opcode::ADD, 10, 0, 10, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 3, false, true),
        // DIVU (unsigned 64-bit): x12 = 10 / 3 = 3
        Instruction::new(Opcode::DIVU, 12, 10, 11, false, false),
        // REMU (unsigned 64-bit): x13 = 10 % 3 = 1
        Instruction::new(Opcode::REMU, 13, 10, 11, false, false),
        // Exit with code 0
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// Construct a Program with DIVW/REMW (signed 32-bit word) instructions.
fn create_divw_remw_program() -> Program {
    let instructions = vec![
        // Setup: x10 = 10, x11 = 3
        Instruction::new(Opcode::ADD, 10, 0, 10, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 3, false, true),
        // DIVW (signed 32-bit word): x12 = 10 / 3 = 3
        Instruction::new(Opcode::DIVW, 12, 10, 11, false, false),
        // REMW (signed 32-bit word): x13 = 10 % 3 = 1
        Instruction::new(Opcode::REMW, 13, 10, 11, false, false),
        // Exit with code 0
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

/// Construct a Program with DIVUW/REMUW (unsigned 32-bit word) instructions.
fn create_divuw_remuw_program() -> Program {
    let instructions = vec![
        // Setup: x10 = 10, x11 = 3
        Instruction::new(Opcode::ADD, 10, 0, 10, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 3, false, true),
        // DIVUW (unsigned 32-bit word): x12 = 10 / 3 = 3
        Instruction::new(Opcode::DIVUW, 12, 10, 11, false, false),
        // REMUW (unsigned 32-bit word): x13 = 10 % 3 = 1
        Instruction::new(Opcode::REMUW, 13, 10, 11, false, false),
        // Exit with code 0
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

#[test]
fn test_rv64_div_rem() {
    run_test(create_div_rem_program(), "DIV/REM");
}

#[test]
fn test_rv64_divu_remu() {
    run_test(create_divu_remu_program(), "DIVU/REMU");
}

#[test]
fn test_rv64_divw_remw() {
    run_test(create_divw_remw_program(), "DIVW/REMW");
}

#[test]
fn test_rv64_divuw_remuw() {
    run_test(create_divuw_remuw_program(), "DIVUW/REMUW");
}

/// CPU-only test with large random u64 values.
/// Exposes LtUnsignedGadget::populate bug: byte_flags has WORD_SIZE=4 entries
/// but populate iterates over 8 bytes and accesses byte_flags[i] with i up to 7.
#[test]
fn test_divrem_cpu_large_random_values() {
    type F = KoalaBear;
    let rng = &mut thread_rng();
    let all_ops = [
        Opcode::DIV,
        Opcode::DIVU,
        Opcode::REM,
        Opcode::REMU,
        Opcode::DIVW,
        Opcode::DIVUW,
        Opcode::REMW,
        Opcode::REMUW,
    ];
    let divrem_events: Vec<AluEvent> = (0..1024u64)
        .map(|i| {
            let op = *all_ops.choose(rng).unwrap();
            let b: u64 = rng.gen();
            let c: u64 = rng.gen_range(1..u64::MAX);
            let (quotient, remainder) = get_quotient_and_remainder(b, c, op);
            let a = match op {
                Opcode::DIV | Opcode::DIVU | Opcode::DIVW | Opcode::DIVUW => quotient,
                Opcode::REM | Opcode::REMU | Opcode::REMW | Opcode::REMUW => remainder,
                _ => unreachable!(),
            };
            AluEvent::new(i, op, a, b, c, false)
        })
        .collect();

    let record = EmulationRecord {
        divrem_events,
        ..Default::default()
    };

    let chip = DivRemChip::<F>::default();
    // This will panic with "index out of bounds: the len is 4 but the index is ..."
    // if LtUnsignedGadget::populate has the byte indexing bug.
    let _trace = chip.generate_main(&record, &mut EmulationRecord::default());
    println!("CPU trace generation with large random u64 values succeeded");
}
