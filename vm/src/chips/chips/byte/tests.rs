use crate::{
    chips::tests::{test_rv64_emulate, test_rv64_prove_and_verify_chunk},
    compiler::riscv::{
        instruction::Instruction,
        opcode::{ByteOpcode, Opcode},
        program::Program,
    },
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{record::RecordBehavior, stdin::EmulatorStdin},
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::chip::{ChipBehavior, MetaChip},
};
use p3_koala_bear::KoalaBear;
use std::sync::Arc;

fn create_srl_program() -> Program {
    let instructions = vec![
        Instruction::new(Opcode::ADD, 10, 0, 16, false, true),
        Instruction::new(Opcode::ADD, 11, 0, 2, false, true),
        Instruction::new(Opcode::SRL, 12, 10, 11, false, false),
        Instruction::new(Opcode::ADD, 10, 0, 0, false, true),
        Instruction::new(Opcode::ECALL, 0, 0, 0, false, false),
    ];
    Program::new(instructions, 0x10000, 0x10000)
}

#[test]
fn test_rv64_byte_chip() {
    let program = Arc::new(create_srl_program());

    let stdin_builder = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    let (stdin, _proofs) = stdin_builder.finalize();

    let chips = vec![
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Program(Default::default())),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Cpu(Default::default())),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Byte(Default::default())),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::SR(Default::default())),
    ];

    let all_records = test_rv64_emulate(program.clone(), stdin);
    let mut record = all_records.first().cloned().unwrap();

    // Manually call extra_record to populate byte_lookups
    for chip in &chips {
        if chip.is_active(&record) {
            let mut extra = Default::default();
            chip.extra_record(&record, &mut extra);
            record.append(&mut extra);
        }
    }

    println!("Byte events count: {}", record.byte_lookups.len());

    let bitrange_count: usize = record
        .byte_lookups
        .iter()
        .filter(|(event, _)| event.opcode == ByteOpcode::BitRange)
        .map(|(_, count)| count)
        .sum();
    println!("BitRange events count: {}", bitrange_count);

    for (event, count) in &record.byte_lookups {
        println!("{:?}: {}", event, count);
    }

    test_rv64_prove_and_verify_chunk(program, chips, record);
}

#[test]
fn test_byte_chip_simple_eval() {
    use crate::{
        chips::chips::byte::ByteChip,
        machine::{
            builder::PublicValuesBuilder, chip::ChipBehavior, folder::SymbolicConstraintFolder,
        },
    };
    use p3_air::{Air, BaseAir};
    use p3_koala_bear::KoalaBear;

    let chip: ByteChip<KoalaBear> = ByteChip::default();
    let preprocessed_width = chip.preprocessed_width();
    let width = chip.width();
    let mut builder = SymbolicConstraintFolder::new(preprocessed_width, width);
    chip.eval(&mut builder);

    assert_eq!(builder.num_constraints(), 0);
    assert_eq!(builder.public_values().len(), 119);
    assert_eq!(builder.num_lookups(), 10);
}
