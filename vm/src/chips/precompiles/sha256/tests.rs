use crate::{
    chips::tests::{test_rv64_emulate, test_rv64_prove_and_verify_chunk},
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{riscv::syscalls::SyscallCode, stdin::EmulatorStdin},
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::chip::MetaChip,
};
use p3_koala_bear::KoalaBear;
use std::sync::Arc;

const SHA2_ELF: &[u8] = include_bytes!("../../../../../perf/bench_data/rv64/sha2-elf");

fn setup_test() -> (Arc<Program>, EmulatorStdin<Program, Vec<u8>>) {
    println!("Creating compiler");
    let compiler = Compiler::new(SourceType::RISCV, SHA2_ELF).expect("failed to create compiler");
    println!("Compiling program");
    let program = compiler.compile();

    println!("Setting up stdin");
    let mut stdin_builder = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    stdin_builder.write(&[3u8; 32]);
    stdin_builder.write(&[1u8; 32]);
    let (stdin, _proofs) = stdin_builder.finalize();

    (program, stdin)
}

#[test]
#[ignore]
fn test_rv64_sha2_compress() {
    let (program, stdin) = setup_test();

    println!("Running emulation...");
    let all_records = test_rv64_emulate(program.clone(), stdin);

    println!("Looking for record with SHA_COMPRESS events...");
    for (i, record) in all_records.iter().enumerate() {
        let sha_compress_events = record.get_precompile_events(SyscallCode::SHA_COMPRESS);
        if !sha_compress_events.is_empty() {
            println!(
                "Found record {} with {} SHA_COMPRESS events",
                i,
                sha_compress_events.len()
            );
            let chips = vec![
                MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Program(Default::default())),
                MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::ShaCompress(
                    Default::default(),
                )),
                MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::ShaCompressControl(
                    Default::default(),
                )),
            ];
            test_rv64_prove_and_verify_chunk(program, chips, record.clone());
            return;
        }
    }
    panic!("No SHA_COMPRESS events found!");
}

#[test]
#[ignore]
fn test_rv64_sha2_extend() {
    let (program, stdin) = setup_test();

    println!("Running emulation...");
    let all_records = test_rv64_emulate(program.clone(), stdin);

    println!("Looking for record with SHA_EXTEND events...");
    for (i, record) in all_records.iter().enumerate() {
        let sha_extend_events = record.get_precompile_events(SyscallCode::SHA_EXTEND);
        if !sha_extend_events.is_empty() {
            println!(
                "Found record {} with {} SHA_EXTEND events",
                i,
                sha_extend_events.len()
            );
            let chips = vec![
                MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Program(Default::default())),
                MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::ShaExtend(Default::default())),
                MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::ShaExtendControl(
                    Default::default(),
                )),
            ];
            test_rv64_prove_and_verify_chunk(program, chips, record.clone());
            return;
        }
    }
    panic!("No SHA_EXTEND events found!");
}

#[test]
fn test_sha_compress_chip_simple_eval() {
    use super::compress::ShaCompressChip;
    use crate::machine::{
        builder::PublicValuesBuilder, chip::ChipBehavior, folder::SymbolicConstraintFolder,
    };
    use p3_air::{Air, BaseAir};
    use p3_koala_bear::KoalaBear;

    let chip: ShaCompressChip<KoalaBear> = ShaCompressChip::default();
    let (preprocessed_width, width) = (chip.preprocessed_width(), chip.width());
    let mut builder = SymbolicConstraintFolder::new(preprocessed_width, width);
    chip.eval(&mut builder);

    assert_eq!(builder.num_constraints(), 305);
    assert_eq!(builder.public_values().len(), 119);
    assert_eq!(builder.num_lookups(), 99);
}

#[test]
fn test_sha_compress_control_chip_simple_eval() {
    use super::compress::ShaCompressControlChip;
    use crate::machine::{
        builder::PublicValuesBuilder, chip::ChipBehavior, folder::SymbolicConstraintFolder,
    };
    use p3_air::{Air, BaseAir};
    use p3_koala_bear::KoalaBear;

    let chip: ShaCompressControlChip<KoalaBear> = ShaCompressControlChip::default();
    let (preprocessed_width, width) = (chip.preprocessed_width(), chip.width());
    let mut builder = SymbolicConstraintFolder::new(preprocessed_width, width);
    chip.eval(&mut builder);

    assert_eq!(builder.num_constraints(), 21);
    assert_eq!(builder.public_values().len(), 119);
    assert_eq!(builder.num_lookups(), 17);
}

#[test]
fn test_sha_extend_chip_simple_eval() {
    use super::extend::ShaExtendChip;
    use crate::machine::{
        builder::PublicValuesBuilder, chip::ChipBehavior, folder::SymbolicConstraintFolder,
    };
    use p3_air::{Air, BaseAir};
    use p3_koala_bear::KoalaBear;

    let chip: ShaExtendChip<KoalaBear> = ShaExtendChip::default();
    let (preprocessed_width, width) = (chip.preprocessed_width(), chip.width());
    let mut builder = SymbolicConstraintFolder::new(preprocessed_width, width);
    chip.eval(&mut builder);

    assert_eq!(builder.num_constraints(), 81);
    assert_eq!(builder.public_values().len(), 119);
    assert_eq!(builder.num_lookups(), 81);
}

#[test]
fn test_sha_extend_control_chip_simple_eval() {
    use super::extend::ShaExtendControlChip;
    use crate::machine::{
        builder::PublicValuesBuilder, chip::ChipBehavior, folder::SymbolicConstraintFolder,
    };
    use p3_air::{Air, BaseAir};
    use p3_koala_bear::KoalaBear;

    let chip: ShaExtendControlChip<KoalaBear> = ShaExtendControlChip::default();
    let (preprocessed_width, width) = (chip.preprocessed_width(), chip.width());
    let mut builder = SymbolicConstraintFolder::new(preprocessed_width, width);
    chip.eval(&mut builder);

    assert_eq!(builder.num_constraints(), 21);
    assert_eq!(builder.public_values().len(), 119);
    assert_eq!(builder.num_lookups(), 16);
}
