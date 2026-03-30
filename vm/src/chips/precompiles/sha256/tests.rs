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
