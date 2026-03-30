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

const BN_ELF: &[u8] = include_bytes!("../../../../../perf/bench_data/rv64/bn254-fp-elf");

fn setup_test() -> (Arc<Program>, EmulatorStdin<Program, Vec<u8>>) {
    let compiler = Compiler::new(SourceType::RISCV, BN_ELF).expect("failed to create compiler");
    let program = compiler.compile();
    let stdin_builder = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    let (stdin, _proofs) = stdin_builder.finalize();
    (program, stdin)
}

const BN254_EVENT_TYPES: &[(&str, SyscallCode)] = &[
    ("bn254 fp_add", SyscallCode::BN254_FP_ADD),
    ("bn254 fp_sub", SyscallCode::BN254_FP_SUB),
    ("bn254 fp_mul", SyscallCode::BN254_FP_MUL),
    ("bn254 fp2_add", SyscallCode::BN254_FP2_ADD),
    ("bn254 fp2_sub", SyscallCode::BN254_FP2_SUB),
    ("bn254 fp2_mul", SyscallCode::BN254_FP2_MUL),
    ("bn254 add", SyscallCode::BN254_ADD),
    ("bn254 double", SyscallCode::BN254_DOUBLE),
];

#[test]
#[ignore]
fn test_rv64_bn_fp_add() {
    let (program, stdin) = setup_test();

    let all_records = test_rv64_emulate(program.clone(), stdin);

    for (i, record) in all_records.iter().enumerate() {
        let non_empty: Vec<_> = BN254_EVENT_TYPES
            .iter()
            .filter_map(|(name, code)| {
                let count = record.get_precompile_events(*code).len();
                if count > 0 {
                    Some(format!("{name}={count}"))
                } else {
                    None
                }
            })
            .collect();

        if !non_empty.is_empty() {
            println!("Record {i}: {}", non_empty.join(", "));
        }

        if !record
            .get_precompile_events(SyscallCode::BN254_FP_ADD)
            .is_empty()
        {
            println!("Record {i}: running prove & verify for bn254 fp add...");
            let chips = vec![
                MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Program(Default::default())),
                MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::FpBn254(Default::default())),
            ];
            test_rv64_prove_and_verify_chunk(program.clone(), chips, record.clone());
            println!("Record {i}: prove & verify passed");
            return;
        }
    }
    panic!("No bn254 fp add events found!");
}

#[test]
#[ignore]
fn test_rv64_bn_fp2_mul() {
    let (program, stdin) = setup_test();

    let all_records = test_rv64_emulate(program.clone(), stdin);

    for (i, record) in all_records.iter().enumerate() {
        let non_empty: Vec<_> = BN254_EVENT_TYPES
            .iter()
            .filter_map(|(name, code)| {
                let count = record.get_precompile_events(*code).len();
                if count > 0 {
                    Some(format!("{name}={count}"))
                } else {
                    None
                }
            })
            .collect();

        if !non_empty.is_empty() {
            println!("Record {i}: {}", non_empty.join(", "));
        }

        if !record
            .get_precompile_events(SyscallCode::BN254_FP2_MUL)
            .is_empty()
        {
            println!("Record {i}: running prove & verify for bn254 fp2 mul...");
            let chips = vec![
                MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Program(Default::default())),
                MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Fp2MulBn254(
                    Default::default(),
                )),
            ];
            test_rv64_prove_and_verify_chunk(program.clone(), chips, record.clone());
            println!("Record {i}: prove & verify passed");
            return;
        }
    }
    panic!("No bn254 fp2 mul events found!");
}
