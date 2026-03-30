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

const BLS_ELF: &[u8] = include_bytes!("../../../../../perf/bench_data/rv64/bls12381-fp-elf");

fn setup_test() -> (Arc<Program>, EmulatorStdin<Program, Vec<u8>>) {
    let compiler = Compiler::new(SourceType::RISCV, BLS_ELF).expect("failed to create compiler");
    let program = compiler.compile();
    let stdin_builder = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    let (stdin, _proofs) = stdin_builder.finalize();
    (program, stdin)
}

const BLS381_EVENT_TYPES: &[(&str, SyscallCode)] = &[
    ("bls381 fp_add", SyscallCode::BLS12381_FP_ADD),
    ("bls381 fp_sub", SyscallCode::BLS12381_FP_SUB),
    ("bls381 fp_mul", SyscallCode::BLS12381_FP_MUL),
    ("bls381 fp2_add", SyscallCode::BLS12381_FP2_ADD),
    ("bls381 fp2_sub", SyscallCode::BLS12381_FP2_SUB),
    ("bls381 fp2_mul", SyscallCode::BLS12381_FP2_MUL),
    ("bls381 add", SyscallCode::BLS12381_ADD),
    ("bls381 double", SyscallCode::BLS12381_DOUBLE),
];

#[test]
#[ignore]
fn test_rv64_bls381_fp_add() {
    let (program, stdin) = setup_test();

    let all_records = test_rv64_emulate(program.clone(), stdin);

    for (i, record) in all_records.iter().enumerate() {
        let non_empty: Vec<_> = BLS381_EVENT_TYPES
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
            .get_precompile_events(SyscallCode::BLS12381_FP_ADD)
            .is_empty()
        {
            println!("Record {i}: running prove & verify for bls 12381 add...");
            let chips = vec![
                MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Program(Default::default())),
                MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::FpBls381(Default::default())),
            ];
            test_rv64_prove_and_verify_chunk(program.clone(), chips, record.clone());
            println!("Record {i}: prove & verify passed");
            return;
        }
    }
    panic!("No bls 12381 fp add events found!");
}

#[test]
#[ignore]
fn test_rv64_bls381_fp2_mul() {
    let (program, stdin) = setup_test();

    let all_records = test_rv64_emulate(program.clone(), stdin);

    for (i, record) in all_records.iter().enumerate() {
        let non_empty: Vec<_> = BLS381_EVENT_TYPES
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
            .get_precompile_events(SyscallCode::BLS12381_FP2_MUL)
            .is_empty()
        {
            println!("Record {i}: running prove & verify for bls 12381 mul...");
            let chips = vec![
                MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Program(Default::default())),
                MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Fp2MulBls381(
                    Default::default(),
                )),
            ];
            test_rv64_prove_and_verify_chunk(program.clone(), chips, record.clone());
            println!("Record {i}: prove & verify passed");
            return;
        }
    }
    panic!("No bls 12381 fp2 mul add events found!");
}
