use crate::{
    chips::tests::test_rv64_prove_and_verify,
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    configs::stark_config::KoalaBearPoseidon2,
    emulator::stdin::EmulatorStdin,
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::chip::MetaChip,
};
use p3_koala_bear::KoalaBear;

const ELF: &[u8] = include_bytes!("../../../../../perf/bench_data/rv64/reth-elf");
const INPUT: &[u8] = include_bytes!("../../../../../perf/bench_data/rv64/reth-18884864.bin");

#[ignore = "slow execution - takes too long to run in CI"]
#[test]
fn test_rv64_cpu_chip() {
    println!("Creating compiler");
    let compiler = Compiler::new(SourceType::RISCV, ELF).expect("failed to create compiler");
    println!("Compiling program");
    let program = compiler.compile();

    println!("Setting up stdin");
    let mut stdin_builder = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    stdin_builder.write_slice(INPUT);
    let (stdin, _proofs) = stdin_builder.finalize();

    println!("Setting up chips");
    let chips = vec![
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Cpu(Default::default())),
        MetaChip::test_no_lookup(RiscvChipType::<KoalaBear>::Program(Default::default())),
    ];

    test_rv64_prove_and_verify(program, stdin, chips);
}
