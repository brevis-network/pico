use pico_vm::{
    configs::config::StarkGenericConfig,
    instances::configs::riscv_config::StarkConfig as RiscvBBSC,
    machine::logger::setup_logger,
    proverchain::{
        CombineProver, CompressProver, ConvertProver, EmbedProver, InitialProverSetup,
        MachineProver, ProverChain, RiscvProver,
    },
};

#[path = "common/parse_args.rs"]
mod parse_args;

#[allow(clippy::unit_arg)]
fn main() {
    setup_logger();
    let (elf, riscv_stdin, _) = parse_args::parse_args();

    let riscv = RiscvProver::new_initial_prover((RiscvBBSC::new(), elf), Default::default());
    let convert = ConvertProver::new_with_prev(&riscv, Default::default());
    let combine = CombineProver::new_with_prev(&convert, Default::default());
    let compress = CompressProver::new_with_prev(&combine, Default::default());
    let embed = EmbedProver::<_, _, Vec<u8>>::new_with_prev(&compress, Default::default());

    let proof = riscv.prove(riscv_stdin);
    assert!(riscv.verify(&proof));
    let proof = convert.prove(proof);
    assert!(convert.verify(&proof));
    let proof = combine.prove(proof);
    assert!(combine.verify(&proof));
    let proof = compress.prove(proof);
    assert!(compress.verify(&proof));
    let proof = embed.prove(proof);
    assert!(embed.verify(&proof));
}
