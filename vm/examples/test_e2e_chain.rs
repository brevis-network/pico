use pico_vm::{
    instances::configs::riscv_config::StarkConfig as RiscvBBSC,
    machine::logger::setup_logger,
    proverchain::{
        CombineProver, CompressProver, ConvertProver, EmbedProver, InitialProverSetup,
        MachineProver, ProverChain, RiscvProver,
    },
};

#[path = "common/parse_args.rs"]
mod parse_args;

fn main() {
    setup_logger();
    let (elf, riscv_stdin, _, _) = parse_args::parse_args();

    let riscv = RiscvProver::new_initial_prover((RiscvBBSC::new(), elf));
    let convert = ConvertProver::new_with_prev(&riscv);
    let combine = CombineProver::new_with_prev(&convert);
    let compress = CompressProver::new_with_prev(&combine);
    let embed = EmbedProver::<_, _, Vec<u8>>::new_with_prev(&compress);

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
