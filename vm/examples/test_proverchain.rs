use pico_vm::{
    configs::config::StarkGenericConfig,
    instances::configs::riscv_config::StarkConfig as RiscvBBSC,
    machine::logger::setup_logger,
    proverchain::{
        CombineProver, CompressProver, ConvertProver, EmbedProver, InitialProverSetup,
        MachineProver, ProverChain, RiscvProver,
    },
};

use tracing::info;

#[path = "common/parse_args.rs"]
mod parse_args;

#[allow(clippy::unit_arg)]
fn main() {
    setup_logger();
    let (elf, riscv_stdin, _) = parse_args::parse_args();

    info!("╔═══════════════════════╗");
    info!("║     PROVER CHAIN      ║");
    info!("╚═══════════════════════╝");
    let riscv = RiscvProver::new_initial_prover((RiscvBBSC::new(), elf), Default::default(), None);
    let convert = ConvertProver::new_with_prev(&riscv, Default::default(), None);
    let combine = CombineProver::new_with_prev(&convert, Default::default(), None);
    let compress = CompressProver::new_with_prev(&combine, Default::default(), None);
    let embed = EmbedProver::<_, _, Vec<u8>>::new_with_prev(&compress, Default::default(), None);

    let riscv_vk = riscv.vk();

    info!("Proving RISCV..");
    let proof = riscv.prove(riscv_stdin);
    assert!(riscv.verify(&proof, riscv_vk));
    info!("Proving Recursion..");
    let proof = convert.prove(proof);
    assert!(convert.verify(&proof, riscv_vk));
    let proof = combine.prove(proof);
    assert!(combine.verify(&proof, riscv_vk));
    let proof = compress.prove(proof);
    assert!(compress.verify(&proof, riscv_vk));
    let proof = embed.prove(proof);
    assert!(embed.verify(&proof, riscv_vk));

    info!("ProverChain e2e succeeded.");
}
