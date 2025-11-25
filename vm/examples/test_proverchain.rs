use pico_vm::{
    configs::config::StarkGenericConfig,
    instances::configs::{
        riscv_bb_poseidon2::StarkConfig as RiscvBBSC, riscv_kb_poseidon2::StarkConfig as RiscvKBSC,
    },
    machine::logger::setup_logger,
    proverchain::{
        CombineProver, CompressProver, ConvertProver, EmbedProver, InitialProverSetup,
        MachineProver, ProverChain, RiscvProver,
    },
};

use pico_vm::configs::stark_config::KoalaBearPoseidon2;
use tracing::info;

#[path = "common/parse_args.rs"]
mod parse_args;
#[path = "common/print_utils.rs"]
mod print_utils;
use print_utils::log_section;

#[allow(clippy::unit_arg)]
fn main() {
    setup_logger();
    let (elf, riscv_stdin, _) = parse_args::parse_args::<KoalaBearPoseidon2>();

    log_section("KB PROVER CHAIN");
    let riscv = RiscvProver::new_initial_prover((RiscvKBSC::new(), elf), Default::default(), None);
    let convert = ConvertProver::new_with_prev(&riscv, Default::default(), None);
    let combine = CombineProver::new_with_prev(&convert, Default::default(), None);
    let compress = CompressProver::new_with_prev(&combine, Default::default(), None);
    let embed = EmbedProver::<_, _, Vec<u8>>::new_with_prev(&compress, Default::default(), None);

    let riscv_vk = riscv.vk();

    info!("Proving RISCV..");
    let proof = riscv.prove(riscv_stdin.clone());
    assert!(riscv.verify(&proof, riscv_vk));

    let kb_meta_bytes =
        bincode::serialize(&proof).expect("serialize KB RISCV MetaProof");
    info!(
        "KB RISCV MetaProof total size = {} bytes (~{:.2} KiB)",
        kb_meta_bytes.len(),
        kb_meta_bytes.len() as f64 / 1024.0
    );
    for (i, base_proof) in proof.proofs.iter().enumerate() {
        let bytes = bincode::serialize(base_proof)
            .expect("serialize KB RISCV BaseProof");
        info!(
            "KB RISCV BaseProof[{}] size = {} bytes (~{:.2} KiB)",
            i,
            bytes.len(),
            bytes.len() as f64 / 1024.0,
        );
    }
    info!("Proving RECURSION..");
    let proof = convert.prove(proof);
    assert!(convert.verify(&proof, riscv_vk));
    let proof = combine.prove(proof);
    assert!(combine.verify(&proof, riscv_vk));
    let proof = compress.prove(proof);
    assert!(compress.verify(&proof, riscv_vk));
    let proof = embed.prove(proof);
    assert!(embed.verify(&proof, riscv_vk));

    info!("ProverChain on KoalaBear succeeded.");

    log_section("BB PROVER CHAIN");
    let riscv = RiscvProver::new_initial_prover((RiscvBBSC::new(), elf), Default::default(), None);
    let convert = ConvertProver::new_with_prev(&riscv, Default::default(), None);
    let combine = CombineProver::new_with_prev(&convert, Default::default(), None);
    let compress = CompressProver::new_with_prev(&combine, Default::default(), None);
    let embed = EmbedProver::<_, _, Vec<u8>>::new_with_prev(&compress, Default::default(), None);

    let riscv_vk = riscv.vk();

    info!("Proving RISCV..");
    let proof = riscv.prove(riscv_stdin);
    assert!(riscv.verify(&proof, riscv_vk));
    info!("Proving RECURSION..");
    let proof = convert.prove(proof);
    assert!(convert.verify(&proof, riscv_vk));
    let proof = combine.prove(proof);
    assert!(combine.verify(&proof, riscv_vk));
    let proof = compress.prove(proof);
    assert!(compress.verify(&proof, riscv_vk));
    let proof = embed.prove(proof);
    assert!(embed.verify(&proof, riscv_vk));

    info!("ProverChain on BabyBear succeeded.");
}
