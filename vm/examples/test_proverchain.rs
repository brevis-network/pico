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
use std::{
    fs,
    path::{Path, PathBuf},
};

use pico_vm::machine::keys::BaseVerifyingKey;
use tracing::info;

#[path = "common/parse_args.rs"]
mod parse_args;
#[path = "common/print_utils.rs"]
mod print_utils;
use print_utils::log_section;

const RISCV_VK_DIR: &str = "riscv_vks";

/// Helper: dump a verifying key to disk (binary)
fn save_vk<P, SC>(vk: &BaseVerifyingKey<SC>, name: P) -> anyhow::Result<()>
where
    P: AsRef<Path>,
    SC: StarkGenericConfig,
    BaseVerifyingKey<SC>: serde::Serialize,
{
    let mut path = PathBuf::from(RISCV_VK_DIR);
    fs::create_dir_all(&path)?; // no‑op if it already exists
    path.push(name);

    fs::write(&path, bincode::serialize(vk)?)?;
    Ok(())
}

fn load_vk<SC>(name: &str) -> anyhow::Result<BaseVerifyingKey<SC>>
where
    SC: StarkGenericConfig,
    BaseVerifyingKey<SC>: serde::de::DeserializeOwned,
{
    let path = Path::new(RISCV_VK_DIR).join(name);
    Ok(bincode::deserialize(&fs::read(path)?)?)
}

#[allow(clippy::unit_arg)]
fn main() {
    setup_logger();
    let (elf, riscv_stdin, _) = parse_args::parse_args();

    log_section("KB PROVER CHAIN");
    let riscv = RiscvProver::new_initial_prover((RiscvKBSC::new(), elf), Default::default(), None);
    let convert = ConvertProver::new_with_prev(&riscv, Default::default(), None);
    let combine = CombineProver::new_with_prev(&convert, Default::default(), None);
    let compress = CompressProver::new_with_prev(&combine, Default::default(), None);
    let embed = EmbedProver::<_, _, Vec<u8>>::new_with_prev(&compress, Default::default(), None);

    let riscv_vk = riscv.vk();
    let vk_filename = "riscv_vk_kb.bin";
    save_vk::<_, RiscvKBSC>(&riscv_vk, vk_filename).unwrap();
    let riscv_vk: BaseVerifyingKey<RiscvKBSC> = load_vk(vk_filename).unwrap();

    info!("Proving RISCV..");
    let proof = riscv.prove(riscv_stdin.clone());
    assert!(riscv.verify(&proof, &riscv_vk));
    info!("Proving RECURSION..");
    let proof = convert.prove(proof);
    assert!(convert.verify(&proof, &riscv_vk));
    let proof = combine.prove(proof);
    assert!(combine.verify(&proof, &riscv_vk));
    let proof = compress.prove(proof);
    assert!(compress.verify(&proof, &riscv_vk));
    let proof = embed.prove(proof);
    assert!(embed.verify(&proof, &riscv_vk));

    info!("ProverChain on KoalaBear succeeded.");

    log_section("BB PROVER CHAIN");
    let riscv = RiscvProver::new_initial_prover((RiscvBBSC::new(), elf), Default::default(), None);
    let convert = ConvertProver::new_with_prev(&riscv, Default::default(), None);
    let combine = CombineProver::new_with_prev(&convert, Default::default(), None);
    let compress = CompressProver::new_with_prev(&combine, Default::default(), None);
    let embed = EmbedProver::<_, _, Vec<u8>>::new_with_prev(&compress, Default::default(), None);

    let riscv_vk = riscv.vk();
    let vk_filename = "riscv_vk_bb.bin";
    save_vk::<_, RiscvBBSC>(&riscv_vk, vk_filename).unwrap();
    let riscv_vk: BaseVerifyingKey<RiscvBBSC> = load_vk(vk_filename).unwrap();

    info!("Proving RISCV..");
    let proof = riscv.prove(riscv_stdin);
    assert!(riscv.verify(&proof, &riscv_vk));
    info!("Proving RECURSION..");
    let proof = convert.prove(proof);
    assert!(convert.verify(&proof, &riscv_vk));
    let proof = combine.prove(proof);
    assert!(combine.verify(&proof, &riscv_vk));
    let proof = compress.prove(proof);
    assert!(compress.verify(&proof, &riscv_vk));
    let proof = embed.prove(proof);
    assert!(embed.verify(&proof, &riscv_vk));

    info!("ProverChain on BabyBear succeeded.");
}
