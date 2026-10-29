//! `mle-ethproofs-vk-bundle <out>`: build the VK bundle (v2) an ethproofs cluster version carries.
//!
//! The guest is the tree's reth-elf unless `--elf` names another, keygen'd on the CPU as the
//! whitelist builder does it. The whitelist is `MLE_VK_MAP` (default: the shipped artifact), pinned
//! by `MLE_VK_ROOT` when that is set. The bundle is decoded again and an apex built from it before
//! anything is written, so a bundle that would not verify anything never reaches a file.

use std::path::PathBuf;

use clap::Parser;
use distributed_vm::mle::ethproofs::vk_bundle::{
    apex_from_bundle, decode_vk_bundle_v2, encode_vk_bundle_v2, riscv_vm_vk_for_elf,
    root_capable_leaves, vm_vk_to_u32s,
};
use p3_field::PrimeField32;
use pico_vm::mle::machine::vk_map::MleVkMap;

#[derive(Parser)]
struct Args {
    /// Where to write the bundle.
    out: PathBuf,
    /// The guest ELF the cluster proves.
    #[clap(long, default_value = "perf/bench_data/rv64/reth-elf")]
    elf: PathBuf,
    /// The whitelist artifact.
    #[clap(
        long,
        env = "MLE_VK_MAP",
        default_value = "vm/src/mle/shape_vk_bins/mle_vk_map_kb.bin"
    )]
    vk_map: PathBuf,
}

fn main() -> Result<(), String> {
    let args = Args::parse();
    let map = MleVkMap::try_load(&args.vk_map).map_err(|e| e.to_string())?;
    let elf = std::fs::read(&args.elf).map_err(|e| format!("{}: {e}", args.elf.display()))?;
    let vm_vk = riscv_vm_vk_for_elf(&elf)?;

    let bytes = encode_vk_bundle_v2(&vm_vk, &map)?;
    let decoded = decode_vk_bundle_v2(&bytes).map_err(|e| e.to_string())?;
    let members = decoded.members.len();
    // `try_load` pinned the map to `MLE_VK_ROOT` when set, so this is the deployment's root.
    apex_from_bundle(&decoded, map.root()).map_err(|e| e.to_string())?;
    std::fs::write(&args.out, &bytes).map_err(|e| format!("{}: {e}", args.out.display()))?;

    let vm_vk_line: Vec<String> = vm_vk_to_u32s(&vm_vk).iter().map(u32::to_string).collect();
    let root: Vec<String> = map
        .root()
        .iter()
        .map(|f| f.as_canonical_u32().to_string())
        .collect();
    println!(
        "exe identity: digest {} | vm_vk ({} u32) = {}",
        vm_vk.digest_hex(),
        vm_vk_line.len(),
        vm_vk_line.join(" ")
    );
    println!("whitelist root: {}", root.join(" "));
    println!(
        "{members} root-capable member(s), leaves {:?} of {}",
        root_capable_leaves(&map),
        map.entries.len()
    );
    println!("wrote {} ({} B)", args.out.display(), bytes.len());
    Ok(())
}
