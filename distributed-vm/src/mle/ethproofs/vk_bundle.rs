//! The VK bundle an ethproofs cluster version carries, so that a verifier can check our v3 proofs.
//!
//! The format, its decoder and the apex built from it are `pico_verifier::bundle`'s; this module
//! adds what needs the prover: the guest identity from an ELF and the members from a whitelist.

use std::sync::Arc;

pub use pico_verifier::bundle::{
    apex_from_bundle, decode_vk_bundle_v2, DecodedVkBundle, MleVkBundleV2, MleVkMemberV2,
    VK_BUNDLE_V2, VK_MAGIC,
};
use pico_verifier::VmVk;
use pico_vm::{
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    mle::machine::{
        exe::RiscvVmVk,
        shape::mle_riscv_shapes,
        vk_map::{whitelist_riscv_vk, MleVkMap, VkMembership},
    },
};

/// The whitelist leaves a root proof's vk can be: everything after the convert keys, which is to
/// say the combine node keys and the deferred node key (the artifact's leaf order).
pub fn root_capable_leaves(map: &MleVkMap) -> std::ops::Range<usize> {
    mle_riscv_shapes().len()..map.entries.len()
}

/// The guest identity a bundle names: the riscv vk keygen'd on the CPU, as the whitelist builder
/// does it, for the program the prover proves.
pub fn riscv_vm_vk_for_elf(elf: &[u8]) -> Result<RiscvVmVk, String> {
    let program: Arc<Program> = Compiler::new(SourceType::RISCV, elf)
        .map_err(|e| format!("ELF does not parse: {e:?}"))?
        .compile();
    let riscv_vk =
        whitelist_riscv_vk(program.clone()).map_err(|e| format!("riscv keygen refused: {e}"))?;
    Ok(RiscvVmVk::from_program_and_vk(&program, &riscv_vk))
}

/// The bundle's `vm_vk` field: the 25 limbs of `RiscvVmVk::digest_preimage` past its domain tag.
pub fn vm_vk_to_u32s(vm_vk: &RiscvVmVk) -> Vec<u32> {
    vm_vk.vm_vk().to_u32s()
}

/// The bundle for `vm_vk` under the whitelist `map`, with every root-capable key's membership.
pub fn encode_vk_bundle_v2(vm_vk: &RiscvVmVk, map: &MleVkMap) -> Result<Vec<u8>, String> {
    encode_with_members(&vm_vk.vm_vk(), map, root_capable_leaves(map))
}

/// [`encode_vk_bundle_v2`] over the memberships of `leaves`.
fn encode_with_members(
    vm_vk: &VmVk,
    map: &MleVkMap,
    leaves: std::ops::Range<usize>,
) -> Result<Vec<u8>, String> {
    if leaves.is_empty() || leaves.end > map.entries.len() {
        return Err(format!(
            "no root-capable leaves in a whitelist of {} entries (leaves {leaves:?})",
            map.entries.len()
        ));
    }
    let members: Vec<VkMembership> = leaves.map(|i| map.membership(i)).collect();
    pico_verifier::bundle::encode_vk_bundle_v2(vm_vk, &map.root(), &members)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;
    use pico_vm::mle::machine::recursion::Kb;

    use super::*;

    fn identity(seed: u32) -> ([Kb; 8], [Kb; 8]) {
        (
            std::array::from_fn(|i| Kb::from_u32(seed + i as u32)),
            std::array::from_fn(|i| Kb::from_u32(500 + seed + i as u32)),
        )
    }

    fn sample_vm_vk() -> RiscvVmVk {
        RiscvVmVk::from_vm_vk(&VmVk::from_u32s(&(1..=25).collect::<Vec<u32>>()).unwrap())
    }

    /// The identity's 25 limbs survive the u32 round trip in `digest_preimage` order.
    #[test]
    fn vm_vk_round_trips() {
        let vm_vk = sample_vm_vk();
        assert_eq!(vm_vk_to_u32s(&vm_vk), (1..=25).collect::<Vec<u32>>());
        let back = VmVk::from_u32s(&vm_vk_to_u32s(&vm_vk)).unwrap();
        assert_eq!(back.digest(), vm_vk.digest());
    }

    fn map40() -> MleVkMap {
        MleVkMap::build((0..40).map(|i| identity(i * 100)).collect())
    }

    /// A bundle decodes to what it was built from, and the apex built from it accepts its members.
    #[test]
    fn bundle_round_trips_and_its_members_verify() {
        let map = map40();
        let vm_vk = sample_vm_vk();
        let bytes = encode_with_members(&vm_vk.vm_vk(), &map, 30..40).unwrap();
        assert_eq!(bytes[..8], VK_MAGIC);
        let decoded = decode_vk_bundle_v2(&bytes).unwrap();
        assert_eq!(decoded.vm_vk.digest(), vm_vk.digest());
        assert_eq!(decoded.vk_root, map.root());
        let expected: Vec<VkMembership> = (30..40).map(|i| map.membership(i)).collect();
        assert_eq!(decoded.members, expected);
        assert!(apex_from_bundle(&decoded, map.root()).is_ok());
    }

    /// No root-capable leaves (a whitelist shorter than the convert keys) is an error, not an
    /// empty bundle that would verify nothing.
    #[test]
    fn an_empty_member_set_is_refused() {
        let vm_vk = sample_vm_vk().vm_vk();
        assert!(encode_with_members(&vm_vk, &map40(), 40..40).is_err());
        assert!(encode_with_members(&vm_vk, &map40(), 30..41).is_err());
    }
}
