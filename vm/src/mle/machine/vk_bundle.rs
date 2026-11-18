//! The VK bundle (v2) a verifier of whitelist-mode root proofs is handed.
//!
//! The format, its decoder and the apex built from it are `pico_verifier::bundle`'s; this module
//! adds what needs the prover: the guest identity from an ELF and the members from a whitelist.
//!
//! TODO(compress-apex): [`apex_from_bundle`] builds `pico_verifier`'s apex, which verifies the
//! combine root only, not this crate's `MleApexVerifier`; a compress proof is verified by the
//! latter.

use std::sync::Arc;

pub use pico_verifier::bundle::{
    apex_from_bundle, decode_vk_bundle_v3, DecodedVkBundle, MleVkBundleV3, MleVkMemberV3,
    VK_BUNDLE_V3, VK_MAGIC,
};
use pico_verifier::VmVk;

use crate::{
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    mle::machine::{
        combine::CombineMachine,
        exe::RiscvVmVk,
        shape::mle_riscv_shapes,
        vk_map::{whitelist_riscv_vk, MleVkMap, VkMembership},
    },
};

/// The whitelist leaves a bundle carries memberships for: the keys an outermost proof can have,
/// which are the complete combine roots and the compress node. In the artifact's leaf order the
/// combine keys follow the convert keys, the roots their second half
/// (`CombineMachine::preregister_standard_shapes`), and the compress key is the last leaf.
///
/// The inner combine nodes, the global LogUp's nodes and the deferred node are leaves too, and
/// no proof under one of them is outermost: the apex's check on the public values
/// (`flag_complete`) refuses it, and leaving their memberships out refuses it once more.
///
/// Empty for a map too short to be a whitelist.
pub fn root_capable_leaves(map: &MleVkMap) -> Vec<usize> {
    let combine = mle_riscv_shapes().len();
    let nodes = CombineMachine::standard_node_count();
    match map.entries.len().checked_sub(1) {
        Some(compress) if compress >= combine + nodes => (combine + nodes / 2..combine + nodes)
            .chain([compress])
            .collect(),
        _ => Vec::new(),
    }
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

/// The bundle's `vm_vk` field: the 20 limbs of `RiscvVmVk::digest_preimage` past its domain tag.
pub fn vm_vk_to_u32s(vm_vk: &RiscvVmVk) -> Vec<u32> {
    vm_vk.vm_vk().to_u32s()
}

/// The bundle for `vm_vk` under the whitelist `map`, with every root-capable key's membership.
pub fn encode_vk_bundle_v3(vm_vk: &RiscvVmVk, map: &MleVkMap) -> Result<Vec<u8>, String> {
    encode_with_members(&vm_vk.vm_vk(), map, root_capable_leaves(map))
}

/// [`encode_vk_bundle_v3`] over the memberships of `leaves`.
fn encode_with_members(
    vm_vk: &VmVk,
    map: &MleVkMap,
    leaves: Vec<usize>,
) -> Result<Vec<u8>, String> {
    if leaves.is_empty() || leaves.iter().any(|&leaf| leaf >= map.entries.len()) {
        return Err(format!(
            "no root-capable leaves in a whitelist of {} entries (leaves {leaves:?})",
            map.entries.len()
        ));
    }
    let members: Vec<VkMembership> = leaves.into_iter().map(|i| map.membership(i)).collect();
    pico_verifier::bundle::encode_vk_bundle_v3(vm_vk, &map.root(), &members)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;

    use crate::mle::machine::recursion::Kb;

    use super::*;

    fn identity(seed: u32) -> ([Kb; 8], [Kb; 8]) {
        (
            std::array::from_fn(|i| Kb::from_u32(seed + i as u32)),
            std::array::from_fn(|i| Kb::from_u32(500 + seed + i as u32)),
        )
    }

    fn sample_vm_vk() -> RiscvVmVk {
        RiscvVmVk::from_vm_vk(&VmVk::from_u32s(&(1..=20).collect::<Vec<u32>>()).unwrap())
    }

    /// The identity's 20 limbs survive the u32 round trip in `digest_preimage` order.
    #[test]
    fn vm_vk_round_trips() {
        let vm_vk = sample_vm_vk();
        assert_eq!(vm_vk_to_u32s(&vm_vk), (1..=20).collect::<Vec<u32>>());
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
        let bytes = encode_with_members(&vm_vk.vm_vk(), &map, (30..40).collect()).unwrap();
        assert_eq!(bytes[..8], VK_MAGIC);
        let decoded = decode_vk_bundle_v3(&bytes).unwrap();
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
        assert!(encode_with_members(&vm_vk, &map40(), Vec::new()).is_err());
        assert!(encode_with_members(&vm_vk, &map40(), (30..41).collect()).is_err());
        assert!(root_capable_leaves(&map40()).is_empty());
        assert!(encode_vk_bundle_v3(&sample_vm_vk(), &map40()).is_err());
    }

    /// In a map laid out as the whitelist is, the root-capable leaves are the complete combine
    /// roots and the last leaf: not the inner nodes before them, nor the leaves between.
    #[test]
    fn the_root_capable_leaves_are_the_complete_roots_and_compress() {
        let combine = mle_riscv_shapes().len();
        let nodes = CombineMachine::standard_node_count();
        // Convert keys, the combine nodes, three more leaves, the compress key.
        let leaves = combine + nodes + 3 + 1;
        let map = MleVkMap::build((0..leaves as u32).map(identity).collect());
        let capable = root_capable_leaves(&map);
        let mut expected: Vec<usize> = (combine + nodes / 2..combine + nodes).collect();
        expected.push(leaves - 1);
        assert_eq!(capable, expected);
        assert_eq!(capable.len(), nodes / 2 + 1);
    }
}
