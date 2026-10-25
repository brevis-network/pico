//! The VK bundle an ethproofs cluster version carries, so that a verifier can check our v3 proofs.
//!
//! `PICOMLEV` | 2 (u32 LE) | zstd(bincode of [`MleVkBundleV2`]). Field order is the wire format;
//! the verifier (ethproofs' `pico-wasm-stark-verifier`) declares the same structs.
//!
//! v2 replaces v1's whole whitelist (the 1 MB artifact) with Merkle memberships of the keys a root
//! proof can carry. The apex authenticates only the root's vk out of circuit -- every other key is
//! checked in-circuit against the root -- so these memberships are all it needs. They depend on the
//! whitelist only through its root, so a verifier reading them needs no shape config: a new
//! whitelist means a new bundle, not a new verifier.

use std::sync::Arc;

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use pico_vm::{
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    machine::septic::{SepticCurve, SepticDigest, SepticExtension},
    mle::machine::{
        apex::MleApexVerifier,
        exe::RiscvVmVk,
        recursion::Kb,
        shape::mle_riscv_shapes,
        vk_map::{whitelist_riscv_vk, MleVkMap, VkMembership},
    },
};
use serde::{Deserialize, Serialize};

pub const VK_MAGIC: [u8; 8] = *b"PICOMLEV";
pub const VK_BUNDLE_V2: u32 = 2;

/// Built once per whitelist, offline, so the slowest level costs nothing that matters.
const VK_ZSTD_LEVEL: i32 = 19;

/// Bounds what a hostile bundle can make a decoder allocate. A real one is ~20 KB decompressed.
const MAX_BODY: u64 = 1 << 20;

#[derive(Serialize, Deserialize)]
pub struct MleVkBundleV2 {
    /// The guest identity: `RiscvVmVk::digest_preimage` without its domain tag, as canonical u32s
    /// -- program commit (8), entry pc (3), initial global cumulative sum x (7) and y (7).
    pub vm_vk: Vec<u32>,
    /// The pinned whitelist root, canonical u32 limbs.
    pub vk_root: [u32; 8],
    /// Memberships of the keys a root can carry, in leaf order.
    pub members: Vec<MleVkMemberV2>,
}

#[derive(Serialize, Deserialize)]
pub struct MleVkMemberV2 {
    pub pre_hash: [u32; 8],
    pub merged_commit: [u32; 8],
    pub index: u32,
    /// One sibling digest per level, bottom-up.
    pub siblings: Vec<[u32; 8]>,
}

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

fn limbs(d: &[Kb; 8]) -> [u32; 8] {
    d.map(|f| f.as_canonical_u32())
}

fn field_limbs(d: &[u32; 8]) -> [Kb; 8] {
    d.map(Kb::from_u32)
}

pub fn vm_vk_to_u32s(vm_vk: &RiscvVmVk) -> Vec<u32> {
    // [1..]: past the domain tag.
    vm_vk.digest_preimage()[1..]
        .iter()
        .map(|f| f.as_canonical_u32())
        .collect()
}

pub fn vm_vk_from_u32s(e: &[u32]) -> Result<RiscvVmVk, String> {
    if e.len() != 25 {
        return Err(format!(
            "the guest identity needs 25 field elements, got {}",
            e.len()
        ));
    }
    let k = |i: usize| Kb::from_u32(e[i]);
    Ok(RiscvVmVk {
        program_commit: std::array::from_fn(k),
        pc_start: [k(8), k(9), k(10)],
        initial_gcs: SepticDigest(SepticCurve {
            x: SepticExtension(std::array::from_fn(|i| k(11 + i))),
            y: SepticExtension(std::array::from_fn(|i| k(18 + i))),
        }),
    })
}

/// The bundle for `vm_vk` under the whitelist `map`, with every root-capable key's membership.
pub fn encode_vk_bundle_v2(vm_vk: &RiscvVmVk, map: &MleVkMap) -> Result<Vec<u8>, String> {
    encode_with_members(vm_vk, map, root_capable_leaves(map))
}

/// [`encode_vk_bundle_v2`] over the memberships of `leaves`.
fn encode_with_members(
    vm_vk: &RiscvVmVk,
    map: &MleVkMap,
    leaves: std::ops::Range<usize>,
) -> Result<Vec<u8>, String> {
    if leaves.is_empty() || leaves.end > map.entries.len() {
        return Err(format!(
            "no root-capable leaves in a whitelist of {} entries (leaves {leaves:?})",
            map.entries.len()
        ));
    }
    let root = map.root();
    let members: Vec<MleVkMemberV2> = leaves
        .map(|i| {
            let m = map.membership(i);
            MleVkMemberV2 {
                pre_hash: limbs(&m.identity.0),
                merged_commit: limbs(&m.identity.1),
                index: m.index as u32,
                siblings: m.siblings.iter().map(limbs).collect(),
            }
        })
        .collect();
    let bundle = MleVkBundleV2 {
        vm_vk: vm_vk_to_u32s(vm_vk),
        vk_root: limbs(&root),
        members,
    };
    let raw = bincode::serialize(&bundle).map_err(|e| e.to_string())?;
    let body = zstd::encode_all(raw.as_slice(), VK_ZSTD_LEVEL).map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(VK_MAGIC.len() + 4 + body.len());
    out.extend_from_slice(&VK_MAGIC);
    out.extend_from_slice(&VK_BUNDLE_V2.to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// What a v2 bundle says, as the apex takes it.
pub struct DecodedVkBundle {
    pub vm_vk: RiscvVmVk,
    pub vk_root: [Kb; 8],
    pub members: Vec<VkMembership>,
}

/// Read a v2 bundle back: the inverse of [`encode_vk_bundle_v2`], bounded against hostile input.
pub fn decode_vk_bundle_v2(bytes: &[u8]) -> Result<DecodedVkBundle, String> {
    use bincode::Options;
    use std::io::Read;
    if bytes.len() < 12 || bytes[..8] != VK_MAGIC {
        return Err("not an MLE VK bundle (magic)".into());
    }
    let version = u32::from_le_bytes(bytes[8..12].try_into().expect("4 bytes"));
    if version != VK_BUNDLE_V2 {
        return Err(format!(
            "MLE VK bundle version {version}, expected {VK_BUNDLE_V2}"
        ));
    }
    let mut raw = Vec::new();
    zstd::Decoder::new(&bytes[12..])
        .map_err(|e| e.to_string())?
        .take(MAX_BODY + 1)
        .read_to_end(&mut raw)
        .map_err(|e| e.to_string())?;
    if raw.len() as u64 > MAX_BODY {
        return Err("MLE VK bundle body too large".into());
    }
    let bundle: MleVkBundleV2 = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_BODY)
        .deserialize(&raw)
        .map_err(|e| e.to_string())?;
    Ok(DecodedVkBundle {
        vm_vk: vm_vk_from_u32s(&bundle.vm_vk)?,
        vk_root: field_limbs(&bundle.vk_root),
        members: bundle
            .members
            .iter()
            .map(|m| VkMembership {
                identity: (field_limbs(&m.pre_hash), field_limbs(&m.merged_commit)),
                index: m.index as usize,
                siblings: m.siblings.iter().map(field_limbs).collect(),
            })
            .collect(),
    })
}

/// The apex a verifier builds from a bundle: every membership must reach the bundle's root.
pub fn apex_from_bundle(bundle: DecodedVkBundle) -> Result<MleApexVerifier, String> {
    MleApexVerifier::with_members(
        pico_vm::mle::recursion_params_with_100_bits_security(),
        bundle.members,
        bundle.vm_vk,
        bundle.vk_root,
    )
    .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(seed: u32) -> ([Kb; 8], [Kb; 8]) {
        (
            std::array::from_fn(|i| Kb::from_u32(seed + i as u32)),
            std::array::from_fn(|i| Kb::from_u32(500 + seed + i as u32)),
        )
    }

    fn sample_vm_vk() -> RiscvVmVk {
        vm_vk_from_u32s(&(1..=25).collect::<Vec<u32>>()).unwrap()
    }

    /// The identity's 25 limbs survive the u32 round trip in `digest_preimage` order.
    #[test]
    fn vm_vk_round_trips() {
        let vm_vk = sample_vm_vk();
        assert_eq!(vm_vk_to_u32s(&vm_vk), (1..=25).collect::<Vec<u32>>());
        assert_eq!(
            vm_vk_from_u32s(&vm_vk_to_u32s(&vm_vk)).unwrap().digest(),
            vm_vk.digest()
        );
    }

    fn map40() -> MleVkMap {
        MleVkMap::build((0..40).map(|i| identity(i * 100)).collect())
    }

    /// A bundle decodes to what it was built from, and every member reaches the root.
    #[test]
    fn bundle_round_trips_and_its_members_verify() {
        let map = map40();
        let vm_vk = sample_vm_vk();
        let bytes = encode_with_members(&vm_vk, &map, 30..40).unwrap();
        assert_eq!(bytes[..8], VK_MAGIC);
        let decoded = decode_vk_bundle_v2(&bytes).unwrap();
        assert_eq!(decoded.vm_vk.digest(), vm_vk.digest());
        assert_eq!(decoded.vk_root, map.root());
        let expected: Vec<VkMembership> = (30..40).map(|i| map.membership(i)).collect();
        assert_eq!(decoded.members, expected);
        assert!(decoded
            .members
            .iter()
            .all(|m| m.verifies_against(&map.root())));
        assert!(apex_from_bundle(decoded).is_ok());
    }

    /// No root-capable leaves (a whitelist shorter than the convert keys) is an error, not an
    /// empty bundle that would verify nothing.
    #[test]
    fn an_empty_member_set_is_refused() {
        assert!(encode_with_members(&sample_vm_vk(), &map40(), 40..40).is_err());
        assert!(encode_with_members(&sample_vm_vk(), &map40(), 30..41).is_err());
    }

    /// Another version, a foreign magic or a cut body is refused, not misread.
    #[test]
    fn decode_refuses_what_it_does_not_know() {
        let map = map40();
        let bytes = encode_with_members(&sample_vm_vk(), &map, 30..40).unwrap();
        let mut v1 = bytes.clone();
        v1[8..12].copy_from_slice(&1u32.to_le_bytes());
        assert!(decode_vk_bundle_v2(&v1).is_err());
        let mut foreign = bytes.clone();
        foreign[..8].copy_from_slice(b"PICOMLE\0");
        assert!(decode_vk_bundle_v2(&foreign).is_err());
        assert!(decode_vk_bundle_v2(&bytes[..bytes.len() / 2]).is_err());
    }
}
