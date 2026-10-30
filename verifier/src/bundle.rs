//! The VK bundle a verifier is handed: `PICOMLEV` | 2 (u32 LE) | zstd(bincode of
//! [`MleVkBundleV2`]). Field order is the wire format; ethproofs' `pico-wasm-stark-verifier`
//! declares the same structs.
//!
//! It carries the exe identity, the pinned whitelist root, and the Merkle memberships of the keys a
//! root proof can carry. The memberships depend on the whitelist only through its root, so a
//! verifier reading them needs no shape config.

use pico_mle_core::config::recursion_params_with_100_bits_security;
use serde::{Deserialize, Serialize};

use crate::{
    hash::{digest_from_u32s, digest_to_u32s},
    whitelist::VkMembership,
    Kb, MleApexVerifier, VerifyError, VmVk,
};

pub const VK_MAGIC: [u8; 8] = *b"PICOMLEV";
pub const VK_BUNDLE_V2: u32 = 2;

/// Built once per whitelist, offline, so the slowest level costs nothing that matters.
const VK_ZSTD_LEVEL: i32 = 19;

/// Bounds what a hostile bundle can make a decoder allocate. A real one is ~20 KB decompressed.
const MAX_BODY: u64 = 1 << 20;

#[derive(Serialize, Deserialize)]
pub struct MleVkBundleV2 {
    /// The guest identity, [`VmVk::to_u32s`]: program commit (8), entry pc (3), initial global
    /// cumulative sum x (7) and y (7).
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

/// What a v2 bundle says, as the apex takes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedVkBundle {
    pub vm_vk: VmVk,
    pub vk_root: [Kb; 8],
    pub members: Vec<VkMembership>,
}

/// Encode a v2 bundle. Refuses an empty member set, which would verify nothing.
pub fn encode_vk_bundle_v2(
    vm_vk: &VmVk,
    vk_root: &[Kb; 8],
    members: &[VkMembership],
) -> Result<Vec<u8>, VerifyError> {
    if members.is_empty() {
        return Err(VerifyError::Bundle("no whitelist members".into()));
    }
    let bundle = MleVkBundleV2 {
        vm_vk: vm_vk.to_u32s(),
        vk_root: digest_to_u32s(vk_root),
        members: members
            .iter()
            .map(|m| MleVkMemberV2 {
                pre_hash: digest_to_u32s(&m.identity.0),
                merged_commit: digest_to_u32s(&m.identity.1),
                index: m.index as u32,
                siblings: m.siblings.iter().map(digest_to_u32s).collect(),
            })
            .collect(),
    };
    let bundle_err = |e: &dyn std::fmt::Display| VerifyError::Bundle(e.to_string());
    let raw = bincode::serialize(&bundle).map_err(|e| bundle_err(&e))?;
    let body = zstd::encode_all(raw.as_slice(), VK_ZSTD_LEVEL).map_err(|e| bundle_err(&e))?;
    let mut out = Vec::with_capacity(VK_MAGIC.len() + 4 + body.len());
    out.extend_from_slice(&VK_MAGIC);
    out.extend_from_slice(&VK_BUNDLE_V2.to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Read a v2 bundle back: the inverse of [`encode_vk_bundle_v2`], bounded against hostile input.
///
/// Limbs are reduced mod p, so a non-canonical `u32` decodes to the field element it is congruent
/// to rather than being refused.
pub fn decode_vk_bundle_v2(bytes: &[u8]) -> Result<DecodedVkBundle, VerifyError> {
    use bincode::Options;
    use std::io::Read;
    let err = |m: String| VerifyError::Bundle(m);
    if bytes.len() < 12 || bytes[..8] != VK_MAGIC {
        return Err(err("not an MLE VK bundle (magic)".into()));
    }
    let version = u32::from_le_bytes(bytes[8..12].try_into().expect("4 bytes"));
    if version != VK_BUNDLE_V2 {
        return Err(err(format!(
            "MLE VK bundle version {version}, expected {VK_BUNDLE_V2}"
        )));
    }
    let mut raw = Vec::new();
    zstd::Decoder::new(&bytes[12..])
        .map_err(|e| err(e.to_string()))?
        .take(MAX_BODY + 1)
        .read_to_end(&mut raw)
        .map_err(|e| err(e.to_string()))?;
    if raw.len() as u64 > MAX_BODY {
        return Err(err("MLE VK bundle body too large".into()));
    }
    let bundle: MleVkBundleV2 = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(MAX_BODY)
        .deserialize(&raw)
        .map_err(|e| err(e.to_string()))?;
    Ok(DecodedVkBundle {
        vm_vk: VmVk::from_u32s(&bundle.vm_vk)?,
        vk_root: digest_from_u32s(&bundle.vk_root),
        members: bundle
            .members
            .iter()
            .map(|m| VkMembership {
                identity: (
                    digest_from_u32s(&m.pre_hash),
                    digest_from_u32s(&m.merged_commit),
                ),
                index: m.index as usize,
                siblings: m.siblings.iter().map(digest_from_u32s).collect(),
            })
            .collect(),
    })
}

/// The apex a verifier builds from a bundle under `trusted_root`, the whitelist root the caller
/// pins. The bundle's own root is refused unless it is that one: a self-made whitelist builds its
/// own root, so trusting the bundle's would accept any proof.
pub fn apex_from_bundle(
    bundle: &DecodedVkBundle,
    trusted_root: [Kb; 8],
) -> Result<MleApexVerifier, VerifyError> {
    if bundle.vk_root != trusted_root {
        return Err(VerifyError::UntrustedVkRoot);
    }
    MleApexVerifier::with_members(
        recursion_params_with_100_bits_security(),
        bundle.members.clone(),
        bundle.vm_vk,
        trusted_root,
    )
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::whitelist::{tests::id, VkIdentity, VkMerkleTree};

    fn sample_vm_vk() -> VmVk {
        VmVk::from_u32s(&(1..=25).collect::<Vec<u32>>()).unwrap()
    }

    fn tree40() -> (Vec<VkIdentity>, VkMerkleTree) {
        let entries: Vec<VkIdentity> = (0..40).map(|i| id(i * 100)).collect();
        let tree = VkMerkleTree::try_build(&entries).unwrap();
        (entries, tree)
    }

    fn members(entries: &[VkIdentity], tree: &VkMerkleTree) -> Vec<VkMembership> {
        (30..40).map(|i| tree.membership(i, entries[i])).collect()
    }

    fn sample_bundle() -> Vec<u8> {
        let (entries, tree) = tree40();
        encode_vk_bundle_v2(&sample_vm_vk(), &tree.root(), &members(&entries, &tree)).unwrap()
    }

    /// A bundle decodes to what it was built from, and every member reaches the root.
    #[test]
    fn bundle_round_trips_and_its_members_verify() {
        let (entries, tree) = tree40();
        let members = members(&entries, &tree);
        let bytes = encode_vk_bundle_v2(&sample_vm_vk(), &tree.root(), &members).unwrap();
        assert_eq!(bytes[..8], VK_MAGIC);
        let decoded = decode_vk_bundle_v2(&bytes).unwrap();
        assert_eq!(decoded.vm_vk, sample_vm_vk());
        assert_eq!(decoded.vk_root, tree.root());
        assert_eq!(decoded.members, members);
        assert!(decoded
            .members
            .iter()
            .all(|m| m.verifies_against(&tree.root())));
        assert!(apex_from_bundle(&decoded, tree.root()).is_ok());
    }

    /// An empty member set is an error, not a bundle that would verify nothing.
    #[test]
    fn an_empty_member_set_is_refused() {
        let (_, tree) = tree40();
        assert!(encode_vk_bundle_v2(&sample_vm_vk(), &tree.root(), &[]).is_err());
    }

    /// Another version, a foreign magic or a cut body is refused, not misread.
    #[test]
    fn decode_refuses_what_it_does_not_know() {
        let bytes = sample_bundle();
        let mut v1 = bytes.clone();
        v1[8..12].copy_from_slice(&1u32.to_le_bytes());
        assert!(decode_vk_bundle_v2(&v1).is_err());
        let mut foreign = bytes.clone();
        foreign[..8].copy_from_slice(b"PICOMLE\0");
        assert!(decode_vk_bundle_v2(&foreign).is_err());
        assert!(decode_vk_bundle_v2(&bytes[..bytes.len() / 2]).is_err());
        assert!(decode_vk_bundle_v2(&bytes[..11]).is_err());
    }

    /// A bundle whose root does not match its members builds no apex.
    #[test]
    fn a_bundle_with_a_foreign_root_builds_no_apex() {
        let (entries, tree) = tree40();
        let mut root = tree.root();
        root[0] += Kb::ONE;
        let bytes = encode_vk_bundle_v2(&sample_vm_vk(), &root, &members(&entries, &tree)).unwrap();
        let err = apex_from_bundle(&decode_vk_bundle_v2(&bytes).unwrap(), root)
            .err()
            .expect("members off the root");
        assert!(
            matches!(err, VerifyError::MemberOffRoot { index: 30 }),
            "{err}"
        );
    }

    /// A bundle under any root but the trusted one builds no apex, even when its members reach it.
    #[test]
    fn a_bundle_under_an_untrusted_root_builds_no_apex() {
        let (entries, tree) = tree40();
        let decoded = decode_vk_bundle_v2(&sample_bundle()).unwrap();
        assert!(members(&entries, &tree)
            .iter()
            .all(|m| m.verifies_against(&decoded.vk_root)));
        let err = apex_from_bundle(&decoded, crate::whitelist::shipped_vk_root())
            .err()
            .expect("a self-made root");
        assert!(matches!(err, VerifyError::UntrustedVkRoot), "{err}");
    }
}
