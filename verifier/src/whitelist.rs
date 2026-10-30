//! The recursion-VK whitelist as a fixed-depth Merkle tree over key identities.
//!
//! A key's identity is `(lean pre_hash, merged_preprocessed_commit)`. The leaf is
//! `sponge(LEAF_DOMAIN ‖ pre_hash ‖ merged_commit)` and interior nodes use the two-to-one
//! Poseidon2 compress, both byte-identical to their in-circuit mirrors, so a host-built path
//! verifies in-circuit. Unused leaves are zero digests. `pico-vm`'s `MleVkMap` (the artifact the
//! prover loads) is built on [`VkMerkleTree`].

use p3_field::PrimeCharacteristicRing;
use pico_mle_core::keygen::types::MultiStarkVerifyingKey;

use crate::{
    hash::{compress, sponge_hash},
    Kb, Sc,
};

/// Fixed Merkle depth: 2^15 = 32,768 whitelist slots. The whitelist holds 15,680 leaves (15,643
/// riscv shapes, 36 combine node shapes and the deferred node), so this leaves 109% headroom;
/// depth 14 would leave 704 free slots (4.3%). A new precompile kind sweeps a few hundred shapes,
/// so a few more kinds would use those up.
/// The depth is baked into the membership circuit, so changing it changes every combine VK and
/// the root.
pub const MLE_VK_MERKLE_DEPTH: usize = 15;

/// Domain separator for whitelist leaves (distinguishes leaf hashes from every other sponge use).
pub const VK_MAP_LEAF_DOMAIN: u32 = 0x564B_6D70; // "VKmp"

/// The root file shipped beside the repo's whitelist artifact. It lives outside this crate: a
/// path or git dependency (which fetches the whole repo) sees it, a crates.io package would not.
pub const SHIPPED_VK_ROOT_FILE: &str =
    include_str!("../../vm/src/mle/shape_vk_bins/mle_vk_root.txt");

/// The whitelist root [`SHIPPED_VK_ROOT_FILE`] pins: the one [`crate::verify`] trusts.
pub fn shipped_vk_root() -> [Kb; 8] {
    root_from_root_file(SHIPPED_VK_ROOT_FILE).expect("the shipped root file names a root")
}

/// The root a root file names, from its `MLE_VK_ROOT="..."` line of eight canonical limbs.
pub fn root_from_root_file(text: &str) -> Option<[Kb; 8]> {
    let limbs = text
        .lines()
        .find_map(|l| l.strip_prefix("MLE_VK_ROOT=\""))?
        .strip_suffix('"')?;
    let limbs: Vec<Kb> = limbs
        .split_whitespace()
        .map(|limb| limb.parse().ok().map(Kb::from_u32))
        .collect::<Option<_>>()?;
    limbs.try_into().ok()
}

/// One whitelisted VK identity: (lean pre_hash, merged_preprocessed_commit).
pub type VkIdentity = ([Kb; 8], [Kb; 8]);

/// Leaf hash of one VK identity.
pub fn vk_map_leaf(pre_hash: &[Kb; 8], merged_commit: &[Kb; 8]) -> [Kb; 8] {
    let mut elems = Vec::with_capacity(17);
    elems.push(Kb::from_u32(VK_MAP_LEAF_DOMAIN));
    elems.extend_from_slice(pre_hash);
    elems.extend_from_slice(merged_commit);
    sponge_hash(&elems)
}

/// The identity pair of a recursion VK (merged mode). Panics on a non-merged vk: every
/// whitelisted key is a recursion key.
pub fn vk_identity(vk: &MultiStarkVerifyingKey<Sc>) -> VkIdentity {
    (
        vk.pre_hash,
        vk.inner
            .merged_preprocessed_commit
            .expect("whitelisted VKs are recursion (merged-preprocessed) keys"),
    )
}

/// More entries than the fixed-depth tree has slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TooManyEntries {
    pub entries: usize,
    pub slots: usize,
}

/// The fixed-depth tree. Levels are stored bottom-up (`levels[0]` = leaves) for path extraction.
#[derive(Clone, Debug)]
pub struct VkMerkleTree {
    levels: Vec<Vec<[Kb; 8]>>,
}

impl VkMerkleTree {
    /// Build over `entries` in leaf order, padding with zero leaves.
    pub fn try_build(entries: &[VkIdentity]) -> Result<Self, TooManyEntries> {
        let slots = 1usize << MLE_VK_MERKLE_DEPTH;
        if entries.len() > slots {
            return Err(TooManyEntries {
                entries: entries.len(),
                slots,
            });
        }
        let mut leaves: Vec<[Kb; 8]> = entries.iter().map(|(p, m)| vk_map_leaf(p, m)).collect();
        leaves.resize(slots, [Kb::ZERO; 8]);
        let mut levels = vec![leaves];
        for _ in 0..MLE_VK_MERKLE_DEPTH {
            let prev = levels.last().unwrap();
            let next: Vec<[Kb; 8]> = prev
                .as_chunks::<2>()
                .0
                .iter()
                .map(|p| compress(p[0], p[1]))
                .collect();
            levels.push(next);
        }
        Ok(Self { levels })
    }

    /// The whitelist root: the per-config trusted constant.
    pub fn root(&self) -> [Kb; 8] {
        self.levels.last().unwrap()[0]
    }

    /// Merkle path for the leaf at `index`: little-endian index bits and the sibling digest per
    /// level, bottom-up, the witness order the membership circuit consumes.
    pub fn path(&self, index: usize) -> (Vec<bool>, Vec<[Kb; 8]>) {
        assert!(index < (1 << MLE_VK_MERKLE_DEPTH));
        let mut bits = Vec::with_capacity(MLE_VK_MERKLE_DEPTH);
        let mut siblings = Vec::with_capacity(MLE_VK_MERKLE_DEPTH);
        let mut idx = index;
        for level in &self.levels[..MLE_VK_MERKLE_DEPTH] {
            bits.push(idx & 1 == 1);
            siblings.push(level[idx ^ 1]);
            idx >>= 1;
        }
        (bits, siblings)
    }

    /// `identity`, claimed to sit at `index`, with its Merkle path.
    pub fn membership(&self, index: usize, identity: VkIdentity) -> VkMembership {
        VkMembership {
            identity,
            index,
            siblings: self.path(index).1,
        }
    }

    /// Test-only: corrupt every node below the root, so every extracted path is wrong while the
    /// root stays intact.
    #[doc(hidden)]
    pub fn corrupt_paths_for_testing(&mut self) {
        let depth = self.levels.len() - 1;
        for level in &mut self.levels[..depth] {
            for node in level.iter_mut() {
                node[0] += Kb::ONE;
            }
        }
    }
}

/// One whitelist member and its Merkle path.
///
/// What a verifier outside the prover holds instead of the whole whitelist: an apex only has to
/// authenticate the ROOT proof's vk (every other key is checked in-circuit against the root), so
/// the memberships of the keys a root can carry stand in for the full map.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VkMembership {
    pub identity: VkIdentity,
    /// Leaf index; its little-endian bits say on which side each sibling sits.
    pub index: usize,
    /// One sibling digest per level, bottom-up.
    pub siblings: Vec<[Kb; 8]>,
}

impl VkMembership {
    /// Whether the identity sits at `index` in a tree with this `root`: hash the leaf and fold
    /// it up the path, the host mirror of the in-circuit membership check.
    pub fn verifies_against(&self, root: &[Kb; 8]) -> bool {
        if self.siblings.len() != MLE_VK_MERKLE_DEPTH || self.index >= 1 << MLE_VK_MERKLE_DEPTH {
            return false;
        }
        let mut node = vk_map_leaf(&self.identity.0, &self.identity.1);
        let mut idx = self.index;
        for sibling in &self.siblings {
            node = if idx & 1 == 1 {
                compress(*sibling, node)
            } else {
                compress(node, *sibling)
            };
            idx >>= 1;
        }
        node == *root
    }
}

/// A whitelist the apex can look a key up in: `pico-vm`'s `MleVkMap` implements it.
pub trait VkWhitelist: Send + Sync {
    /// The root the whitelist builds.
    fn root(&self) -> [Kb; 8];
    /// Whether `id` is a member.
    fn contains(&self, id: &VkIdentity) -> bool;
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn id(seed: u32) -> VkIdentity {
        (
            std::array::from_fn(|i| Kb::from_u32(seed + i as u32)),
            std::array::from_fn(|i| Kb::from_u32(1000 + seed + i as u32)),
        )
    }

    fn ids(n: u32, offset: u32) -> Vec<VkIdentity> {
        (0..n).map(|i| id(i * 100 + offset)).collect()
    }

    /// Every path re-verifies against the root with the same leaf/compress functions.
    #[test]
    fn paths_verify_against_root() {
        let entries = ids(5, 0);
        let tree = VkMerkleTree::try_build(&entries).unwrap();
        let root = tree.root();
        for (i, (p, m)) in entries.iter().enumerate() {
            let (bits, siblings) = tree.path(i);
            let mut cur = vk_map_leaf(p, m);
            for (bit, sib) in bits.iter().zip(&siblings) {
                cur = if *bit {
                    compress(*sib, cur)
                } else {
                    compress(cur, *sib)
                };
            }
            assert_eq!(cur, root, "leaf {i} path does not reconstruct the root");
        }
    }

    /// A membership verifies against its own root, and against nothing else: another root, a
    /// changed sibling, index or identity, or a path of the wrong length all fail.
    #[test]
    fn memberships_verify_against_their_root_only() {
        let entries = ids(5, 0);
        let tree = VkMerkleTree::try_build(&entries).unwrap();
        let root = tree.root();
        for (i, e) in entries.iter().enumerate() {
            assert!(tree.membership(i, *e).verifies_against(&root), "leaf {i}");
        }
        let good = tree.membership(3, entries[3]);
        let other_root = VkMerkleTree::try_build(&ids(5, 1)).unwrap().root();
        assert!(!good.verifies_against(&other_root));

        let mut m = good.clone();
        m.siblings[7][0] += Kb::ONE;
        assert!(!m.verifies_against(&root), "changed sibling");
        let mut m = good.clone();
        m.index = 2;
        assert!(!m.verifies_against(&root), "changed index");
        let mut m = good.clone();
        m.identity.1[0] += Kb::ONE;
        assert!(!m.verifies_against(&root), "changed identity");
        let mut m = good.clone();
        m.siblings.pop();
        assert!(!m.verifies_against(&root), "short path");
        let mut m = good;
        m.index = 1 << MLE_VK_MERKLE_DEPTH;
        assert!(!m.verifies_against(&root), "index past the tree");
    }

    #[test]
    fn root_is_sensitive_to_entries() {
        let root = |e: &[VkIdentity]| VkMerkleTree::try_build(e).unwrap().root();
        let base = root(&[id(0), id(100)]);
        assert_ne!(root(&[id(0), id(101)]), base);
        assert_ne!(root(&[id(100), id(0)]), base);
        assert_ne!(root(&[id(0)]), base);
    }

    #[test]
    fn too_many_entries_is_reported() {
        let n = (1 << MLE_VK_MERKLE_DEPTH) + 1;
        let err = VkMerkleTree::try_build(&vec![id(0); n]).unwrap_err();
        assert_eq!(err.entries, n);
    }

    /// The shipped root file parses; a line with a missing, extra or non-numeric limb does not.
    #[test]
    fn root_files_parse_only_when_well_formed() {
        assert!(root_from_root_file(SHIPPED_VK_ROOT_FILE).is_some());
        let line = |limbs: &str| format!("# comment\nMLE_VK_ROOT=\"{limbs}\"\n");
        let root = root_from_root_file(&line("1 2 3 4 5 6 7 8")).unwrap();
        assert_eq!(root, std::array::from_fn(|i| Kb::from_u32(i as u32 + 1)));
        assert_eq!(root_from_root_file(&line("1 2 3 4 5 6 7")), None);
        assert_eq!(root_from_root_file(&line("1 2 3 4 5 6 7 8 9")), None);
        assert_eq!(root_from_root_file(&line("1 2 3 4 5 6 7 x")), None);
        assert_eq!(root_from_root_file("no root here"), None);
    }
}
