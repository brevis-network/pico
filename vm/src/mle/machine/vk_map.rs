//! The recursion-VK whitelist (vk map): a fixed-depth Merkle tree over the approved recursion
//! verifying keys' identities.
//!
//! Each whitelisted VK is identified by its `(lean pre_hash, merged_preprocessed_commit)` pair —
//! together they pin the full key: the lean pre-hash covers machine + shape, the merged
//! commitment is the circuit identity. The leaf is
//! `sponge(LEAF_DOMAIN ‖ pre_hash(8) ‖ merged_commit(8))` with the shared padding-free
//! rate-8/width-16 sponge, and interior nodes use the truncated two-to-one Poseidon2 compress —
//! both byte-identical to their in-circuit mirrors (`hash_poseidon2_fresh`,
//! `compress_poseidon2`), so a host-built path verifies in-circuit.
//!
//! The tree has a FIXED depth ([`MLE_VK_MERKLE_DEPTH`], baked into the membership circuit);
//! unused leaves are zero digests (nothing proves under a zero-commitment key). The whitelist
//! contents are a per-config artifact: one convert VK per RISC-V shape the whitelist admits
//! (`shape::mle_riscv_shapes`), the combine node VKs, then the deferred node VK, in that leaf
//! order.

use std::collections::HashMap;

use p3_field::PrimeCharacteristicRing;
use p3_symmetric::Permutation;
use pico_mle_core::{
    config::{
        koala_bear_poseidon2::default_koalabear_poseidon2_16,
        riscv_params_with_100_bits_security,
        soundness::{admit_production_vk, UnderBudgetError},
    },
    keygen::types::MultiStarkVerifyingKey,
    StarkEngine,
};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use super::{
    exe::sponge_hash,
    recursion::{
        extract_recursion_vk_layout_from_heights, pad_convert_program,
        recursion_air_refs_with_preprocessed, Engine,
    },
    riscv::{Kb, Sc},
};
use crate::{
    compiler::riscv::program::Program,
    mle::compiler::recursion::{ConvertProgramInput, ConvertVerifierCircuit, RecursionVkLayout},
};

/// Fixed Merkle depth: 2^15 = 32,768 whitelist slots. The whitelist holds 15,680 leaves (15,643
/// riscv shapes, 36 combine node shapes and the deferred node), so this leaves 109% headroom;
/// depth 14 would leave 704 free slots (4.3%). A ladder class costs one slot, but a new
/// precompile kind sweeps a few hundred shapes -- the three at air ids 47-49 took 519 -- so a
/// few more kinds would use them up.
/// The depth is baked into the membership circuit, so changing it changes every combine VK and
/// the root.
pub const MLE_VK_MERKLE_DEPTH: usize = 15;

/// Domain separator for whitelist leaves (distinguishes leaf hashes from every other sponge use).
pub const VK_MAP_LEAF_DOMAIN: u32 = 0x564B_6D70; // "VKmp"

/// One whitelisted VK identity: (lean pre_hash, merged_preprocessed_commit).
pub type VkIdentity = ([Kb; 8], [Kb; 8]);

/// The whitelist tree. Levels are stored bottom-up (`levels[0]` = leaves) for path extraction.
#[derive(Clone, Debug)]
pub struct MleVkMap {
    /// The whitelisted identities, in leaf order.
    pub entries: Vec<VkIdentity>,
    levels: Vec<Vec<[Kb; 8]>>,
    /// Leaf index by identity: the lookup every combine witness performs, once per child.
    index: HashMap<VkIdentity, usize>,
}

/// Two-to-one Poseidon2 compress: `permute([l ‖ r])[..8]` — the in-circuit
/// `compress_poseidon2`'s host mirror.
fn compress(l: [Kb; 8], r: [Kb; 8]) -> [Kb; 8] {
    let perm = default_koalabear_poseidon2_16();
    let mut state = [Kb::ZERO; 16];
    state[..8].copy_from_slice(&l);
    state[8..].copy_from_slice(&r);
    perm.permute_mut(&mut state);
    std::array::from_fn(|i| state[i])
}

/// Leaf hash of one VK identity.
pub fn vk_map_leaf(pre_hash: &[Kb; 8], merged_commit: &[Kb; 8]) -> [Kb; 8] {
    let mut elems = Vec::with_capacity(17);
    elems.push(Kb::from_u32(VK_MAP_LEAF_DOMAIN));
    elems.extend_from_slice(pre_hash);
    elems.extend_from_slice(merged_commit);
    sponge_hash(&elems)
}

/// The identity pair of a recursion VK (merged mode). Panics on a non-merged vk — every
/// whitelisted key is a recursion key.
pub fn vk_identity(vk: &MultiStarkVerifyingKey<Sc>) -> VkIdentity {
    (
        vk.pre_hash,
        vk.inner
            .merged_preprocessed_commit
            .expect("whitelisted VKs are recursion (merged-preprocessed) keys"),
    )
}

impl MleVkMap {
    /// Build the fixed-depth tree over `entries` (≤ 2^depth; unused leaves are zero digests),
    /// panicking on overflow. [`Self::try_build`] is the same build without the abort.
    pub fn build(entries: Vec<VkIdentity>) -> Self {
        Self::try_build(entries).unwrap_or_else(|e| panic!("{e}"))
    }

    /// Build the fixed-depth tree over `entries`, reporting overflow instead of aborting.
    ///
    /// Entry count is artifact-controlled, so a load path that must not abort needs this.
    pub fn try_build(entries: Vec<VkIdentity>) -> Result<Self, VkMapError> {
        let n_slots = 1usize << MLE_VK_MERKLE_DEPTH;
        if entries.len() > n_slots {
            return Err(VkMapError::TooManyEntries {
                entries: entries.len(),
                slots: n_slots,
            });
        }
        let mut leaves: Vec<[Kb; 8]> = entries.iter().map(|(p, m)| vk_map_leaf(p, m)).collect();
        leaves.resize(n_slots, [Kb::ZERO; 8]);
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
        let index = entries.iter().enumerate().map(|(i, e)| (*e, i)).collect();
        Ok(Self {
            entries,
            levels,
            index,
        })
    }

    /// The whitelist root — the per-config trusted constant.
    pub fn root(&self) -> [Kb; 8] {
        self.levels.last().unwrap()[0]
    }

    /// Leaf index of an identity, if whitelisted.
    pub fn find(&self, id: &VkIdentity) -> Option<usize> {
        self.index.get(id).copied()
    }

    /// Test-only: corrupt every sibling below the root (entries and the root stay intact).
    /// Host-side lookups (`find`, `root`) keep succeeding, so witness generation proceeds —
    /// but every extracted path is wrong, forcing the IN-CIRCUIT membership constraint itself
    /// to reject. This is the only way to exercise that rejection: honest flows fail closed at
    /// witness generation before the circuit ever sees a bad path.
    #[doc(hidden)]
    pub fn corrupt_paths_for_testing(&mut self) {
        let depth = self.levels.len() - 1; // keep the root level intact
        for level in &mut self.levels[..depth] {
            for node in level.iter_mut() {
                node[0] += Kb::ONE;
            }
        }
    }

    /// Merkle path for the leaf at `index`: little-endian index bits and the sibling digest per
    /// level, bottom-up — the witness order the membership circuit consumes.
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

    /// The entry at `index` with its Merkle path: proof that it is a member, without the rest of
    /// the tree.
    pub fn membership(&self, index: usize) -> VkMembership {
        let (_, siblings) = self.path(index);
        VkMembership {
            identity: self.entries[index],
            index,
            siblings,
        }
    }
}

/// One whitelist member and its Merkle path.
///
/// What a verifier outside the prover holds instead of the whole whitelist: an apex only has to
/// authenticate the ROOT proof's vk (every other key is checked in-circuit against the root), so
/// the memberships of the keys a root can carry -- the combine and deferred node keys -- stand in
/// for the 15,680-entry map. They depend on the whitelist only through its root, so a verifier
/// built on them needs no shape config.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VkMembership {
    pub identity: VkIdentity,
    /// Leaf index; its little-endian bits say on which side each sibling sits.
    pub index: usize,
    /// One sibling digest per level, bottom-up, as [`MleVkMap::path`] gives them.
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

/// Synthesize the per-air (presence, log_height) vector a bucketed RISC-V proof with the given
/// SHAPE yields: an air the shape names sits exactly at that height (which is what the pad shape
/// enforces), an air it does not name is `None`. The shape, not the air set, is the argument --
/// with a height ladder the same set of airs can be proved at several different height vectors,
/// so the set no longer determines the layout. Feed to
/// [`extract_recursion_vk_layout_from_heights`] to enumerate convert layouts without proving.
pub fn synthesize_riscv_child_heights(
    vk: &MultiStarkVerifyingKey<Sc>,
    shape: &[(String, usize)],
) -> Vec<Option<usize>> {
    (0..vk.inner.per_air.len())
        .map(|air_id| {
            let name = super::riscv::air_name(air_id)?;
            shape.iter().find(|(n, _)| n == name).map(|(_, log)| *log)
        })
        .collect()
}

/// The riscv vk every whitelist key is derived against: the whitelist-mode riscv machine
/// keygen'd on `program`. Under the shape config its layout-relevant content (DAGs, params,
/// geometry, byte-table commit) is app-independent, and the app-varying program commit is
/// witnessed rather than baked, so any program serves; the builder and the artifact test use
/// fib.
pub fn whitelist_riscv_vk(
    program: Arc<Program>,
) -> Result<MultiStarkVerifyingKey<Sc>, UnderBudgetError> {
    let engine: Engine = StarkEngine::new(riscv_params_with_100_bits_security(
        super::riscv::log_stacked_height_from_env(),
    ));
    let airs = super::riscv::mle_riscv_air_refs(program, true);
    let vk = engine
        .keygen_with_app_prep(&airs, super::riscv::RISCV_APP_PREP_AIR_IDS)
        .1;
    admit_production_vk("riscv", "cpu", &vk)?;
    Ok(vk)
}

/// The convert layout a proof of `shape` has, synthesized from the riscv vk without proving.
pub fn synthesized_convert_layout(
    riscv_vk: &MultiStarkVerifyingKey<Sc>,
    shape: &[(String, usize)],
) -> RecursionVkLayout {
    let heights = synthesize_riscv_child_heights(riscv_vk, shape);
    extract_recursion_vk_layout_from_heights(riscv_vk, Some(&heights))
}

/// Keygen the convert VK of one whitelist shape, through the same tier check the ConvertMachine
/// runs. `engine` must be the recursion params engine, the one ConvertMachine uses: params sit
/// in the pre-hash preimage and shape the merged commitment, so another engine would yield
/// another identity. The builder puts this key in the artifact and the artifact test looks it
/// up, so the two cannot drift apart.
pub fn whitelist_convert_vk(
    engine: &Engine,
    riscv_vk: &MultiStarkVerifyingKey<Sc>,
    label: &str,
    shape: &[(String, usize)],
) -> Result<MultiStarkVerifyingKey<Sc>, UnderBudgetError> {
    let mut program = ConvertVerifierCircuit::build_verify_program(&ConvertProgramInput {
        vk: synthesized_convert_layout(riscv_vk, shape),
        vk_verification: true,
    });
    pad_convert_program(&format!("convert:{label}"), &mut program);
    let program = Arc::new(program);
    let airs = recursion_air_refs_with_preprocessed(&program);
    let vk = engine.keygen_merged_preprocessed(&airs).1;
    admit_production_vk(&format!("convert:{label}"), "cpu", &vk)?;
    Ok(vk)
}

/// Serializable whitelist artifact: the per-config deliverable of the offline builder.
///
/// Three things travel together and are checked against each other on load: the shape config
/// (as its digest), the leaves, and the root. A file whose digest is not this binary's is refused
/// (built from another shape config); a file whose root does not recompute from its leaves is
/// refused (tampered or corrupt); and when `MLE_VK_ROOT` pins a root, a file with any other root
/// is refused (the wrong whitelist for this deployment).
#[derive(serde::Serialize, serde::Deserialize)]
pub struct VkMapArtifact {
    /// [`super::shape::mle_shape_config_digest`] of the config the artifact was built from.
    pub config_digest: [u32; 8],
    /// The trusted whitelist root (canonical u32 limbs) — the constant an apex pins.
    pub root: [u32; 8],
    /// (lean pre_hash, merged_commit) per entry, leaf order, canonical u32 limbs.
    pub entries: Vec<([u32; 8], [u32; 8])>,
}

/// Why a vk map artifact could not be loaded.
#[derive(Debug, thiserror::Error)]
pub enum VkMapError {
    /// The artifact file could not be read.
    #[error("cannot read vk map artifact `{}`: {source}", path.display())]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    /// The file is not a well-formed [`VkMapArtifact`].
    #[error("cannot parse vk map artifact `{}`: {source}", path.display())]
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
    /// More entries than the fixed-depth tree has slots.
    #[error("vk map overflow: {entries} entries > {slots} slots (raise MLE_VK_MERKLE_DEPTH)")]
    TooManyEntries { entries: usize, slots: usize },
    /// The entries do not rebuild the root the file claims — the file is internally inconsistent.
    /// This does NOT establish authenticity: a file whose entries and root were replaced together
    /// is consistent and passes. See [`MleVkMap::try_from_artifact`].
    #[error("vk map artifact root mismatch (inconsistent file): recomputed {computed:?}, file claims {claimed:?}")]
    RootMismatch {
        computed: [u32; 8],
        claimed: [u32; 8],
    },
    /// The artifact was built from another shape config than this binary's.
    #[error("vk map artifact was built from a different shape config than this binary's: artifact digest {artifact:?}, binary {binary:?}")]
    ConfigMismatch {
        artifact: [u32; 8],
        binary: [u32; 8],
    },
    /// The artifact's root is not the one the deployment pins through `MLE_VK_ROOT`.
    #[error("vk map artifact `{}` does not carry the pinned MLE_VK_ROOT: artifact {artifact:?}, pinned {pinned:?}", path.display())]
    PinnedRootMismatch {
        path: PathBuf,
        artifact: [u32; 8],
        pinned: [u32; 8],
    },
    /// The file is not a well-formed bincode [`VkMapArtifact`].
    #[error("cannot decode vk map artifact `{}`: {source}", path.display())]
    ParseBin {
        path: PathBuf,
        source: bincode::Error,
    },
}

/// The root a deployment pins, from `MLE_VK_ROOT` as eight canonical u32 limbs separated by
/// spaces or commas -- the value the builder logs and the artifact carries. Unset means "trust
/// the artifact's own root", which is what a self-map run does.
pub fn pinned_root_from_env() -> Option<[Kb; 8]> {
    let raw = std::env::var("MLE_VK_ROOT").ok()?;
    let limbs: Vec<Kb> = raw
        .split([' ', ','])
        .filter(|s| !s.is_empty())
        .map(|s| {
            Kb::from_u32(
                s.parse()
                    .unwrap_or_else(|_| panic!("MLE_VK_ROOT limb `{s}`")),
            )
        })
        .collect();
    Some(
        limbs
            .try_into()
            .unwrap_or_else(|v: Vec<Kb>| panic!("MLE_VK_ROOT needs 8 limbs, got {}", v.len())),
    )
}

/// The text of `mle_vk_root.txt`, the file that ships beside the artifact: what the artifact
/// holds, the config digest it was built for and the pinned root. Its `MLE_VK_ROOT="..."` line
/// is the one readers parse (the artifact unit test and the SDK's whitelist fixture); the rest is
/// for the eye.
pub fn root_file_text(
    artifact: &VkMapArtifact,
    bin_name: &str,
    n_convert: usize,
    n_combine: usize,
    n_deferred: usize,
    riscv_pre_hash: [u32; 8],
    date: &str,
) -> String {
    use super::shape::MLE_RISCV_PROGRAM_LOG_HEIGHT;
    let root = artifact
        .root
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<_>>()
        .join(" ");
    let lines = [
        format!(
            "# MLE whitelist artifact {bin_name}: {n_convert} convert VKs (one per riscv shape) + \
             {n_combine} combine node VKs + {n_deferred} deferred node VK = {} leaves in a \
             depth-{MLE_VK_MERKLE_DEPTH} Merkle tree,",
            n_convert + n_combine + n_deferred
        ),
        format!(
            "# built {date} with mle_build_vk_map for the riscv machine whose whitelist-mode vk \
             pre_hash is {riscv_pre_hash:?} (program table at 2^{MLE_RISCV_PROGRAM_LOG_HEIGHT})."
        ),
        "# The digest is the shape config the artifact was built for and the root is the \
         verifier's pinned constant; MleVkMap::load re-checks both, and the unit test"
            .to_string(),
        "# the_shipped_artifact_matches_this_binary fails when the code no longer matches this \
         file. Rebuild it with the mle_build_vk_map example."
            .to_string(),
        format!("config digest = {:?}", artifact.config_digest),
        format!("MLE_VK_ROOT=\"{root}\""),
    ];
    lines.join("\n") + "\n"
}

/// The root a root file names, from its `MLE_VK_ROOT="..."` line.
pub fn root_from_root_file(text: &str) -> Option<[Kb; 8]> {
    text.lines()
        .find_map(|l| l.strip_prefix("MLE_VK_ROOT=\""))
        .and_then(|l| l.strip_suffix('"'))
        .map(limbs_from_string)
}

/// The content key of a riscv shape: its `name:height` pairs, sorted. Two shapes with the same
/// key are the same shape whatever label or index the enumeration gave them; the builder
/// checkpoints by it, so a ladder edit that moves every index still reuses what was keygen'd.
pub fn shape_content_key(shape: &[(String, usize)]) -> String {
    let mut pairs: Vec<String> = shape.iter().map(|(n, h)| format!("{n}:{h}")).collect();
    pairs.sort();
    pairs.join(",")
}

fn limbs_to_string(d: &[Kb; 8]) -> String {
    use p3_field::PrimeField32;
    d.iter()
        .map(|f| f.as_canonical_u32().to_string())
        .collect::<Vec<_>>()
        .join(" ")
}

fn limbs_from_string(s: &str) -> [Kb; 8] {
    let v: Vec<Kb> = s
        .split(' ')
        .map(|x| Kb::from_u32(x.parse().unwrap_or_else(|_| panic!("bad limb `{x}`"))))
        .collect();
    v.try_into()
        .unwrap_or_else(|v: Vec<Kb>| panic!("expected 8 limbs, got {}", v.len()))
}

/// One builder checkpoint line: `key \t label \t pre_hash limbs \t merged_commit limbs`.
pub fn checkpoint_line(key: &str, label: &str, id: &VkIdentity) -> String {
    format!(
        "{key}\t{label}\t{}\t{}",
        limbs_to_string(&id.0),
        limbs_to_string(&id.1)
    )
}

/// Parse a [`checkpoint_line`] back into `(key, identity)`.
pub fn parse_checkpoint_line(line: &str) -> (String, VkIdentity) {
    let f: Vec<&str> = line.split('\t').collect();
    assert_eq!(f.len(), 4, "malformed checkpoint line: {line}");
    (
        f[0].to_string(),
        (limbs_from_string(f[2]), limbs_from_string(f[3])),
    )
}

impl MleVkMap {
    /// Export the artifact (root included so consumers can pin it without rebuilding).
    pub fn to_artifact(&self) -> VkMapArtifact {
        use p3_field::PrimeField32;
        VkMapArtifact {
            config_digest: super::shape::mle_shape_config_digest().map(|f| f.as_canonical_u32()),
            root: self.root().map(|f| f.as_canonical_u32()),
            entries: self
                .entries
                .iter()
                .map(|(p, m)| {
                    (
                        p.map(|f| f.as_canonical_u32()),
                        m.map(|f| f.as_canonical_u32()),
                    )
                })
                .collect(),
        }
    }

    /// Rebuild from an artifact, reporting a bad one instead of aborting.
    ///
    /// Three checks: the artifact must come from this binary's shape config (its digest), its
    /// entry count must fit the tree, and its entries must rebuild the root stored beside them.
    /// Together they catch a stale or **inconsistent** file.
    ///
    /// They do **not** authenticate it. Root and entries both come from the same file, so an
    /// attacker who replaces the two together passes every check here. A relying party that did
    /// not produce the whitelist itself must compare the root against a value pinned out of band:
    /// [`Self::try_load`] does when `MLE_VK_ROOT` is set, and
    /// [`crate::mle::machine::apex::MleApexVerifier::new`] takes that root beside the map.
    pub fn try_from_artifact(artifact: &VkMapArtifact) -> Result<Self, VkMapError> {
        use p3_field::PrimeField32;
        let binary = super::shape::mle_shape_config_digest().map(|f| f.as_canonical_u32());
        if artifact.config_digest != binary {
            return Err(VkMapError::ConfigMismatch {
                artifact: artifact.config_digest,
                binary,
            });
        }
        let map = Self::try_build(
            artifact
                .entries
                .iter()
                .map(|(p, m)| (p.map(Kb::from_u32), m.map(Kb::from_u32)))
                .collect(),
        )?;
        let computed = map.root().map(|f| f.as_canonical_u32());
        if computed != artifact.root {
            return Err(VkMapError::RootMismatch {
                computed,
                claimed: artifact.root,
            });
        }
        Ok(map)
    }

    /// Rebuild from an artifact, panicking on a bad one.
    /// [`Self::try_from_artifact`] is the same check without the abort.
    pub fn from_artifact(artifact: &VkMapArtifact) -> Self {
        Self::try_from_artifact(artifact).unwrap_or_else(|e| panic!("{e}"))
    }

    /// Load an artifact JSON file, reporting every failure as a [`VkMapError`].
    ///
    /// The entry point for library code, where a bad artifact is a condition the caller handles
    /// rather than a reason to abort its process. [`Self::load_json`] is the panicking twin.
    pub fn try_load_json(path: impl AsRef<Path>) -> Result<Self, VkMapError> {
        let path = path.as_ref();
        let data = std::fs::read_to_string(path).map_err(|source| VkMapError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let artifact: VkMapArtifact =
            serde_json::from_str(&data).map_err(|source| VkMapError::Parse {
                path: path.to_path_buf(),
                source,
            })?;
        Self::try_from_artifact(&artifact)
    }

    /// Load an artifact JSON file, panicking on any failure (see [`Self::try_load_json`]).
    pub fn load_json(path: impl AsRef<Path>) -> Self {
        Self::try_load_json(path).unwrap_or_else(|e| panic!("{e}"))
    }

    /// Write the artifact JSON file.
    pub fn save_json(&self, path: impl AsRef<Path>) {
        let path = path.as_ref();
        let json = serde_json::to_string_pretty(&self.to_artifact()).unwrap();
        std::fs::write(path, json)
            .unwrap_or_else(|e| panic!("cannot write vk map artifact `{}`: {e}", path.display()));
    }

    /// Load a bincode artifact (`*.bin`, the deployable form), reporting every failure as a
    /// [`VkMapError`]. Same encoding as the FRI path's `vk_map_kb.bin`; the payload is
    /// [`VkMapArtifact`] rather than FRI's digest-to-index map, because a leaf here is the
    /// `(pre_hash, merged_commit)` pair the membership circuit hashes itself.
    pub fn try_load_bin(path: impl AsRef<Path>) -> Result<Self, VkMapError> {
        let path = path.as_ref();
        let data = std::fs::read(path).map_err(|source| VkMapError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        let artifact: VkMapArtifact =
            bincode::deserialize(&data).map_err(|source| VkMapError::ParseBin {
                path: path.to_path_buf(),
                source,
            })?;
        Self::try_from_artifact(&artifact)
    }

    /// Load a bincode artifact, panicking on any failure (see [`Self::try_load_bin`]).
    pub fn load_bin(path: impl AsRef<Path>) -> Self {
        Self::try_load_bin(path).unwrap_or_else(|e| panic!("{e}"))
    }

    /// Write the bincode artifact.
    pub fn save_bin(&self, path: impl AsRef<Path>) {
        let path = path.as_ref();
        let data = bincode::serialize(&self.to_artifact()).unwrap();
        std::fs::write(path, data)
            .unwrap_or_else(|e| panic!("cannot write vk map artifact `{}`: {e}", path.display()));
    }

    /// Load an artifact by extension (`.bin` is bincode, anything else JSON) and hold it to the
    /// pinned root when `MLE_VK_ROOT` is set: the artifact's own root is only the deployment's
    /// trusted constant once something outside the file says so. Every failure is a
    /// [`VkMapError`]; [`Self::load`] is the panicking twin.
    pub fn try_load(path: impl AsRef<Path>) -> Result<Self, VkMapError> {
        let path = path.as_ref();
        let map = if path.extension().is_some_and(|e| e == "bin") {
            Self::try_load_bin(path)?
        } else {
            Self::try_load_json(path)?
        };
        if let Some(pinned) = pinned_root_from_env() {
            if map.root() != pinned {
                use p3_field::PrimeField32;
                return Err(VkMapError::PinnedRootMismatch {
                    path: path.to_path_buf(),
                    artifact: map.root().map(|f| f.as_canonical_u32()),
                    pinned: pinned.map(|f| f.as_canonical_u32()),
                });
            }
        }
        Ok(map)
    }

    /// Load by extension and hold to the pinned root, panicking on any failure (see
    /// [`Self::try_load`]).
    pub fn load(path: impl AsRef<Path>) -> Self {
        Self::try_load(path).unwrap_or_else(|e| panic!("{e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(seed: u32) -> VkIdentity {
        (
            std::array::from_fn(|i| Kb::from_u32(seed + i as u32)),
            std::array::from_fn(|i| Kb::from_u32(1000 + seed + i as u32)),
        )
    }

    /// Every path re-verifies against the root with the same leaf/compress functions.
    #[test]
    fn paths_verify_against_root() {
        let map = MleVkMap::build((0..5).map(|i| id(i * 100)).collect());
        let root = map.root();
        for (i, (p, m)) in map.entries.clone().iter().enumerate() {
            let (bits, siblings) = map.path(i);
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
        let map = MleVkMap::build((0..5).map(|i| id(i * 100)).collect());
        let root = map.root();
        for i in 0..map.entries.len() {
            assert!(map.membership(i).verifies_against(&root), "leaf {i}");
        }
        let good = map.membership(3);
        let other_root = MleVkMap::build((0..5).map(|i| id(i * 100 + 1)).collect()).root();
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

    /// Every failure an artifact can carry is reported rather than aborting: missing, malformed,
    /// root mismatch, more entries than slots.
    #[test]
    fn try_load_json_reports_instead_of_panicking() {
        let dir = std::env::temp_dir().join(format!("vk_map_try_load_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");

        let missing = dir.join("absent.json");
        assert!(matches!(
            MleVkMap::try_load_json(&missing),
            Err(VkMapError::Read { .. })
        ));

        let malformed = dir.join("malformed.json");
        std::fs::write(&malformed, "{ not json").expect("write");
        assert!(matches!(
            MleVkMap::try_load_json(&malformed),
            Err(VkMapError::Parse { .. })
        ));

        // Well-formed, but the root does not match the entries.
        let map = MleVkMap::build(vec![id(0), id(100)]);
        let mut artifact = map.to_artifact();
        artifact.root[0] = artifact.root[0].wrapping_add(1);
        let tampered = dir.join("tampered.json");
        std::fs::write(&tampered, serde_json::to_string(&artifact).expect("encode"))
            .expect("write");
        assert!(matches!(
            MleVkMap::try_load_json(&tampered),
            Err(VkMapError::RootMismatch { .. })
        ));

        // Entry count is artifact-controlled too, and overflows the fixed-depth tree.
        let n_slots = 1usize << MLE_VK_MERKLE_DEPTH;
        let overflowing = VkMapArtifact {
            config_digest: map.to_artifact().config_digest,
            root: [0; 8],
            entries: (0..=n_slots as u32).map(|i| ([i; 8], [i; 8])).collect(),
        };
        let too_many = dir.join("too_many.json");
        std::fs::write(
            &too_many,
            serde_json::to_string(&overflowing).expect("encode"),
        )
        .expect("write");
        assert!(matches!(
            MleVkMap::try_load_json(&too_many),
            Err(VkMapError::TooManyEntries { .. })
        ));

        let good = dir.join("good.json");
        map.save_json(&good);
        let loaded = MleVkMap::try_load_json(&good).expect("honest artifact");
        assert_eq!(loaded.root(), map.root());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// A tampered whitelist aborts on the panicking path.
    #[test]
    #[should_panic(expected = "vk map artifact root mismatch")]
    fn load_json_panics_on_a_tampered_artifact() {
        let dir = std::env::temp_dir().join(format!("vk_map_load_panic_{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let mut artifact = MleVkMap::build(vec![id(0), id(100)]).to_artifact();
        artifact.root[0] = artifact.root[0].wrapping_add(1);
        let path = dir.join("tampered.json");
        std::fs::write(&path, serde_json::to_string(&artifact).expect("encode")).expect("write");
        let _ = MleVkMap::load_json(&path);
    }

    /// The root binds every entry and the leaf order.
    /// The binary artifact must round-trip to the same root and the same leaf order, and
    /// `find` must answer for every entry after the reload.
    #[test]
    fn bin_artifact_round_trips() {
        let map = MleVkMap::build((0..7).map(|i| id(i * 31)).collect());
        let path = std::env::temp_dir().join(format!("mle_vk_map_{}.bin", std::process::id()));
        let path = path.to_str().unwrap().to_string();
        map.save_bin(&path);
        let back = MleVkMap::load(&path);
        std::fs::remove_file(&path).ok();
        assert_eq!(back.root(), map.root());
        assert_eq!(back.entries, map.entries);
        for (i, e) in map.entries.iter().enumerate() {
            assert_eq!(back.find(e), Some(i));
        }
        assert_eq!(back.find(&id(999)), None);
    }

    /// An artifact from another shape config must be refused, whatever its root says.
    #[test]
    #[should_panic(expected = "different shape config")]
    fn a_foreign_config_digest_is_rejected() {
        let mut artifact = MleVkMap::build(vec![id(1), id(2)]).to_artifact();
        artifact.config_digest[0] ^= 1;
        let _ = MleVkMap::from_artifact(&artifact);
    }

    /// The shipped artifact loads under this binary's shape config, and the root file beside it
    /// names the root it carries. A machine or config change that invalidates the whitelist
    /// fails here, in CI, rather than at a prover's first whitelist lookup.
    #[test]
    fn the_shipped_artifact_matches_this_binary() {
        use p3_field::PrimeField32;
        let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/src/mle/shape_vk_bins");
        let map = MleVkMap::try_load_bin(format!("{dir}/mle_vk_map_kb.bin"))
            .unwrap_or_else(|e| panic!("shipped whitelist does not load: {e}"));
        let root_file =
            std::fs::read_to_string(format!("{dir}/mle_vk_root.txt")).expect("root file");
        let pinned =
            root_from_root_file(&root_file).expect("mle_vk_root.txt carries an MLE_VK_ROOT line");
        assert_eq!(
            map.root(),
            pinned,
            "mle_vk_root.txt names a different root than the artifact"
        );
        use crate::{
            compiler::riscv::compiler::{Compiler, SourceType},
            mle::machine::{combine::CombineMachine, deferred::DeferredMachine, exe::RiscvVmVk},
        };
        use pico_mle_core::config::recursion_params_with_100_bits_security;
        let shapes = super::super::shape::mle_riscv_shapes();
        let nodes = CombineMachine::standard_node_count();
        assert_eq!(
            map.entries.len(),
            shapes.len() + nodes + 1,
            "leaf count: {} riscv shapes + {nodes} combine node shapes + 1 deferred node",
            shapes.len()
        );
        let _ = map.root().map(|f| f.as_canonical_u32());

        // The digest covers the shape config; it does not cover the riscv AIRs, the params or the
        // recursion compiler, whose changes move keys without moving the digest. An AIR's change
        // moves the convert VKs of the shapes it is present in, so one shape per family is
        // probed: the first core row, the first memory shape and the first shape of every
        // precompile kind, plus the combine node the preregistration bootstraps from. Each key
        // this binary derives must be a member; a stale artifact fails here rather than at a
        // prover's first whitelist lookup. One keygen per probe, seconds each in release.
        const FIB_ELF: &[u8] = include_bytes!("../../compiler/test_elf/fib-elf");
        let program = Compiler::new(SourceType::RISCV, FIB_ELF)
            .expect("fib elf")
            .compile();
        let riscv_vk = whitelist_riscv_vk(program.clone()).expect("riscv keygen");
        let engine: Engine = StarkEngine::new(recursion_params_with_100_bits_security());
        // Labels are `core:...`, `memory:...` and `precompile:<kind>:...`; the family key is
        // the label up to the kind.
        let family = |label: &str| -> String {
            let mut parts = label.splitn(3, ':');
            match (parts.next(), parts.next()) {
                (Some("precompile"), Some(kind)) => format!("precompile:{kind}"),
                (Some(head), _) => head.to_string(),
                (None, _) => label.to_string(),
            }
        };
        let mut seen = std::collections::BTreeSet::new();
        let probes: Vec<&(String, Vec<(String, usize)>)> = shapes
            .iter()
            .filter(|(label, _)| seen.insert(family(label)))
            .collect();
        assert!(
            probes.len() >= 3,
            "a core, a memory and a precompile probe at least"
        );
        let mut first_convert = None;
        for (label, shape) in probes {
            let vk =
                whitelist_convert_vk(&engine, &riscv_vk, label, shape).expect("convert keygen");
            assert!(
                map.find(&vk_identity(&vk)).is_some(),
                "the convert VK of `{label}` is not a whitelist member: the riscv machine or the \
                 recursion compiler changed since the artifact was built; rebuild it \
                 with `cargo run --release -p pico-vm --example mle_build_vk_map`"
            );
            first_convert.get_or_insert(vk);
        }
        let vm_vk = RiscvVmVk::from_program_and_vk(&program, &riscv_vk);
        let mut combine = CombineMachine::new(
            recursion_params_with_100_bits_security(),
            vm_vk.clone(),
            true,
        );
        let first_convert = first_convert.as_ref().expect("a convert VK");
        let node = combine
            .bootstrap_node_vk(first_convert)
            .expect("combine keygen");
        assert!(
            map.find(&vk_identity(&node)).is_some(),
            "the combine bootstrap node VK is not a whitelist member: the recursion compiler or \
             the combine tier changed since the artifact was built; rebuild it \
             with `cargo run --release -p pico-vm --example mle_build_vk_map`"
        );
        let mut deferred =
            DeferredMachine::new(recursion_params_with_100_bits_security(), vm_vk, true);
        let layout = combine
            .combine_tier_child_layout(first_convert)
            .expect("combine keygen");
        let node = deferred.preregister(&layout).expect("deferred keygen");
        assert_eq!(
            map.find(&vk_identity(&node)),
            Some(map.entries.len() - 1),
            "the deferred node VK is not the whitelist's last leaf: the deferred program or the \
             combine tier changed since the artifact was built; rebuild it \
             with `cargo run --release -p pico-vm --example mle_build_vk_map`"
        );

        // The soundness manifest records the identities an apex verifier is built from; they must
        // be this tree's.
        let manifest: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../mle-core/tests/soundness_manifest.json"
        ))
        .expect("the soundness manifest parses");
        let limbs = |v: &serde_json::Value| -> Vec<u32> {
            v.as_array()
                .expect("an array of limbs")
                .iter()
                .map(|x| x.as_u64().expect("a limb") as u32)
                .collect()
        };
        let regenerate = "regenerate it: cargo run --release -p pico-vm --example \
                          mle_soundness_manifest";
        assert_eq!(
            limbs(&manifest["apex"]["vk_root"]),
            pinned.map(|f| f.as_canonical_u32()),
            "the soundness manifest records another whitelist root than mle_vk_root.txt; \
             {regenerate}"
        );
        assert_eq!(
            limbs(&manifest["apex"]["riscv_vk_pre_hash"]),
            riscv_vk.pre_hash.map(|f| f.as_canonical_u32()),
            "the soundness manifest records another whitelist-mode riscv key than this binary \
             keygens; {regenerate}"
        );
    }

    #[test]
    fn root_file_text_carries_the_lines_its_readers_parse() {
        let map = MleVkMap::build(vec![id(1), id(2)]);
        let artifact = map.to_artifact();
        let text = root_file_text(
            &artifact,
            "mle_vk_map_kb.bin",
            1,
            1,
            0,
            [7; 8],
            "2026-01-02",
        );
        assert_eq!(root_from_root_file(&text), Some(map.root()));
        assert!(text.contains(&format!("config digest = {:?}", artifact.config_digest)));
        assert!(text.contains("2 leaves in a depth-15 Merkle tree"));
        assert!(text.contains("built 2026-01-02"));
        assert!(text.ends_with('\n'));
        assert!(text.lines().all(|l| l.starts_with('#') || l.contains('=')));
    }

    #[test]
    fn checkpoint_line_round_trips() {
        let ident = id(4242);
        let line = checkpoint_line("Add:21,Cpu:23", "core:class1", &ident);
        let (key, back) = parse_checkpoint_line(&line);
        assert_eq!(key, "Add:21,Cpu:23");
        assert_eq!(back, ident);
    }

    /// The content key orders pairs canonically and is independent of the input order.
    #[test]
    fn content_key_is_order_independent() {
        let a = vec![("Cpu".to_string(), 23), ("Add".to_string(), 21)];
        let b = vec![("Add".to_string(), 21), ("Cpu".to_string(), 23)];
        assert_eq!(shape_content_key(&a), shape_content_key(&b));
        assert_eq!(shape_content_key(&a), "Add:21,Cpu:23");
    }

    #[test]
    fn root_is_sensitive_to_entries() {
        let base = MleVkMap::build(vec![id(0), id(100)]).root();
        assert_ne!(MleVkMap::build(vec![id(0), id(101)]).root(), base);
        assert_ne!(MleVkMap::build(vec![id(100), id(0)]).root(), base);
        assert_ne!(MleVkMap::build(vec![id(0)]).root(), base);
    }
}
