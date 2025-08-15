pub mod builder;
pub mod stdin;

use crate::{
    compiler::recursion::circuit::{hash::FieldHasher, merkle_tree::MerkleTree},
    configs::{
        config::{StarkGenericConfig, Val},
        stark_config::{BabyBearPoseidon2, KoalaBearPoseidon2},
    },
    instances::compiler::{
        recursion_circuit::stdin::RecursionStdin,
        vk_merkle::stdin::{MerkleProofStdin, RecursionVkStdin},
    },
    machine::{
        chip::ChipBehavior,
        keys::{BaseVerifyingKey, HashableKey},
    },
    primitives::consts::DIGEST_SIZE,
};
use once_cell::sync::Lazy;
use std::{collections::BTreeMap, env};
use tracing::{debug, info};

pub fn vk_verification_enabled() -> bool {
    env::var("VK_VERIFICATION")
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(true)
}

// TODO: use once lock for vk_manager
pub struct VkMerkleManager<SC: StarkGenericConfig + FieldHasher<Val<SC>>> {
    pub allowed_vk_map: BTreeMap<[Val<SC>; DIGEST_SIZE], usize>,
    pub merkle_root: [Val<SC>; DIGEST_SIZE],
    pub merkle_tree: MerkleTree<Val<SC>, SC>,
    vk_verification: bool,
}

impl<SC> VkMerkleManager<SC>
where
    SC: StarkGenericConfig + FieldHasher<Val<SC>, Digest = [Val<SC>; DIGEST_SIZE]>,
    Val<SC>: Ord,
{
    /// Initialize the VkMerkleManager
    pub fn new_from_bytes(file_content: &[u8]) -> Result<Self, Box<dyn std::error::Error>> {
        // Deserialize the vk_map from the byte slice
        let allowed_vk_map: BTreeMap<[Val<SC>; DIGEST_SIZE], usize> =
            bincode::deserialize(file_content)?;

        // Generate Merkle root and tree from the allowed_vk_map
        let (merkle_root, merkle_tree) =
            MerkleTree::commit(allowed_vk_map.keys().copied().collect());

        let vk_verification = vk_verification_enabled();
        info!("VK_VERIFICATION: {}", vk_verification);

        Ok(Self {
            allowed_vk_map,
            merkle_root,
            merkle_tree,
            vk_verification,
        })
    }

    pub fn vk_verification_enabled(&self) -> bool {
        self.vk_verification
    }

    /// Initialize the VkMerkleManager from a file
    pub fn new_from_file(file_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // Deserialize the vk_map from the file
        let allowed_vk_map: BTreeMap<[Val<SC>; DIGEST_SIZE], usize> =
            bincode::deserialize(std::fs::read(file_path)?.as_slice())?;

        // Generate Merkle root and tree from the allowed_vk_map
        let (merkle_root, merkle_tree) =
            MerkleTree::commit(allowed_vk_map.keys().copied().collect());

        let vk_verification = vk_verification_enabled();

        Ok(Self {
            allowed_vk_map,
            merkle_root,
            merkle_tree,
            vk_verification,
        })
    }

    /// Generate a RecursionVkStdin from a given RecursionStdin input
    pub fn add_vk_merkle_proof<'a, C>(
        &self,
        stdin: RecursionStdin<'a, SC, C>,
    ) -> RecursionVkStdin<'a, SC, C>
    where
        BaseVerifyingKey<SC>: HashableKey<Val<SC>>,
        C: ChipBehavior<Val<SC>>,
    {
        // Map over vks_and_proofs to extract vk digests and their indices
        let (indices, vk_digests): (Vec<usize>, Vec<_>) = stdin
            .vks
            .iter()
            .map(|vk| {
                let vk_digest = vk.hash_field(); // Compute the vk digest
                debug!("vk digest in add_vk_merkle_proof: {:?}", vk_digest);
                let index = self
                    .allowed_vk_map
                    .get(&vk_digest)
                    .unwrap_or_else(|| panic!("vk not allowed: {:?}", vk_digest));
                (*index, vk_digest)
            })
            .unzip();

        // Generate MerkleProofStdin
        let merkle_proof_stdin = MerkleProofStdin {
            vk_merkle_proofs: indices
                .iter()
                .map(|&index| {
                    let (_, proof) = MerkleTree::open(&self.merkle_tree, index);
                    proof
                })
                .collect(),
            vk_values: vk_digests,
            merkle_root: self.merkle_root,
        };

        RecursionVkStdin {
            merkle_proof_stdin,
            recursion_stdin: stdin,
        }
    }

    pub fn is_vk_allowed(&self, vk_digest: [Val<SC>; DIGEST_SIZE]) -> bool {
        self.allowed_vk_map.contains_key(&vk_digest)
    }
}

pub static VK_MANAGER_BB: Lazy<VkMerkleManager<BabyBearPoseidon2>> = Lazy::new(|| {
    let file_content = include_bytes!("../shape_vk_bins/vk_map_bb.bin");
    debug!("Initializing global BabyBear VK_MANAGER");
    VkMerkleManager::<BabyBearPoseidon2>::new_from_bytes(file_content)
        .expect("Failed to load BabyBear VkMerkleManager")
});

pub static VK_MANAGER_KB: Lazy<VkMerkleManager<KoalaBearPoseidon2>> = Lazy::new(|| {
    let file_content = include_bytes!("../shape_vk_bins/vk_map_kb.bin");
    debug!("Initializing global KoalaBear VK_MANAGER");
    VkMerkleManager::<KoalaBearPoseidon2>::new_from_bytes(file_content)
        .expect("Failed to load KoalaBear VkMerkleManager")
});

pub trait HasStaticVkManager:
    StarkGenericConfig + FieldHasher<Val<Self>, Digest = [Val<Self>; DIGEST_SIZE]>
{
    fn static_vk_manager() -> &'static VkMerkleManager<Self>;
}

impl HasStaticVkManager for BabyBearPoseidon2 {
    fn static_vk_manager() -> &'static VkMerkleManager<Self> {
        &VK_MANAGER_BB
    }
}

impl HasStaticVkManager for KoalaBearPoseidon2 {
    fn static_vk_manager() -> &'static VkMerkleManager<Self> {
        &VK_MANAGER_KB
    }
}
