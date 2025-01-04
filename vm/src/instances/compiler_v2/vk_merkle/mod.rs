pub mod builder;
pub mod stdin;

use crate::{
    compiler::recursion_v2::circuit::merkle_tree::MerkleTree,
    configs::{config::Val, stark_config::bb_poseidon2::BabyBearPoseidon2},
    instances::compiler_v2::{
        recursion_circuit::stdin::RecursionStdin,
        vk_merkle::stdin::{MerkleProofStdin, RecursionVkStdin},
    },
    machine::{
        chip::ChipBehavior,
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::HashableKey,
    },
    primitives::consts::DIGEST_SIZE,
};
use p3_air::Air;
use p3_baby_bear::BabyBear;
use std::collections::BTreeMap;

pub struct VkMerkleManager {
    pub allowed_vk_map: BTreeMap<[BabyBear; DIGEST_SIZE], usize>,
    pub merkle_root: [BabyBear; DIGEST_SIZE],
    pub merkle_tree: MerkleTree<BabyBear, BabyBearPoseidon2>,
}

impl VkMerkleManager {
    /// Initialize the VkMerkleManager from a file
    pub fn new_from_file(file_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // Deserialize the vk_map from the file
        let allowed_vk_map: BTreeMap<[BabyBear; DIGEST_SIZE], usize> =
            bincode::deserialize(std::fs::read(file_path)?.as_slice())?;

        // Generate Merkle root and tree from the allowed_vk_map
        let (merkle_root, merkle_tree) =
            MerkleTree::commit(allowed_vk_map.keys().copied().collect());

        Ok(Self {
            allowed_vk_map,
            merkle_root,
            merkle_tree,
        })
    }

    /// Generate a RecursionVkStdin from a given RecursionStdin input
    pub fn add_vk_merkle_proof<'a, C>(
        &self,
        stdin: RecursionStdin<'a, BabyBearPoseidon2, C>,
    ) -> RecursionVkStdin<'a, BabyBearPoseidon2, C>
    where
        C: ChipBehavior<Val<BabyBearPoseidon2>>
            + for<'b> Air<ProverConstraintFolder<'b, BabyBearPoseidon2>>
            + for<'b> Air<VerifierConstraintFolder<'b, BabyBearPoseidon2>>,
    {
        // Map over vks_and_proofs to extract vk digests and their indices
        let (indices, vk_digests): (Vec<usize>, Vec<_>) = stdin
            .vks
            .iter()
            .map(|vk| {
                let vk_digest = vk.hash_babybear(); // Compute the vk digest
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
}
