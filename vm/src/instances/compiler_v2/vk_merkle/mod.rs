pub mod builder;
pub mod stdin;

use crate::{
    compiler::recursion_v2::circuit::{hash::FieldHasher, merkle_tree::MerkleTree},
    configs::config::{StarkGenericConfig, Val},
    instances::compiler_v2::{
        recursion_circuit::stdin::RecursionStdin,
        vk_merkle::stdin::{MerkleProofStdin, RecursionVkStdin},
    },
    machine::{
        chip::ChipBehavior,
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::{BaseVerifyingKey, HashableKey},
    },
    primitives::consts::DIGEST_SIZE,
};
use p3_air::Air;
use std::collections::BTreeMap;

pub struct VkMerkleManager<SC: StarkGenericConfig + FieldHasher<Val<SC>>> {
    pub allowed_vk_map: BTreeMap<[Val<SC>; DIGEST_SIZE], usize>,
    pub merkle_root: [Val<SC>; DIGEST_SIZE],
    pub merkle_tree: MerkleTree<Val<SC>, SC>,
}

impl<SC> VkMerkleManager<SC>
where
    SC: StarkGenericConfig + FieldHasher<Val<SC>, Digest = [Val<SC>; DIGEST_SIZE]>,
    SC::Val: Ord,
{
    /// Initialize the VkMerkleManager from a file
    pub fn new_from_file(file_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        // Deserialize the vk_map from the file
        let allowed_vk_map: BTreeMap<[Val<SC>; DIGEST_SIZE], usize> =
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
        stdin: RecursionStdin<'a, SC, C>,
    ) -> RecursionVkStdin<'a, SC, C>
    where
        SC::Val: Ord,
        BaseVerifyingKey<SC>: HashableKey<Val<SC>>,
        C: ChipBehavior<Val<SC>>
            + for<'b> Air<ProverConstraintFolder<'b, SC>>
            + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
    {
        // Map over vks_and_proofs to extract vk digests and their indices
        let (indices, vk_digests): (Vec<usize>, Vec<_>) = stdin
            .vks
            .iter()
            .map(|vk| {
                let vk_digest = vk.hash_field(); // Compute the vk digest
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
