use p3_challenger::DuplexChallenger;
use p3_circle::CirclePcs;
use p3_commit::ExtensionMmcs;
use p3_field::{extension::BinomialExtensionField, Field};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_mersenne_31::Mersenne31;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};

use crate::{
    configs::{field_config::m31_simple, stark_config::m31_poseidon2},
    primitives::{consts::DIGEST_SIZE, PicoPoseidon2Mersenne31},
};

pub type FieldConfig = m31_simple::M31Simple;
pub type StarkConfig = m31_poseidon2::M31Poseidon2;

pub type SC_Val = Mersenne31;
pub type SC_Perm = PicoPoseidon2Mersenne31;
pub type SC_Hash = PaddingFreeSponge<SC_Perm, 16, 8, 8>;
pub type SC_Compress = TruncatedPermutation<SC_Perm, 2, 8, 16>;
pub type SC_ValMmcs =
    MerkleTreeMmcs<<SC_Val as Field>::Packing, <SC_Val as Field>::Packing, SC_Hash, SC_Compress, 8>;
pub type SC_Challenge = BinomialExtensionField<SC_Val, 3>;
pub type SC_ChallengeMmcs = ExtensionMmcs<SC_Val, SC_Challenge, SC_ValMmcs>;

pub type SC_Challenger = DuplexChallenger<SC_Val, SC_Perm, 16, 8>;
pub type SC_Pcs = CirclePcs<SC_Val, SC_ValMmcs, SC_ChallengeMmcs>;
pub type SC_DigestHash = p3_symmetric::Hash<SC_Val, SC_Val, DIGEST_SIZE>;

pub const POSEIDON2_S_BOX_DEGREE: u64 = MERSENNE31_S_BOX_DEGREE;
