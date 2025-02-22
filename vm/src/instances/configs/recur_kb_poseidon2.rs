use crate::{
    configs::{field_config::KoalaBearSimple, stark_config::kb_poseidon2},
    primitives::consts::DIGEST_SIZE,
};
use p3_fri::{BatchOpening, CommitPhaseProofStep, FriProof, QueryProof};
use p3_symmetric::Hash;

/// A configuration for recursion, with KoalaBear field and Poseidon2 hash

// Each recursion config mod should have public types with the same names as below.

pub struct KoalaBearPoseidon2Recursion;

pub type FieldConfig = KoalaBearSimple;
pub type StarkConfig = kb_poseidon2::KoalaBearPoseidon2;

pub type SC_Val = kb_poseidon2::SC_Val;
pub type SC_Perm = kb_poseidon2::SC_Perm;
pub type SC_Hash = kb_poseidon2::SC_Hash;
pub type SC_Compress = kb_poseidon2::SC_Compress;
pub type SC_ValMmcs = kb_poseidon2::SC_ValMmcs;
pub type SC_Challenge = kb_poseidon2::SC_Challenge;
pub type SC_ChallengeMmcs = kb_poseidon2::SC_ChallengeMmcs;

pub type SC_DigestHash = Hash<SC_Val, SC_Val, DIGEST_SIZE>;
pub type SC_Digest = [SC_Val; DIGEST_SIZE];
pub type SC_BatchOpening = BatchOpening<SC_Val, SC_ValMmcs>;
pub type SC_InputProof = Vec<SC_BatchOpening>;
pub type SC_QueryProof = QueryProof<SC_Challenge, SC_ChallengeMmcs, Vec<SC_BatchOpening>>;
pub type SC_CommitPhaseStep = CommitPhaseProofStep<SC_Challenge, SC_ChallengeMmcs>;
pub type SC_PcsProof = FriProof<SC_Challenge, SC_ChallengeMmcs, SC_Val, SC_InputProof>;
