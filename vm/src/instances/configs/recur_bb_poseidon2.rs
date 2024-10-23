use crate::{
    configs::{field_config::bb_simple, stark_config::bb_poseidon2},
    primitives::consts::DIGEST_SIZE,
};

/// A configuration for field_config, with BabyBear field and Poseidon2 hash

// Each field_config config mod should have public types with the same names as below.

pub type FieldConfig = bb_simple::BabyBearSimple;
pub type StarkConfig = bb_poseidon2::BabyBearPoseidon2;

pub type Val = bb_poseidon2::Val;
pub type Perm = bb_poseidon2::Perm;
pub type Hash = bb_poseidon2::Hash;
pub type Compress = bb_poseidon2::Compress;
pub type ValMmcs = bb_poseidon2::ValMmcs;
pub type Challenge = bb_poseidon2::Challenge;
pub type ChallengeMmcs = bb_poseidon2::ChallengeMmcs;

pub type DigestHash = p3_symmetric::Hash<Val, Val, DIGEST_SIZE>;
pub type Digest = [Val; DIGEST_SIZE];
pub type QueryProof = p3_fri::QueryProof<Challenge, ChallengeMmcs>;
pub type CommitPhaseStep = p3_fri::CommitPhaseProofStep<Challenge, ChallengeMmcs>;
pub type FriProof = p3_fri::FriProof<Challenge, ChallengeMmcs, Val>;
pub type BatchOpening = p3_fri::BatchOpening<Val, ValMmcs>;
pub type PcsProof = p3_fri::TwoAdicFriPcsProof<Val, Challenge, ValMmcs, ChallengeMmcs>;
