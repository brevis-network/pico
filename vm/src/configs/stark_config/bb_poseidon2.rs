use crate::{configs::config::StarkGenericConfig, primitives::RC_16_30};
use log::info;
use p3_baby_bear::{BabyBear, DiffusionMatrixBabyBear};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{extension::BinomialExtensionField, Field};
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_merkle_tree::FieldMerkleTreeMmcs;
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use serde::Serialize;

pub type Val = BabyBear;
pub type Perm = Poseidon2<Val, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBabyBear, 16, 7>;
pub type Hash = PaddingFreeSponge<Perm, 16, 8, 8>;
pub type Compress = TruncatedPermutation<Perm, 2, 8, 16>;
pub type ValMmcs =
    FieldMerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, Hash, Compress, 8>;
pub type Challenge = BinomialExtensionField<Val, 4>;
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

pub type Challenger = DuplexChallenger<Val, Perm, 16, 8>;
pub type Dft = Radix2DitParallel;
pub type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;

pub struct BabyBearPoseidon2 {
    pub perm: Perm,
    pcs: Pcs,
}

impl Serialize for BabyBearPoseidon2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        std::marker::PhantomData::<BabyBearPoseidon2>.serialize(serializer)
    }
}

impl BabyBearPoseidon2 {
    #[must_use]
    pub fn my_perm() -> Perm {
        const ROUNDS_F: usize = 8;
        const ROUNDS_P: usize = 13;
        let mut round_constants = RC_16_30.to_vec();
        let internal_start = ROUNDS_F / 2;
        let internal_end = (ROUNDS_F / 2) + ROUNDS_P;
        let internal_round_constants = round_constants
            .drain(internal_start..internal_end)
            .map(|vec| vec[0])
            .collect::<Vec<_>>();
        let external_round_constants = round_constants;
        Perm::new(
            ROUNDS_F,
            external_round_constants,
            Poseidon2ExternalMatrixGeneral,
            ROUNDS_P,
            internal_round_constants,
            DiffusionMatrixBabyBear,
        )
    }

    pub fn new() -> Self {
        let perm = Self::my_perm();
        let hash = Hash::new(perm.clone());
        let compress = Compress::new(perm.clone());
        let val_mmcs = ValMmcs::new(hash, compress);
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
        let dft = Dft {};
        let num_queries = match std::env::var("FRI_QUERIES") {
            Ok(num_queries) => num_queries.parse().unwrap(),
            Err(_) => 100,
        };
        info!("NUM_QUERIES: {}", num_queries);

        let fri_config = FriConfig {
            log_blowup: 1,
            num_queries,
            proof_of_work_bits: 16,
            mmcs: challenge_mmcs,
        };
        let pcs = Pcs::new(27, dft, val_mmcs, fri_config);

        Self { perm, pcs }
    }

    pub fn compress() -> Self {
        let perm = Self::my_perm();
        let hash = Hash::new(perm.clone());
        let compress = Compress::new(perm.clone());
        let val_mmcs = ValMmcs::new(hash, compress);
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
        let dft = Dft {};
        let num_queries = match std::env::var("FRI_QUERIES") {
            Ok(num_queries) => num_queries.parse().unwrap(),
            Err(_) => 33,
        };
        info!("NUM_QUERIES: {}", num_queries);

        let fri_config = FriConfig {
            log_blowup: 3,
            num_queries,
            proof_of_work_bits: 16,
            mmcs: challenge_mmcs,
        };
        let pcs = Pcs::new(27, dft, val_mmcs, fri_config);

        Self { perm, pcs }
    }
}

impl Clone for BabyBearPoseidon2 {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl StarkGenericConfig for BabyBearPoseidon2 {
    type Val = BabyBear;
    type Domain = <Pcs as p3_commit::Pcs<Challenge, Challenger>>::Domain;
    type Challenge = Challenge;
    type Challenger = Challenger;
    type Pcs = Pcs;

    fn pcs(&self) -> &Self::Pcs {
        &self.pcs
    }

    fn challenger(&self) -> Self::Challenger {
        Challenger::new(self.perm.clone())
    }

    fn name(&self) -> String {
        "BabyBearPoseidon2".to_string()
    }
}
