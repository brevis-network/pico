use crate::{
    configs::config::{Com, SimpleFriConfig, StarkGenericConfig, Val, ZeroCommitment},
    primitives::{consts::DIGEST_SIZE, pico_poseidon2bb_init, PicoPoseidon2BabyBear},
};
use log::info;
use p3_baby_bear::BabyBear;
use p3_challenger::DuplexChallenger;
use p3_commit::{ExtensionMmcs, Pcs};
use p3_dft::Radix2DitParallel;
use p3_field::{extension::BinomialExtensionField, Field, FieldAlgebra};
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge, TruncatedPermutation};
use serde::Serialize;

pub type SC_Val = BabyBear;
pub type SC_Perm = PicoPoseidon2BabyBear;
pub type SC_Hash = PaddingFreeSponge<SC_Perm, 16, 8, 8>;
pub type SC_Compress = TruncatedPermutation<SC_Perm, 2, 8, 16>;
pub type SC_ValMmcs =
    MerkleTreeMmcs<<SC_Val as Field>::Packing, <SC_Val as Field>::Packing, SC_Hash, SC_Compress, 8>;
pub type SC_Challenge = BinomialExtensionField<SC_Val, 4>;
pub type SC_ChallengeMmcs = ExtensionMmcs<SC_Val, SC_Challenge, SC_ValMmcs>;

pub type SC_Challenger = DuplexChallenger<SC_Val, SC_Perm, 16, 8>;
pub type SC_Dft = Radix2DitParallel<SC_Val>;
pub type SC_Pcs = TwoAdicFriPcs<SC_Val, SC_Dft, SC_ValMmcs, SC_ChallengeMmcs>;
pub type SC_DigestHash = p3_symmetric::Hash<SC_Val, SC_Val, DIGEST_SIZE>;

pub struct BabyBearPoseidon2 {
    pub perm: SC_Perm,
    pcs: SC_Pcs,
    simple_fri_config: SimpleFriConfig,
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
    pub fn compress() -> Self {
        let perm = pico_poseidon2bb_init();
        let hash = SC_Hash::new(perm.clone());
        let compress = SC_Compress::new(perm.clone());
        let val_mmcs = SC_ValMmcs::new(hash, compress);
        let challenge_mmcs = SC_ChallengeMmcs::new(val_mmcs.clone());
        let dft = SC_Dft::default();
        let num_queries = match std::env::var("FRI_QUERIES") {
            Ok(num_queries) => num_queries.parse().unwrap(),
            Err(_) => 50,
        };
        info!("NUM_QUERIES: {}", num_queries);

        let fri_config = FriConfig {
            log_blowup: 2,
            num_queries,
            proof_of_work_bits: 16,
            mmcs: challenge_mmcs,
        };
        let pcs = SC_Pcs::new(dft, val_mmcs, fri_config);

        let simple_fri_config = SimpleFriConfig {
            log_blowup: 2,
            num_queries,
            proof_of_work_bits: 16,
        };

        Self {
            perm,
            pcs,
            simple_fri_config,
        }
    }

    pub fn fri_config(&self) -> &SimpleFriConfig {
        &self.simple_fri_config
    }
}

impl Clone for BabyBearPoseidon2 {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl Default for BabyBearPoseidon2 {
    fn default() -> Self {
        Self::new()
    }
}

impl StarkGenericConfig for BabyBearPoseidon2 {
    type Val = SC_Val;
    type Domain = <SC_Pcs as Pcs<SC_Challenge, SC_Challenger>>::Domain;
    type Challenge = SC_Challenge;
    type Challenger = SC_Challenger;
    type Pcs = SC_Pcs;

    fn new() -> Self {
        let perm = pico_poseidon2bb_init();
        let hash = SC_Hash::new(perm.clone());
        let compress = SC_Compress::new(perm.clone());
        let val_mmcs = SC_ValMmcs::new(hash, compress);
        let challenge_mmcs = SC_ChallengeMmcs::new(val_mmcs.clone());
        let dft = SC_Dft::default();
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
        let pcs = SC_Pcs::new(dft, val_mmcs, fri_config);

        let simple_fri_config = SimpleFriConfig {
            log_blowup: 1,
            num_queries,
            proof_of_work_bits: 16,
        };

        Self {
            perm,
            pcs,
            simple_fri_config,
        }
    }

    fn pcs(&self) -> &Self::Pcs {
        &self.pcs
    }

    fn challenger(&self) -> Self::Challenger {
        SC_Challenger::new(self.perm.clone())
    }

    fn name(&self) -> String {
        "BabyBearPoseidon2".to_string()
    }

    fn hash_slice(&self, input: &[Val<Self>]) -> [Val<Self>; DIGEST_SIZE] {
        let hash = SC_Hash::new(self.perm.clone());
        hash.hash_slice(input)
    }
}

impl ZeroCommitment<BabyBearPoseidon2> for SC_Pcs {
    fn zero_commitment(&self) -> Com<BabyBearPoseidon2> {
        SC_DigestHash::from([SC_Val::ZERO; DIGEST_SIZE])
    }
}
