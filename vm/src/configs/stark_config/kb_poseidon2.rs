use crate::{
    configs::config::{SimpleFriConfig, StarkGenericConfig},
    primitives::{pico_poseidon2kb_init, PicoPoseidon2KoalaBear},
};
use p3_challenger::DuplexChallenger;
use p3_commit::{ExtensionMmcs, Pcs};
use p3_dft::Radix2DitParallel;
use p3_field::{extension::BinomialExtensionField, Field};
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_koala_bear::KoalaBear;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use serde::Serialize;
use tracing::info;

pub type SC_Val = KoalaBear;
pub type SC_Perm = PicoPoseidon2KoalaBear;
pub type SC_Hash = PaddingFreeSponge<SC_Perm, 16, 8, 8>;
pub type SC_Compress = TruncatedPermutation<SC_Perm, 2, 8, 16>;
pub type SC_ValMmcs =
    MerkleTreeMmcs<<SC_Val as Field>::Packing, <SC_Val as Field>::Packing, SC_Hash, SC_Compress, 8>;
pub type SC_Challenge = BinomialExtensionField<SC_Val, 4>;
pub type SC_ChallengeMmcs = ExtensionMmcs<SC_Val, SC_Challenge, SC_ValMmcs>;

pub type SC_Challenger = DuplexChallenger<SC_Val, SC_Perm, 16, 8>;
pub type SC_Dft = Radix2DitParallel<SC_Val>;
pub type SC_Pcs = TwoAdicFriPcs<SC_Val, SC_Dft, SC_ValMmcs, SC_ChallengeMmcs>;

pub struct KoalaBearPoseidon2 {
    pub perm: SC_Perm,
    pcs: SC_Pcs,
    simple_fri_config: SimpleFriConfig,
}

impl Serialize for KoalaBearPoseidon2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        std::marker::PhantomData::<KoalaBearPoseidon2>.serialize(serializer)
    }
}

impl KoalaBearPoseidon2 {
    pub fn new() -> Self {
        let perm = pico_poseidon2kb_init();
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

    pub fn compress() -> Self {
        let perm = pico_poseidon2kb_init();
        let hash = SC_Hash::new(perm.clone());
        let compress = SC_Compress::new(perm.clone());
        let val_mmcs = SC_ValMmcs::new(hash, compress);
        let challenge_mmcs = SC_ChallengeMmcs::new(val_mmcs.clone());
        let dft = SC_Dft::default();
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
        let pcs = SC_Pcs::new(dft, val_mmcs, fri_config);

        let simple_fri_config = SimpleFriConfig {
            log_blowup: 3,
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

impl Clone for KoalaBearPoseidon2 {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl Default for KoalaBearPoseidon2 {
    fn default() -> Self {
        Self::new()
    }
}

impl StarkGenericConfig for KoalaBearPoseidon2 {
    type Val = SC_Val;
    type Domain = <SC_Pcs as Pcs<SC_Challenge, SC_Challenger>>::Domain;
    type Challenge = SC_Challenge;
    type Challenger = SC_Challenger;
    type Pcs = SC_Pcs;

    fn pcs(&self) -> &Self::Pcs {
        &self.pcs
    }

    fn challenger(&self) -> Self::Challenger {
        SC_Challenger::new(self.perm.clone())
    }

    fn name(&self) -> String {
        "KoalaBearPoseidon2".to_string()
    }
}
