use crate::{
    configs::config::{SimpleFriConfig, StarkGenericConfig},
    primitives::pico_poseidon2bn254_init,
};
use p3_baby_bear::BabyBear;
use p3_bn254_fr::{Bn254Fr, Poseidon2Bn254};
use p3_challenger::MultiField32Challenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{BatchOpening, CommitPhaseProofStep, FriConfig, FriProof, QueryProof, TwoAdicFriPcs};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{Hash, MultiField32PaddingFreeSponge, TruncatedPermutation};
use serde::Serialize;
use tracing::info;

pub type SC_Val = BabyBear;
pub type SC_Perm = Poseidon2Bn254<3>;
pub type SC_Hash = MultiField32PaddingFreeSponge<SC_Val, Bn254Fr, SC_Perm, 3, 16, 1>;
pub type SC_DigestHash = Hash<Bn254Fr, Bn254Fr, 1>;
pub type SC_Digest = [Bn254Fr; 1];
pub type SC_Compress = TruncatedPermutation<SC_Perm, 2, 1, 3>;
pub type SC_ValMmcs = MerkleTreeMmcs<BabyBear, Bn254Fr, SC_Hash, SC_Compress, 1>;
pub type SC_Challenge = BinomialExtensionField<SC_Val, 4>;
pub type SC_ChallengeMmcs = ExtensionMmcs<SC_Val, SC_Challenge, SC_ValMmcs>;
pub type SC_Challenger = MultiField32Challenger<SC_Val, Bn254Fr, SC_Perm, 3, 3>; // todo: currently setting RATE == WIDTH
pub type SC_Dft = Radix2DitParallel<SC_Val>;
pub type SC_Pcs = TwoAdicFriPcs<SC_Val, SC_Dft, SC_ValMmcs, SC_ChallengeMmcs>;

pub type SC_BatchOpening = BatchOpening<SC_Val, SC_ValMmcs>;
pub type SC_InputProof = Vec<SC_BatchOpening>;
pub type SC_QueryProof = QueryProof<SC_Challenge, SC_ChallengeMmcs, SC_InputProof>;
pub type SC_CommitPhaseStep = CommitPhaseProofStep<SC_Challenge, SC_ChallengeMmcs>;
pub type SC_PcsProof = FriProof<SC_Challenge, SC_ChallengeMmcs, SC_Val, SC_InputProof>;

pub struct BbBn254Poseidon2 {
    pub perm: SC_Perm,
    pcs: SC_Pcs,
    simple_fri_config: SimpleFriConfig,
}

impl Serialize for BbBn254Poseidon2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        std::marker::PhantomData::<BbBn254Poseidon2>.serialize(serializer)
    }
}

impl Clone for BbBn254Poseidon2 {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl BbBn254Poseidon2 {
    pub fn new() -> Self {
        let perm = pico_poseidon2bn254_init();
        let hash = SC_Hash::new(perm.clone()).unwrap();
        let compress = SC_Compress::new(perm.clone());
        let val_mmcs = SC_ValMmcs::new(hash, compress);
        let challenge_mmcs = SC_ChallengeMmcs::new(val_mmcs.clone());
        let dft = SC_Dft::default();

        let num_queries = match std::env::var("FRI_QUERIES") {
            Ok(num_queries) => num_queries.parse().unwrap(),
            Err(_) => 25,
        };
        info!("NUM_QUERIES: {}", num_queries);
        let fri_config = FriConfig {
            log_blowup: 4,
            num_queries,
            proof_of_work_bits: 16,
            mmcs: challenge_mmcs,
        };
        let pcs = SC_Pcs::new(dft, val_mmcs, fri_config);

        let simple_fri_config = SimpleFriConfig {
            log_blowup: 4,
            num_queries,
            proof_of_work_bits: 16,
        };

        BbBn254Poseidon2 {
            perm,
            pcs,
            simple_fri_config,
        }
    }

    pub fn fri_config(&self) -> &SimpleFriConfig {
        &self.simple_fri_config
    }
}

impl Default for BbBn254Poseidon2 {
    fn default() -> Self {
        Self::new()
    }
}

impl StarkGenericConfig for BbBn254Poseidon2 {
    type Val = SC_Val;
    type Domain = <SC_Pcs as p3_commit::Pcs<SC_Challenge, SC_Challenger>>::Domain;
    type Challenge = SC_Challenge;
    type Challenger = SC_Challenger;
    type Pcs = SC_Pcs;

    fn pcs(&self) -> &Self::Pcs {
        &self.pcs
    }

    fn challenger(&self) -> Self::Challenger {
        SC_Challenger::new(self.perm.clone()).unwrap()
    }

    fn name(&self) -> String {
        "BbBn254Poseidon2".to_string()
    }
}
