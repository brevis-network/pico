use crate::configs::{config::StarkGenericConfig, stark_config::utils::bn254_poseidon2_rc3};
use p3_baby_bear::BabyBear;
use p3_bn254_fr::{Bn254Fr, DiffusionMatrixBN254};
use p3_challenger::MultiField32Challenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{
    BatchOpening, CommitPhaseProofStep, FriConfig, FriProof, QueryProof, TwoAdicFriPcs,
    TwoAdicFriPcsProof,
};
use p3_merkle_tree::FieldMerkleTreeMmcs;
use p3_poseidon2::{Poseidon2, Poseidon2ExternalMatrixGeneral};
use p3_symmetric::{Hash, MultiField32PaddingFreeSponge, TruncatedPermutation};
use serde::Serialize;
use tracing::info;
// todo: deeper understanding of the following types

#[allow(non_camel_case_types)]
pub type SC_Val = BabyBear;
#[allow(non_camel_case_types)]
pub type SC_Perm = Poseidon2<Bn254Fr, Poseidon2ExternalMatrixGeneral, DiffusionMatrixBN254, 3, 5>;
#[allow(non_camel_case_types)]
pub type SC_Hash = MultiField32PaddingFreeSponge<SC_Val, Bn254Fr, SC_Perm, 3, 16, 1>;
#[allow(non_camel_case_types)]
pub type SC_DigestHash = Hash<Bn254Fr, Bn254Fr, 1>;
#[allow(non_camel_case_types)]
pub type SC_Digest = [Bn254Fr; 1];
#[allow(non_camel_case_types)]
pub type SC_Compress = TruncatedPermutation<SC_Perm, 2, 1, 3>;
#[allow(non_camel_case_types)]
pub type SC_ValMmcs = FieldMerkleTreeMmcs<BabyBear, Bn254Fr, SC_Hash, SC_Compress, 1>;
#[allow(non_camel_case_types)]
pub type SC_Challenge = BinomialExtensionField<SC_Val, 4>;
#[allow(non_camel_case_types)]
pub type SC_ChallengeMmcs = ExtensionMmcs<SC_Val, SC_Challenge, SC_ValMmcs>;
#[allow(non_camel_case_types)]
pub type SC_Challenger = MultiField32Challenger<SC_Val, Bn254Fr, SC_Perm, 3>;
#[allow(non_camel_case_types)]
pub type SC_Dft = Radix2DitParallel;
#[allow(non_camel_case_types)]
pub type SC_Pcs = TwoAdicFriPcs<SC_Val, SC_Dft, SC_ValMmcs, SC_ChallengeMmcs>;

#[allow(non_camel_case_types)]
pub type SC_QueryProof = QueryProof<SC_Challenge, SC_ChallengeMmcs>;
#[allow(non_camel_case_types)]
pub type SC_CommitPhaseStep = CommitPhaseProofStep<SC_Challenge, SC_ChallengeMmcs>;
#[allow(non_camel_case_types)]
pub type SC_FriProof = FriProof<SC_Challenge, SC_ChallengeMmcs, SC_Val>;
#[allow(non_camel_case_types)]
pub type SC_BatchOpening = BatchOpening<SC_Val, SC_ValMmcs>;
#[allow(non_camel_case_types)]
pub type SC_PcsProof = TwoAdicFriPcsProof<SC_Val, SC_Challenge, SC_ValMmcs, SC_ChallengeMmcs>;

pub struct BbBn254Poseidon2 {
    pub perm: SC_Perm,
    pub pcs: SC_Pcs,
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
    #[must_use]
    pub fn my_perm() -> SC_Perm {
        const ROUNDS_F: usize = 8;
        const ROUNDS_P: usize = 56;
        let mut round_constants = bn254_poseidon2_rc3();
        let internal_start = ROUNDS_F / 2;
        let internal_end = (ROUNDS_F / 2) + ROUNDS_P;
        let internal_round_constants = round_constants
            .drain(internal_start..internal_end)
            .map(|vec| vec[0])
            .collect::<Vec<_>>();
        let external_round_constants = round_constants;
        SC_Perm::new(
            ROUNDS_F,
            external_round_constants,
            Poseidon2ExternalMatrixGeneral,
            ROUNDS_P,
            internal_round_constants,
            DiffusionMatrixBN254,
        )
    }

    pub fn new() -> Self {
        let perm = Self::my_perm();
        let hash = SC_Hash::new(perm.clone()).unwrap();
        let compress = SC_Compress::new(perm.clone());
        let val_mmcs = SC_ValMmcs::new(hash, compress);
        let challenge_mmcs = SC_ChallengeMmcs::new(val_mmcs.clone());
        let dft = SC_Dft {};

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
        let pcs = SC_Pcs::new(27, dft, val_mmcs, fri_config);

        BbBn254Poseidon2 { perm, pcs }
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
