use crate::{
    configs::config::{Com, SimpleFriConfig, StarkGenericConfig, Val, ZeroCommitment},
    primitives::{consts::DIGEST_SIZE, PicoPoseidon2KoalaBear, Poseidon2Init},
};
use p3_challenger::DuplexChallenger;
use p3_commit::{ExtensionMmcs, Pcs};
use p3_dft::Radix2DitParallel;
use p3_field::{extension::BinomialExtensionField, Field, FieldAlgebra};
use p3_fri::{FriConfig, TwoAdicFriPcs};
use p3_koala_bear::KoalaBear;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge, TruncatedPermutation};
use serde::Serialize;

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
pub type SC_Pcs_tmp = TwoAdicFriPcs<SC_Val, SC_Dft, SC_ValMmcs, SC_ChallengeMmcs>;
pub type SC_DigestHash = p3_symmetric::Hash<SC_Val, SC_Val, DIGEST_SIZE>;

#[derive(Debug)]
pub struct ProxyPcs(SC_Pcs_tmp);

pub type SC_Pcs = ProxyPcs;

impl Pcs<SC_Challenge, SC_Challenger> for ProxyPcs {
    type Domain = <SC_Pcs_tmp as Pcs<SC_Challenge, SC_Challenger>>::Domain;
    type Commitment = <SC_Pcs_tmp as Pcs<SC_Challenge, SC_Challenger>>::Commitment;
    type ProverData = <SC_Pcs_tmp as Pcs<SC_Challenge, SC_Challenger>>::ProverData;
    type Proof = <SC_Pcs_tmp as Pcs<SC_Challenge, SC_Challenger>>::Proof;
    type Error = <SC_Pcs_tmp as Pcs<SC_Challenge, SC_Challenger>>::Error;

    fn natural_domain_for_degree(&self, degree: usize) -> Self::Domain {
        <SC_Pcs_tmp as Pcs<SC_Challenge, SC_Challenger>>::natural_domain_for_degree(&self.0, degree)
    }

    fn commit(
        &self,
        evaluations: Vec<(Self::Domain, p3_matrix::dense::RowMajorMatrix<p3_commit::Val<Self::Domain>>)>,
    ) -> (Self::Commitment, Self::ProverData) {
        <SC_Pcs_tmp as Pcs<SC_Challenge, SC_Challenger>>::commit(&self.0, evaluations)
    }

    fn get_evaluations_on_domain<'a>(
        &self,
        prover_data: &'a Self::ProverData,
        idx: usize,
        domain: Self::Domain,
    ) -> impl p3_matrix::Matrix<p3_commit::Val<Self::Domain>> + 'a {
        <SC_Pcs_tmp as Pcs<SC_Challenge, SC_Challenger>>::get_evaluations_on_domain(&self.0, prover_data, idx, domain)
    }

    fn open(
        &self,
        // For each round,
        rounds: Vec<(
            &Self::ProverData,
            // for each matrix,
            Vec<
                // points to open
                Vec<SC_Challenge>,
            >,
        )>,
        challenger: &mut SC_Challenger,
    ) -> (p3_commit::OpenedValues<SC_Challenge>, Self::Proof) {
        use log::info;
        use core::mem::size_of_val;

        let mut total_size: usize = 0;
        let (opened, proof) = <SC_Pcs_tmp as Pcs<SC_Challenge, SC_Challenger>>::open(&self.0, rounds, challenger);

        // Hash is a wrapper around [W; DIGEST_ELEMS]
        // get n * this array size
        total_size += size_of_val(proof.commit_phase_commits.as_slice());

        // sum up each proof
        for qp in proof.query_proofs.iter() {
            // add up the sizes of each InputProof
            for ip in qp.input_proof.iter() {
                // each InputProof is a BatchOpening
                // opened_values: Vec<Vec<Val>>
                // for each outer vec elem, get the total slice size (n * sizeof(Val))
                ip.opened_values.iter().for_each(|v| total_size += size_of_val(v.as_slice()));

                // opening_proof: Vec<[<PW as PackedValue>::Value; DIGEST_ELEMS]>
                total_size += size_of_val(ip.opening_proof.as_slice());
            }

            // CommitPhaseOpening sizes
            qp.commit_phase_openings.iter().for_each(|cpo| {
                // opening_proof: Vec<[<PW as PackedValue>::Value; DIGEST_ELEMS]>
                // get vec length * sizeof the array item
                total_size += size_of_val(cpo.opening_proof.as_slice());
                total_size += size_of_val(&cpo.sibling_value);
            });
        }

        total_size += size_of_val(&proof.final_poly);
        total_size += size_of_val(&proof.pow_witness);

        info!("FRIProof total element size: {}", total_size);

        (opened, proof)
    }

    fn verify(
        &self,
        // For each round:
        rounds: Vec<(
            Self::Commitment,
            // for each matrix:
            Vec<(
                // its domain,
                Self::Domain,
                // for each point:
                Vec<(
                    // the point,
                    SC_Challenge,
                    // values at the point
                    Vec<SC_Challenge>,
                )>,
            )>,
        )>,
        proof: &Self::Proof,
        challenger: &mut SC_Challenger,
    ) -> Result<(), Self::Error> {
        <SC_Pcs_tmp as Pcs<SC_Challenge, SC_Challenger>>::verify(&self.0, rounds, proof, challenger)
    }
}

#[derive(Clone)]
pub struct KoalaBearPoseidon2 {
    pub perm: SC_Perm,
    simple_fri_config: SimpleFriConfig,
    log_blowup: usize,
    num_queries: usize,
}

impl Serialize for KoalaBearPoseidon2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        std::marker::PhantomData::<KoalaBearPoseidon2>.serialize(serializer)
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

    /// Targeting 100 bits of security.
    fn new() -> Self {
        let perm = Self::init();
        let num_queries = match std::env::var("FRI_QUERIES") {
            Ok(num_queries) => num_queries.parse().unwrap(),
            Err(_) => 84,
        };

        let log_blowup = 1;
        let simple_fri_config = SimpleFriConfig {
            log_blowup,
            num_queries,
            proof_of_work_bits: 16,
        };

        Self {
            perm,
            simple_fri_config,
            log_blowup,
            num_queries,
        }
    }

    fn pcs(&self) -> Self::Pcs {
        let hash = SC_Hash::new(self.perm.clone());
        let compress = SC_Compress::new(self.perm.clone());
        let val_mmcs = SC_ValMmcs::new(hash, compress);
        let fri_config = FriConfig {
            log_blowup: self.log_blowup,
            num_queries: self.num_queries,
            proof_of_work_bits: 16,
            mmcs: SC_ChallengeMmcs::new(val_mmcs.clone()),
        };
        ProxyPcs(SC_Pcs_tmp::new(SC_Dft::default(), val_mmcs.clone(), fri_config))
    }

    fn challenger(&self) -> Self::Challenger {
        SC_Challenger::new(self.perm.clone())
    }

    fn name(&self) -> String {
        "KoalaBearPoseidon2".to_string()
    }

    fn hash_slice(&self, input: &[Val<Self>]) -> [Val<Self>; DIGEST_SIZE] {
        let hash = SC_Hash::new(self.perm.clone());
        hash.hash_slice(input)
    }
}

impl KoalaBearPoseidon2 {
    /// Targeting 100 bits of security.
    pub fn compress() -> Self {
        let perm = Self::init();
        let num_queries = match std::env::var("FRI_QUERIES") {
            Ok(num_queries) => num_queries.parse().unwrap(),
            // fix from log_blowup=3 and num_queries=28 to log_blowup=4 and num_queries=21 to
            // reduce the compress proof size
            // Err(_) => 28,
            Err(_) => 21,
        };

        // let log_blowup = 3;
        let log_blowup = 4;
        let simple_fri_config = SimpleFriConfig {
            log_blowup,
            num_queries,
            proof_of_work_bits: 16,
        };

        Self {
            perm,
            simple_fri_config,
            log_blowup,
            num_queries,
        }
    }

    pub fn fri_config(&self) -> &SimpleFriConfig {
        &self.simple_fri_config
    }
}

impl ZeroCommitment<KoalaBearPoseidon2> for SC_Pcs {
    fn zero_commitment(&self) -> Com<KoalaBearPoseidon2> {
        SC_DigestHash::from([SC_Val::ZERO; DIGEST_SIZE])
    }
}
