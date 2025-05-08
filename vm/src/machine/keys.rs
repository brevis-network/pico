use super::septic::SepticDigest;
use crate::{
    configs::config::{Com, Dom, PcsProverData, StarkGenericConfig, Val},
    primitives::{
        consts::DIGEST_SIZE, POSEIDON2_BB_HASHER, POSEIDON2_KB_HASHER, POSEIDON2_M31_HASHER,
    },
};
use alloc::sync::Arc;
use hashbrown::HashMap;
use p3_baby_bear::BabyBear;
use p3_bn254_fr::Bn254Fr;
use p3_challenger::CanObserve;
use p3_circle::CircleDomain;
use p3_commit::{Pcs, PolynomialSpace, TwoAdicMultiplicativeCoset};
use p3_field::{FieldAlgebra, PrimeField, PrimeField32, TwoAdicField};
use p3_koala_bear::KoalaBear;
use p3_matrix::{dense::RowMajorMatrix, Dimensions};
use p3_mersenne_31::Mersenne31;
use p3_symmetric::CryptographicHasher;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct BaseProvingKey<SC: StarkGenericConfig> {
    /// The commitment to the named traces.
    pub commit: Com<SC>,
    /// start pc of program
    pub pc_start: SC::Val,
    /// named preprocessed traces.
    pub preprocessed_trace: Arc<[RowMajorMatrix<SC::Val>]>,
    /// The pcs data for the preprocessed traces.
    pub preprocessed_prover_data: PcsProverData<SC>,
    /// the index of for chips, chip name for key
    pub preprocessed_chip_ordering: Arc<HashMap<String, usize>>,
    /// The starting global digest of the program, after incorporating the initial memory.
    pub initial_global_cumulative_sum: SepticDigest<SC::Val>,
    /// The preprocessed chip local only information.
    pub local_only: Arc<[bool]>,
}

impl<SC: StarkGenericConfig> Clone for BaseProvingKey<SC>
where
    PcsProverData<SC>: Clone,
{
    fn clone(&self) -> Self {
        Self {
            commit: self.commit.clone(),
            pc_start: self.pc_start,
            preprocessed_trace: self.preprocessed_trace.clone(),
            preprocessed_prover_data: self.preprocessed_prover_data.clone(),
            preprocessed_chip_ordering: self.preprocessed_chip_ordering.clone(),
            initial_global_cumulative_sum: self.initial_global_cumulative_sum,
            local_only: self.local_only.clone(),
        }
    }
}

impl<SC: StarkGenericConfig> BaseProvingKey<SC> {
    /// Observes the values of the proving key into the challenger.
    pub fn observed_by(&self, challenger: &mut SC::Challenger) {
        challenger.observe(self.commit.clone());
        challenger.observe(self.pc_start);
        challenger.observe_slice(&self.initial_global_cumulative_sum.0.x.0);
        challenger.observe_slice(&self.initial_global_cumulative_sum.0.y.0);
        for _ in 0..7 {
            challenger.observe(Val::<SC>::ZERO);
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "Dom<SC>: Serialize"))]
#[serde(bound(deserialize = "Dom<SC>: DeserializeOwned"))]
pub struct BaseVerifyingKey<SC: StarkGenericConfig> {
    /// The commitment to the preprocessed traces.
    pub commit: Com<SC>,
    /// start pc of program
    pub pc_start: SC::Val,
    /// The preprocessed information.
    pub preprocessed_info: Arc<[(String, Dom<SC>, Dimensions)]>,
    /// the index of for chips, chip name for key
    pub preprocessed_chip_ordering: Arc<HashMap<String, usize>>,
    /// The starting global digest of the program, after incorporating the initial memory.
    pub initial_global_cumulative_sum: SepticDigest<SC::Val>,
}

impl<SC: StarkGenericConfig> BaseVerifyingKey<SC> {
    /// Observes the values of the verifying key into the challenger.
    pub fn observed_by(&self, challenger: &mut SC::Challenger) {
        challenger.observe(self.commit.clone());
        challenger.observe(self.pc_start);
        challenger.observe_slice(&self.initial_global_cumulative_sum.0.x.0);
        challenger.observe_slice(&self.initial_global_cumulative_sum.0.y.0);
        for _ in 0..7 {
            challenger.observe(Val::<SC>::ZERO);
        }
    }
}

/// A trait for keys that can be hashed into a digest.
pub trait HashableKey<F> {
    /// Hash the key into a digest of BabyBear elements.
    fn hash_field(&self) -> [F; DIGEST_SIZE];

    fn hash_bn254(&self) -> Bn254Fr
    where
        F: PrimeField32,
    {
        let mut bn254 = Bn254Fr::ZERO;
        for word in self.hash_field() {
            bn254 *= Bn254Fr::from_canonical_u32(1 << 31);
            bn254 += Bn254Fr::from_canonical_u32(word.as_canonical_u32());
        }
        bn254
    }

    fn hash_str_via_bn254(&self) -> String
    where
        F: PrimeField32,
    {
        format!(
            "0x{:0>64}",
            self.hash_bn254().as_canonical_biguint().to_str_radix(16)
        )
    }
}

impl<SC: StarkGenericConfig<Val = BabyBear, Domain = TwoAdicMultiplicativeCoset<BabyBear>>>
    HashableKey<BabyBear> for BaseVerifyingKey<SC>
where
    <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment: AsRef<[BabyBear; DIGEST_SIZE]>,
{
    fn hash_field(&self) -> [BabyBear; DIGEST_SIZE] {
        let prep_domains = self.preprocessed_info.iter().map(|(_, domain, _)| domain);
        let num_inputs = DIGEST_SIZE + 1 + (4 * prep_domains.len());
        let mut inputs = Vec::with_capacity(num_inputs);
        inputs.extend(self.commit.as_ref());
        inputs.push(self.pc_start);
        for domain in prep_domains {
            inputs.push(BabyBear::from_canonical_usize(domain.log_n));
            let size = 1 << domain.log_n;
            inputs.push(BabyBear::from_canonical_usize(size));
            let g = BabyBear::two_adic_generator(domain.log_n);
            inputs.push(domain.shift);
            inputs.push(g);
        }

        POSEIDON2_BB_HASHER.hash_iter(inputs)
    }
}

impl<SC: StarkGenericConfig<Val = KoalaBear, Domain = TwoAdicMultiplicativeCoset<KoalaBear>>>
    HashableKey<KoalaBear> for BaseVerifyingKey<SC>
where
    <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment: AsRef<[KoalaBear; DIGEST_SIZE]>,
{
    fn hash_field(&self) -> [KoalaBear; DIGEST_SIZE] {
        let prep_domains = self.preprocessed_info.iter().map(|(_, domain, _)| domain);
        let num_inputs = DIGEST_SIZE + 1 + (4 * prep_domains.len());
        let mut inputs = Vec::with_capacity(num_inputs);
        inputs.extend(self.commit.as_ref());
        inputs.push(self.pc_start);
        for domain in prep_domains {
            inputs.push(KoalaBear::from_canonical_usize(domain.log_n));
            let size = 1 << domain.log_n;
            inputs.push(KoalaBear::from_canonical_usize(size));
            let g = KoalaBear::two_adic_generator(domain.log_n);
            inputs.push(domain.shift);
            inputs.push(g);
        }

        POSEIDON2_KB_HASHER.hash_iter(inputs)
    }
}

impl<SC: StarkGenericConfig<Val = Mersenne31, Domain = CircleDomain<Mersenne31>>>
    HashableKey<Mersenne31> for BaseVerifyingKey<SC>
where
    <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment: AsRef<[Mersenne31; DIGEST_SIZE]>,
{
    fn hash_field(&self) -> [Mersenne31; DIGEST_SIZE] {
        let prep_domains = self.preprocessed_info.iter().map(|(_, domain, _)| domain);
        let num_inputs = DIGEST_SIZE + 1 + (4 * prep_domains.len());
        let mut inputs = Vec::with_capacity(num_inputs);
        inputs.extend(self.commit.as_ref());
        inputs.push(self.pc_start);
        for domain in prep_domains {
            inputs.push(Mersenne31::from_canonical_usize(domain.log_n));
            inputs.push(Mersenne31::from_canonical_usize(domain.size()));
            inputs.push(domain.first_point());
        }

        POSEIDON2_M31_HASHER.hash_iter(inputs)
    }
}
