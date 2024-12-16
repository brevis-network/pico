use crate::{
    configs::config::{Com, Dom, PcsProverData, StarkGenericConfig},
    primitives::{consts::DIGEST_SIZE, poseidon2_hash},
};
use alloc::sync::Arc;
use hashbrown::HashMap;
use p3_baby_bear::BabyBear;
use p3_challenger::CanObserve;
use p3_commit::{Pcs, TwoAdicMultiplicativeCoset};
use p3_field::{FieldAlgebra, TwoAdicField};
use p3_matrix::{dense::RowMajorMatrix, Dimensions};

pub struct BaseProvingKey<SC: StarkGenericConfig> {
    /// The commitment to the named traces.
    pub commit: Com<SC>,
    /// start pc of program
    pub pc_start: SC::Val,
    /// named preprocessed traces.
    pub preprocessed_trace: Vec<RowMajorMatrix<SC::Val>>,
    /// The pcs data for the preprocessed traces.
    pub preprocessed_prover_data: PcsProverData<SC>,
    /// the index of for chips, chip name for key
    pub preprocessed_chip_ordering: Arc<HashMap<String, usize>>,
}

impl<SC: StarkGenericConfig> BaseProvingKey<SC> {
    /// Observes the values of the proving key into the challenger.
    pub fn observed_by(&self, challenger: &mut SC::Challenger) {
        challenger.observe(self.commit.clone());
        challenger.observe(self.pc_start);
    }
}

#[derive(Clone)]
pub struct BaseVerifyingKey<SC: StarkGenericConfig> {
    /// The commitment to the preprocessed traces.
    pub commit: Com<SC>,
    /// start pc of program
    pub pc_start: SC::Val,
    /// The preprocessed information.
    pub preprocessed_info: Arc<[(String, SC::Domain, Dimensions)]>,
    /// the index of for chips, chip name for key
    pub preprocessed_chip_ordering: Arc<HashMap<String, usize>>,
}

impl<SC: StarkGenericConfig> BaseVerifyingKey<SC> {
    /// Observes the values of the verifying key into the challenger.
    pub fn observed_by(&self, challenger: &mut SC::Challenger) {
        challenger.observe(self.commit.clone());
        challenger.observe(self.pc_start);
    }
}

/// A trait for keys that can be hashed into a digest.
pub trait HashableKey {
    /// Hash the key into a digest of BabyBear elements.
    fn hash_babybear(&self) -> [BabyBear; DIGEST_SIZE];
}

impl<SC: StarkGenericConfig<Val = BabyBear, Domain = TwoAdicMultiplicativeCoset<BabyBear>>>
    HashableKey for BaseVerifyingKey<SC>
where
    <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment: AsRef<[BabyBear; DIGEST_SIZE]>,
{
    fn hash_babybear(&self) -> [BabyBear; DIGEST_SIZE] {
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

        poseidon2_hash(inputs)
    }
}
