use super::{
    challenger::CanObserveVariable,
    config::{CircuitConfig, FieldFriConfigVariable},
    hash::FieldHasherVariable,
};
use crate::{
    compiler::recursion_v2::prelude::*, machine::septic::SepticDigest,
    primitives::consts::DIGEST_SIZE,
};
use hashbrown::HashMap;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::{FieldAlgebra, TwoAdicField};
use p3_matrix::Dimensions;

#[derive(Clone)]
pub struct BaseVerifyingKeyVariable<CC, SC>
where
    CC: CircuitConfig,
    CC::F: TwoAdicField,
    SC: FieldFriConfigVariable<CC, Val = CC::F, Domain = TwoAdicMultiplicativeCoset<CC::F>>,
{
    pub commit: SC::DigestVariable,
    pub pc_start: Felt<CC::F>,
    pub initial_global_cumulative_sum: SepticDigest<Felt<CC::F>>,
    pub preprocessed_info: Vec<(String, SC::Domain, Dimensions)>,
    pub preprocessed_chip_ordering: HashMap<String, usize>,
}

#[derive(Clone)]
pub struct FriProofVariable<CC: CircuitConfig, H: FieldHasherVariable<CC>> {
    pub commit_phase_commits: Vec<H::DigestVariable>,
    pub query_proofs: Vec<QueryProofVariable<CC, H>>,
    pub final_poly: Ext<CC::F, CC::EF>,
    pub pow_witness: Felt<CC::F>,
}

#[derive(Clone)]
pub struct QueryProofVariable<CC: CircuitConfig, H: FieldHasherVariable<CC>> {
    pub input_proof: Vec<BatchOpeningVariable<CC, H>>,
    pub commit_phase_openings: Vec<FriCommitPhaseProofStepVariable<CC, H>>,
}

#[derive(Clone)]
pub struct BatchOpeningVariable<CC: CircuitConfig, H: FieldHasherVariable<CC>> {
    pub opened_values: Vec<Vec<Vec<Felt<CC::F>>>>,
    pub opening_proof: Vec<H::DigestVariable>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/proof.rs#L32
#[derive(Clone)]
pub struct FriCommitPhaseProofStepVariable<CC: CircuitConfig, H: FieldHasherVariable<CC>> {
    pub sibling_value: Ext<CC::F, CC::EF>,
    pub opening_proof: Vec<H::DigestVariable>,
}

/// Reference: https://github.com/Plonky3/Plonky3/blob/4809fa7bedd9ba8f6f5d3267b1592618e3776c57/fri/src/verifier.rs#L22
#[derive(Clone)]
pub struct FriChallengesVariable<CC: CircuitConfig> {
    pub query_indices: Vec<Vec<CC::Bit>>,
    pub betas: Vec<Ext<CC::F, CC::EF>>,
}

// #[derive(Clone)]
// pub struct TwoAdicPcsProofVariable<CC: CircuitConfig, H: FieldHasherVariable<CC>> {
//     pub fri_proof: FriProofVariable<CC, H>,
//     pub query_openings: Vec<Vec<BatchOpeningVariable<CC, H>>>,
// }

#[derive(Clone)]
pub struct TwoAdicPcsRoundVariable<CC: CircuitConfig, H: FieldHasherVariable<CC>, Domain> {
    pub batch_commit: H::DigestVariable,
    pub domains_points_and_opens: Vec<TwoAdicPcsMatsVariable<CC, Domain>>,
}

#[derive(Clone)]
pub struct TwoAdicPcsMatsVariable<CC: CircuitConfig, Domain> {
    pub domain: Domain,
    pub points: Vec<Ext<CC::F, CC::EF>>,
    pub values: Vec<Vec<Ext<CC::F, CC::EF>>>,
}

impl<CC, SC> BaseVerifyingKeyVariable<CC, SC>
where
    CC: CircuitConfig,
    CC::F: TwoAdicField,
    SC: FieldFriConfigVariable<CC, Val = CC::F, Domain = TwoAdicMultiplicativeCoset<CC::F>>,
{
    pub fn observed_by<Challenger>(&self, builder: &mut Builder<CC>, challenger: &mut Challenger)
    where
        Challenger:
            CanObserveVariable<CC, Felt<CC::F>> + CanObserveVariable<CC, SC::DigestVariable>,
    {
        // Observe the commitment.
        challenger.observe(builder, self.commit);
        // Observe the pc_start.
        challenger.observe(builder, self.pc_start);
        challenger.observe_slice(builder, self.initial_global_cumulative_sum.0.x.0);
        challenger.observe_slice(builder, self.initial_global_cumulative_sum.0.y.0);
        let zero: Felt<_> = builder.eval(CC::F::ZERO);
        for _ in 0..7 {
            challenger.observe(builder, zero);
        }
    }

    /// Hash the verifying key + prep domains into a single digest.
    /// poseidon2( commit[0..8] || pc_start || prep_domains[N].{log_n, .size, .shift, .g})
    pub fn hash_field(&self, builder: &mut Builder<CC>) -> SC::DigestVariable
    where
        CC::F: TwoAdicField,
        SC::DigestVariable: IntoIterator<Item = Felt<CC::F>>,
    {
        let prep_domains = self.preprocessed_info.iter().map(|(_, domain, _)| domain);
        let num_inputs = DIGEST_SIZE + 1 + (4 * prep_domains.len());
        let mut inputs = Vec::with_capacity(num_inputs);
        inputs.extend(self.commit);
        inputs.push(self.pc_start);
        for domain in prep_domains {
            inputs.push(builder.eval(CC::F::from_canonical_usize(domain.log_n)));
            let size = 1 << domain.log_n;
            inputs.push(builder.eval(CC::F::from_canonical_usize(size)));
            let g = CC::F::two_adic_generator(domain.log_n);
            inputs.push(builder.eval(domain.shift));
            inputs.push(builder.eval(g));
        }

        SC::hash(builder, &inputs)
    }
}
