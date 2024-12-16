use super::{WitnessWriter, Witnessable};
use crate::{
    compiler::recursion_v2::{
        circuit::{
            config::CircuitConfig,
            types::{
                BatchOpeningVariable, FriCommitPhaseProofStepVariable, FriProofVariable,
                QueryProofVariable,
            },
        },
        ir::{Builder, Felt},
    },
    configs::config::FieldGenericConfig,
    instances::configs::{recur_config as rcf, riscv_config::StarkConfig as RiscvSC},
    recursion_v2::air::Block,
};
use p3_baby_bear::BabyBear;
use p3_field::{FieldAlgebra, FieldExtensionAlgebra};
use p3_fri::{CommitPhaseProofStep, QueryProof};
use p3_symmetric::Hash;
use std::borrow::Borrow;

pub type WitnessBlock<FC> = Block<<FC as FieldGenericConfig>::F>;

impl<CC: CircuitConfig<F = BabyBear, Bit = Felt<BabyBear>>> WitnessWriter<CC>
    for Vec<WitnessBlock<CC>>
{
    fn write_bit(&mut self, value: bool) {
        self.push(Block::from(CC::F::from_bool(value)))
    }

    fn write_var(&mut self, _value: <CC>::N) {
        unimplemented!("Cannot write Var<N> in this configuration")
    }

    fn write_felt(&mut self, value: <CC>::F) {
        self.push(Block::from(value))
    }

    fn write_ext(&mut self, value: <CC>::EF) {
        self.push(Block::from(value.as_base_slice()))
    }
}

impl<C, F, W, const DIGEST_ELEMENTS: usize> Witnessable<C> for Hash<F, W, DIGEST_ELEMENTS>
where
    C: CircuitConfig<F = rcf::SC_Val, EF = rcf::SC_Challenge>,
    W: Witnessable<C>,
{
    type WitnessVariable = [W::WitnessVariable; DIGEST_ELEMENTS];

    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let array: &[W; DIGEST_ELEMENTS] = self.borrow();
        array.read(builder)
    }

    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        let array: &[W; DIGEST_ELEMENTS] = self.borrow();
        array.write(witness);
    }
}

impl<CC> Witnessable<CC> for rcf::SC_BatchOpening
where
    CC: CircuitConfig<F = rcf::SC_Val, EF = rcf::SC_Challenge, Bit = Felt<BabyBear>>,
{
    type WitnessVariable = BatchOpeningVariable<CC, RiscvSC>;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        let opened_values = self
            .opened_values
            .read(builder)
            .into_iter()
            .map(|a| a.into_iter().map(|b| vec![b]).collect())
            .collect();
        let opening_proof = self.opening_proof.read(builder);
        Self::WitnessVariable {
            opened_values,
            opening_proof,
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        self.opened_values.write(witness);
        self.opening_proof.write(witness);
    }
}

impl<CC: CircuitConfig<F = rcf::SC_Val, EF = rcf::SC_Challenge, Bit = Felt<BabyBear>>>
    Witnessable<CC> for rcf::SC_PcsProof
{
    type WitnessVariable = FriProofVariable<CC, RiscvSC>;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        let commit_phase_commits = self
            .commit_phase_commits
            .iter()
            .map(|commit| {
                let commit: &rcf::SC_Digest = commit.borrow();
                commit.read(builder)
            })
            .collect();
        let query_proofs = self.query_proofs.read(builder);
        let final_poly = self.final_poly.read(builder);
        let pow_witness = self.pow_witness.read(builder);
        Self::WitnessVariable {
            commit_phase_commits,
            query_proofs,
            final_poly,
            pow_witness,
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        self.commit_phase_commits.iter().for_each(|commit| {
            let commit = Borrow::<rcf::SC_Digest>::borrow(commit);
            commit.write(witness);
        });
        self.query_proofs.write(witness);
        self.final_poly.write(witness);
        self.pow_witness.write(witness);
    }
}

impl<CC: CircuitConfig<F = rcf::SC_Val, EF = rcf::SC_Challenge, Bit = Felt<BabyBear>>>
    Witnessable<CC> for rcf::SC_QueryProof
{
    type WitnessVariable = QueryProofVariable<CC, RiscvSC>;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        let input_proof = self.input_proof.read(builder);
        let commit_phase_openings = self.commit_phase_openings.read(builder);
        Self::WitnessVariable {
            input_proof,
            commit_phase_openings,
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        self.input_proof.write(witness);
        self.commit_phase_openings.write(witness);
    }
}

impl<CC: CircuitConfig<F = rcf::SC_Val, EF = rcf::SC_Challenge, Bit = Felt<BabyBear>>>
    Witnessable<CC> for CommitPhaseProofStep<rcf::SC_Challenge, rcf::SC_ChallengeMmcs>
{
    type WitnessVariable = FriCommitPhaseProofStepVariable<CC, RiscvSC>;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        let sibling_value = self.sibling_value.read(builder);
        let opening_proof = self.opening_proof.read(builder);
        Self::WitnessVariable {
            sibling_value,
            opening_proof,
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        self.sibling_value.write(witness);
        self.opening_proof.write(witness);
    }
}
