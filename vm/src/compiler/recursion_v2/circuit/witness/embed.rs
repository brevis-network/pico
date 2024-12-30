use crate::{
    compiler::recursion_v2::{
        circuit::{
            config::{BabyBearFriConfigVariable, CircuitConfig},
            hash::FieldHasherVariable,
            stark::BaseProofVariable,
            types::{
                BaseVerifyingKeyVariable, BatchOpeningVariable, FriCommitPhaseProofStepVariable,
                FriProofVariable, QueryProofVariable,
            },
            witness::{WitnessWriter, Witnessable},
        },
        ir::{Builder, Felt, Var, Witness},
    },
    configs::{
        config::{Com, PcsProof, StarkGenericConfig},
        stark_config::{bb_bn254_poseidon2 as ecf, bb_bn254_poseidon2::BabyBearBn254Poseidon2},
    },
    instances::configs::embed_config::{FieldConfig as EmbedFC, StarkConfig as EmbedSC},
    machine::{keys::BaseVerifyingKey, proof::BaseProof},
};
use core::borrow::Borrow;
use p3_baby_bear::BabyBear;
use p3_bn254_fr::Bn254Fr;
use p3_field::{extension::BinomialExtensionField, FieldAlgebra};
use p3_fri::CommitPhaseProofStep;

impl<C: CircuitConfig<N = Bn254Fr>> Witnessable<C> for Bn254Fr {
    type WitnessVariable = Var<Bn254Fr>;
    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        builder.witness_var()
    }
    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        witness.write_var(*self)
    }
}

pub struct EmbedWitnessValues<SC: StarkGenericConfig> {
    pub vks_and_proofs: Vec<(BaseVerifyingKey<SC>, BaseProof<SC>)>,
    pub is_complete: bool,
}
pub struct EmbedWitnessVariable<C: CircuitConfig<F = BabyBear>, SC: BabyBearFriConfigVariable<C>> {
    /// The chunk proofs to verify.
    pub vks_and_proofs: Vec<(BaseVerifyingKeyVariable<C, SC>, BaseProofVariable<C, SC>)>,
    pub is_complete: Felt<C::F>,
}
impl WitnessWriter<EmbedFC> for Witness<EmbedFC> {
    fn write_bit(&mut self, value: bool) {
        self.vars.push(Bn254Fr::from_bool(value));
    }
    fn write_var(&mut self, value: Bn254Fr) {
        self.vars.push(value);
    }
    fn write_felt(&mut self, value: BabyBear) {
        self.felts.push(value);
    }
    fn write_ext(&mut self, value: ecf::SC_Challenge) {
        self.exts.push(value);
    }
}
impl<
        C: CircuitConfig<F = BabyBear, EF = BinomialExtensionField<BabyBear, 4>>,
        SC: BabyBearFriConfigVariable<C>,
    > Witnessable<C> for EmbedWitnessValues<SC>
where
    Com<SC>: Witnessable<C, WitnessVariable = <SC as FieldHasherVariable<C>>::DigestVariable>,
    PcsProof<SC>: Witnessable<C, WitnessVariable = FriProofVariable<C, SC>>,
{
    type WitnessVariable = EmbedWitnessVariable<C, SC>;
    fn read(&self, builder: &mut Builder<C>) -> Self::WitnessVariable {
        let vks_and_proofs = self.vks_and_proofs.read(builder);
        let is_complete = BabyBear::from_bool(self.is_complete).read(builder);
        EmbedWitnessVariable {
            vks_and_proofs,
            is_complete,
        }
    }
    fn write(&self, witness: &mut impl WitnessWriter<C>) {
        self.vks_and_proofs.write(witness);
        BabyBear::from_bool(self.is_complete).write(witness);
    }
}

impl<
        CC: CircuitConfig<F = ecf::SC_Val, N = Bn254Fr, EF = ecf::SC_Challenge, Bit = Var<Bn254Fr>>,
    > Witnessable<CC> for ecf::SC_PcsProof
{
    type WitnessVariable = FriProofVariable<CC, BabyBearBn254Poseidon2>;
    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        let commit_phase_commits = self
            .commit_phase_commits
            .iter()
            .map(|commit| {
                let commit: &crate::configs::stark_config::bb_bn254_poseidon2::SC_Digest =
                    commit.borrow();
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
            let commit = Borrow::<ecf::SC_Digest>::borrow(commit);
            commit.write(witness);
        });
        self.query_proofs.write(witness);
        self.final_poly.write(witness);
        self.pow_witness.write(witness);
    }
}
impl<
        CC: CircuitConfig<F = ecf::SC_Val, N = Bn254Fr, EF = ecf::SC_Challenge, Bit = Var<Bn254Fr>>,
    > Witnessable<CC> for ecf::SC_QueryProof
{
    type WitnessVariable = QueryProofVariable<CC, ecf::BabyBearBn254Poseidon2>;
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
impl<
        CC: CircuitConfig<F = ecf::SC_Val, N = Bn254Fr, EF = ecf::SC_Challenge, Bit = Var<Bn254Fr>>,
    > Witnessable<CC> for CommitPhaseProofStep<ecf::SC_Challenge, ecf::SC_ChallengeMmcs>
{
    type WitnessVariable = FriCommitPhaseProofStepVariable<CC, BabyBearBn254Poseidon2>;
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
impl<CC> Witnessable<CC> for ecf::SC_BatchOpening
where
    CC: CircuitConfig<F = ecf::SC_Val, N = Bn254Fr, EF = ecf::SC_Challenge, Bit = Var<Bn254Fr>>,
{
    type WitnessVariable = BatchOpeningVariable<CC, BabyBearBn254Poseidon2>;
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
