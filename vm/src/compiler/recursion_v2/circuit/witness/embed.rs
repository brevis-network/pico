use crate::{
    compiler::recursion_v2::{
        circuit::{
            config::CircuitConfig,
            types::{
                BatchOpeningVariable, FriCommitPhaseProofStepVariable, FriProofVariable,
                QueryProofVariable,
            },
            witness::{WitnessWriter, Witnessable},
        },
        ir::{Builder, Var, Witness},
    },
    configs::stark_config::{
        bb_bn254_poseidon2::{self, BabyBearBn254Poseidon2},
        kb_bn254_poseidon2::{self, KoalaBearBn254Poseidon2},
    },
};
use core::borrow::Borrow;
use p3_bn254_fr::Bn254Fr;
use p3_field::FieldAlgebra;
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

impl<CC: CircuitConfig> WitnessWriter<CC> for Witness<CC> {
    fn write_bit(&mut self, value: bool) {
        self.vars.push(CC::N::from_bool(value));
    }
    fn write_var(&mut self, value: CC::N) {
        self.vars.push(value);
    }
    fn write_felt(&mut self, value: CC::F) {
        self.felts.push(value);
    }
    fn write_ext(&mut self, value: CC::EF) {
        self.exts.push(value);
    }
}

macro_rules! impl_pcs_related_witnessable {
    ($mod_name:ident, $sc_name:ident) => {
        impl<
                CC: CircuitConfig<
                    F = $mod_name::SC_Val,
                    N = Bn254Fr,
                    EF = $mod_name::SC_Challenge,
                    Bit = Var<Bn254Fr>,
                >,
            > Witnessable<CC> for $mod_name::SC_PcsProof
        {
            type WitnessVariable = FriProofVariable<CC, $sc_name>;
            fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
                let commit_phase_commits = self
                    .commit_phase_commits
                    .iter()
                    .map(|commit| {
                        let commit: $mod_name::SC_Digest = *commit.borrow();
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
                    let commit = Borrow::<$mod_name::SC_Digest>::borrow(commit);
                    commit.write(witness);
                });
                self.query_proofs.write(witness);
                self.final_poly.write(witness);
                self.pow_witness.write(witness);
            }
        }
        impl<
                CC: CircuitConfig<
                    F = $mod_name::SC_Val,
                    N = Bn254Fr,
                    EF = $mod_name::SC_Challenge,
                    Bit = Var<Bn254Fr>,
                >,
            > Witnessable<CC> for $mod_name::SC_QueryProof
        {
            type WitnessVariable = QueryProofVariable<CC, $sc_name>;
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
                CC: CircuitConfig<
                    F = $mod_name::SC_Val,
                    N = Bn254Fr,
                    EF = $mod_name::SC_Challenge,
                    Bit = Var<Bn254Fr>,
                >,
            > Witnessable<CC>
            for CommitPhaseProofStep<$mod_name::SC_Challenge, $mod_name::SC_ChallengeMmcs>
        {
            type WitnessVariable = FriCommitPhaseProofStepVariable<CC, $sc_name>;
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
        impl<CC> Witnessable<CC> for $mod_name::SC_BatchOpening
        where
            CC: CircuitConfig<
                F = $mod_name::SC_Val,
                N = Bn254Fr,
                EF = $mod_name::SC_Challenge,
                Bit = Var<Bn254Fr>,
            >,
        {
            type WitnessVariable = BatchOpeningVariable<CC, $sc_name>;
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
    };
}

impl_pcs_related_witnessable!(bb_bn254_poseidon2, BabyBearBn254Poseidon2);
impl_pcs_related_witnessable!(kb_bn254_poseidon2, KoalaBearBn254Poseidon2);
