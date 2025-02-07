use crate::{
    compiler::recursion::{
        circuit::{
            challenger::DuplexChallengerVariable,
            config::{CircuitConfig, FieldFriConfigVariable},
            types::BaseVerifyingKeyVariable,
            witness::{WitnessWriter, Witnessable},
        },
        ir::{Builder, Felt},
    },
    configs::config::Com,
    machine::{keys::BaseVerifyingKey, septic::SepticDigest},
};
use p3_challenger::DuplexChallenger;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::{ExtensionField, PrimeField, TwoAdicField};
use p3_symmetric::CryptographicPermutation;

impl<Perm, CC> Witnessable<CC> for DuplexChallenger<CC::F, Perm, 16, 8>
where
    CC: CircuitConfig,
    CC::F: PrimeField + TwoAdicField + Witnessable<CC, WitnessVariable = Felt<CC::F>>,
    CC::EF: ExtensionField<CC::F> + TwoAdicField,
    Perm: CryptographicPermutation<[CC::F; 16]>,
{
    type WitnessVariable = DuplexChallengerVariable<CC>;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        let sponge_state = self.sponge_state.read(builder);
        let input_buffer = self.input_buffer.read(builder);
        let output_buffer = self.output_buffer.read(builder);
        DuplexChallengerVariable {
            sponge_state,
            input_buffer,
            output_buffer,
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        self.sponge_state.write(witness);
        self.input_buffer.write(witness);
        self.output_buffer.write(witness);
    }
}

impl<CC, SC> Witnessable<CC> for BaseVerifyingKey<SC>
where
    CC: CircuitConfig,
    CC::F: TwoAdicField + Witnessable<CC, WitnessVariable = Felt<CC::F>>,
    SC: FieldFriConfigVariable<CC, Val = CC::F, Domain = TwoAdicMultiplicativeCoset<CC::F>>,
    Com<SC>: Witnessable<CC, WitnessVariable = SC::DigestVariable>,
    SepticDigest<CC::F>: Witnessable<CC, WitnessVariable = SepticDigest<Felt<CC::F>>>,
{
    type WitnessVariable = BaseVerifyingKeyVariable<CC, SC>;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        let commit = self.commit.read(builder);
        let pc_start = self.pc_start.read(builder);
        let initial_global_cumulative_sum = self.initial_global_cumulative_sum.read(builder);
        let preprocessed_info = self.preprocessed_info.clone();
        let preprocessed_chip_ordering = self.preprocessed_chip_ordering.clone();
        BaseVerifyingKeyVariable {
            commit,
            pc_start,
            initial_global_cumulative_sum,
            preprocessed_info: preprocessed_info.to_vec(),
            preprocessed_chip_ordering: (*preprocessed_chip_ordering).clone(),
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        self.commit.write(witness);
        self.pc_start.write(witness);
        self.initial_global_cumulative_sum.write(witness);
    }
}
