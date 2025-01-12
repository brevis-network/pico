use crate::{
    compiler::recursion_v2::{
        circuit::{
            challenger::DuplexChallengerVariable,
            config::{BabyBearFriConfigVariable, CircuitConfig},
            hash::FieldHasherVariable,
            types::{BaseVerifyingKeyVariable, FriProofVariable},
            witness::{WitnessWriter, Witnessable},
        },
        ir::Builder,
    },
    configs::{
        config::{Com, PcsProof},
        stark_config::bb_poseidon2::{SC_Challenge, SC_Perm, SC_Val},
    },
    machine::keys::BaseVerifyingKey,
};
use p3_challenger::DuplexChallenger;

impl<CC> Witnessable<CC> for DuplexChallenger<SC_Val, SC_Perm, 16, 8>
where
    CC: CircuitConfig<F = SC_Val, EF = SC_Challenge>,
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

impl<CC: CircuitConfig<F = SC_Val, EF = SC_Challenge>, SC: BabyBearFriConfigVariable<CC>>
    Witnessable<CC> for BaseVerifyingKey<SC>
where
    Com<SC>: Witnessable<CC, WitnessVariable = <SC as FieldHasherVariable<CC>>::DigestVariable>,
    PcsProof<SC>: Witnessable<CC, WitnessVariable = FriProofVariable<CC, SC>>,
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
