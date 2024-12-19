use crate::{
    compiler::recursion_v2::{
        circuit::{
            challenger::DuplexChallengerVariable,
            config::{BabyBearFriConfigVariable, CircuitConfig},
            hash::FieldHasherVariable,
            types::BaseVerifyingKeyVariable,
            witness::{WitnessWriter, Witnessable},
        },
        ir::{Builder, Felt, Var},
    },
    configs::{
        config::{Com, PcsProof},
        stark_config::{
            bb_bn254_poseidon2::BbBn254Poseidon2,
            bb_poseidon2::{BabyBearPoseidon2, SC_Challenge, SC_Perm, SC_Val},
        },
    },
    instances::configs::recur_config as rcf,
    machine::keys::BaseVerifyingKey,
};
use p3_baby_bear::BabyBear;
use p3_bn254_fr::Bn254Fr;
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

impl<CC: CircuitConfig<F = SC_Val, EF = SC_Challenge, Bit = Felt<BabyBear>>> Witnessable<CC>
    for BaseVerifyingKey<BabyBearPoseidon2>
{
    type WitnessVariable = BaseVerifyingKeyVariable<CC, BabyBearPoseidon2>;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        let commit = self.commit.read(builder);
        let pc_start = self.pc_start.read(builder);
        let preprocessed_info = self.preprocessed_info.clone();
        let preprocessed_chip_ordering = self.preprocessed_chip_ordering.clone();
        BaseVerifyingKeyVariable {
            commit,
            pc_start,
            preprocessed_info: preprocessed_info.to_vec(),
            preprocessed_chip_ordering: (*preprocessed_chip_ordering).clone(),
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        self.commit.write(witness);
        self.pc_start.write(witness);
    }
}

// TODO, while using same SC_Challenge with bb_poseidon2, but still should use bn254_poseidon2 SC_Challenge.
// As they are same( BinomialExtensionField<SC_Val, 4>;), it work now.
impl<CC: CircuitConfig<F = SC_Val, N = Bn254Fr, EF = SC_Challenge, Bit = Var<Bn254Fr>>>
    Witnessable<CC> for BaseVerifyingKey<BbBn254Poseidon2>
{
    type WitnessVariable = BaseVerifyingKeyVariable<CC, BbBn254Poseidon2>;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        let commit = self.commit.read(builder);
        let pc_start = self.pc_start.read(builder);
        let preprocessed_info = self.preprocessed_info.clone();
        let preprocessed_chip_ordering = self.preprocessed_chip_ordering.clone();
        BaseVerifyingKeyVariable {
            commit,
            pc_start,
            preprocessed_info: preprocessed_info.to_vec(),
            preprocessed_chip_ordering: (*preprocessed_chip_ordering).clone(),
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        self.commit.write(witness);
        self.pc_start.write(witness);
    }
}
