use crate::{
    compiler::recursion_v2::{
        circuit::{
            challenger::DuplexChallengerVariable,
            config::{BabyBearFriConfigVariable, CircuitConfig},
            hash::FieldHasherVariable,
            stark::BaseProofVariable,
            types,
            types::BaseVerifyingKeyVariable,
            witness::{witnessable::Witnessable, WitnessWriter},
        },
        prelude::*,
    },
    configs::{
        config::{Com, FieldGenericConfig, PcsProof, StarkGenericConfig},
        stark_config::bb_poseidon2::{BabyBearPoseidon2, SC_Challenge, SC_Val},
    },
    instances::{
        compiler_v2::witness,
        configs::{recur_config as rcf, riscv_config::StarkConfig as RiscvSC},
    },
    machine::{
        chip::ChipBehavior,
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::BaseVerifyingKey,
        machine::BaseMachine,
        proof::BaseProof,
    },
    recursion_v2::air::Block,
};
use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_challenger::{CanObserve, DuplexChallenger};
use p3_field::FieldAlgebra;

pub struct SimpleRecursionStdin<'a, SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>
        + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
{
    pub vk: &'a BaseVerifyingKey<SC>,
    pub machine: &'a BaseMachine<SC, C>,
    pub base_proofs: Vec<BaseProof<SC>>,
    pub base_challenger: SC::Challenger,
    pub initial_reconstruct_challenger: SC::Challenger,
    pub flag_complete: bool,
    pub flag_first_chunk: bool,
    // todo: vk_root
}

pub struct SimpleRecursionStdinVariable<
    CC: CircuitConfig<F = BabyBear>,
    SC: BabyBearFriConfigVariable<CC>,
> {
    pub vk: BaseVerifyingKeyVariable<CC, SC>,
    pub base_proofs: Vec<BaseProofVariable<CC, SC>>,
    pub base_challenger: SC::FriChallengerVariable,
    pub initial_reconstruct_challenger: DuplexChallengerVariable<CC>,
    pub flag_complete: Felt<CC::F>,
    pub flag_first_chunk: Felt<CC::F>,
}

impl<'a, SC, C> SimpleRecursionStdin<'a, SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>
        + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
{
    pub fn construct(
        machine: &'a BaseMachine<SC, C>,
        reconstruct_challenger: &mut SC::Challenger,
        vk: &'a BaseVerifyingKey<SC>,
        base_challenger: &'a mut SC::Challenger,
        base_proof: BaseProof<SC>,
    ) -> Self {
        let num_public_values = machine.num_public_values();

        vk.observed_by(reconstruct_challenger);
        vk.observed_by(base_challenger);

        let base_proofs = vec![base_proof.clone()];

        base_challenger.observe(base_proof.commitments.global_main_commit);
        base_challenger.observe_slice(&base_proof.public_values[0..num_public_values]);

        Self {
            vk,
            machine,
            base_proofs,
            base_challenger: base_challenger.clone(),
            initial_reconstruct_challenger: reconstruct_challenger.clone(),
            flag_complete: true,
            flag_first_chunk: true,
        }
    }
}

impl<'a, CC, C> Witnessable<CC> for SimpleRecursionStdin<'a, BabyBearPoseidon2, C>
where
    CC: CircuitConfig<F = SC_Val, EF = SC_Challenge, Bit = Felt<BabyBear>>,
    C: ChipBehavior<BabyBear>
        + for<'b> Air<ProverConstraintFolder<'b, BabyBearPoseidon2>>
        + for<'b> Air<VerifierConstraintFolder<'b, BabyBearPoseidon2>>,
{
    type WitnessVariable = SimpleRecursionStdinVariable<CC, BabyBearPoseidon2>;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        let vk = self.vk.read(builder);
        let base_proofs = self.base_proofs.read(builder);
        let base_challenger = self.base_challenger.read(builder);
        let initial_reconstruct_challenger = self.initial_reconstruct_challenger.read(builder);
        let flag_complete = SC_Val::from_bool(self.flag_complete).read(builder);
        let flag_first_chunk = SC_Val::from_bool(self.flag_first_chunk).read(builder);

        SimpleRecursionStdinVariable {
            vk,
            base_proofs,
            base_challenger,
            initial_reconstruct_challenger,
            flag_complete,
            flag_first_chunk,
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        self.vk.write(witness);
        self.base_proofs.write(witness);
        self.base_challenger.write(witness);
        self.initial_reconstruct_challenger.write(witness);
        self.flag_complete.write(witness);
        self.flag_first_chunk.write(witness);
    }
}
