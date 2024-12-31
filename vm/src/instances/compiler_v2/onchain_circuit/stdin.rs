use crate::{
    compiler::recursion_v2::{
        circuit::{
            config::{BabyBearFriConfigVariable, CircuitConfig},
            stark::BaseProofVariable,
            types::BaseVerifyingKeyVariable,
            witness::{WitnessWriter, Witnessable},
        },
        ir::{Builder, Felt},
    },
    configs::config::{StarkGenericConfig, Val},
    instances::configs::embed_config::{FieldConfig as EmbedFC, StarkConfig as EmbedSC},
    machine::{
        chip::ChipBehavior,
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::BaseVerifyingKey,
        machine::BaseMachine,
        proof::BaseProof,
    },
};
use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_field::FieldAlgebra;

pub struct OnchainStdin<'a, SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>
        + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
{
    pub machine: &'a BaseMachine<SC, C>,
    pub vk: BaseVerifyingKey<SC>,
    pub proof: BaseProof<SC>,
    pub flag_complete: bool,
}

pub struct OnchainStdinVariable<CC: CircuitConfig<F = BabyBear>, SC: BabyBearFriConfigVariable<CC>>
{
    pub vk: BaseVerifyingKeyVariable<CC, SC>,
    pub proof: BaseProofVariable<CC, SC>,
    pub flag_complete: Felt<CC::F>,
}

impl<C> Witnessable<EmbedFC> for OnchainStdin<'_, EmbedSC, C>
where
    C: ChipBehavior<BabyBear>
        + for<'b> Air<ProverConstraintFolder<'b, EmbedSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, EmbedSC>>,
{
    type WitnessVariable = OnchainStdinVariable<EmbedFC, EmbedSC>;
    fn read(&self, builder: &mut Builder<EmbedFC>) -> Self::WitnessVariable {
        let vk = self.vk.read(builder);
        let proof = self.proof.read(builder);
        let flag_complete = BabyBear::from_bool(self.flag_complete).read(builder);
        OnchainStdinVariable {
            vk,
            proof,
            flag_complete,
        }
    }
    fn write(&self, witness: &mut impl WitnessWriter<EmbedFC>) {
        self.vk.write(witness);
        self.proof.write(witness);
        BabyBear::from_bool(self.flag_complete).write(witness);
    }
}
