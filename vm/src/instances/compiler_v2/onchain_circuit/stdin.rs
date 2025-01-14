use crate::{
    compiler::recursion_v2::{
        circuit::{
            config::{CircuitConfig, FieldFriConfigVariable},
            stark::BaseProofVariable,
            types::{BaseVerifyingKeyVariable, FriProofVariable},
            witness::{WitnessWriter, Witnessable},
        },
        ir::{Builder, Ext, Felt},
    },
    configs::config::{Com, PcsProof, StarkGenericConfig, Val},
    machine::{chip::ChipBehavior, keys::BaseVerifyingKey, machine::BaseMachine, proof::BaseProof},
};
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::{FieldAlgebra, TwoAdicField};

pub struct OnchainStdin<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>,
{
    pub machine: BaseMachine<SC, C>,
    pub vk: BaseVerifyingKey<SC>,
    pub proof: BaseProof<SC>,
    pub flag_complete: bool,
}

pub struct OnchainStdinVariable<CC, SC>
where
    CC: CircuitConfig,
    CC::F: TwoAdicField,
    SC: FieldFriConfigVariable<CC, Val = CC::F, Domain = TwoAdicMultiplicativeCoset<CC::F>>,
{
    pub vk: BaseVerifyingKeyVariable<CC, SC>,
    pub proof: BaseProofVariable<CC, SC>,
    pub flag_complete: Felt<CC::F>,
}

impl<CC, SC, C> Witnessable<CC> for OnchainStdin<SC, C>
where
    CC: CircuitConfig,
    CC::F: TwoAdicField + Witnessable<CC, WitnessVariable = Felt<CC::F>>,
    CC::EF: Witnessable<CC, WitnessVariable = Ext<CC::F, CC::EF>>,
    SC: FieldFriConfigVariable<
        CC,
        Val = CC::F,
        Challenge = CC::EF,
        Domain = TwoAdicMultiplicativeCoset<CC::F>,
    >,
    Com<SC>: Witnessable<CC, WitnessVariable = SC::DigestVariable>,
    PcsProof<SC>: Witnessable<CC, WitnessVariable = FriProofVariable<CC, SC>>,
    C: ChipBehavior<Val<SC>>,
{
    type WitnessVariable = OnchainStdinVariable<CC, SC>;
    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        let vk = self.vk.read(builder);
        let proof = self.proof.read(builder);
        let flag_complete = Val::<SC>::from_bool(self.flag_complete).read(builder);
        OnchainStdinVariable {
            vk,
            proof,
            flag_complete,
        }
    }
    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        self.vk.write(witness);
        self.proof.write(witness);
        Val::<SC>::from_bool(self.flag_complete).write(witness);
    }
}
