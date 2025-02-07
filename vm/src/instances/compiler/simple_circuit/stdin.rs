use crate::{
    compiler::recursion::{
        circuit::{
            config::{CircuitConfig, FieldFriConfigVariable},
            stark::BaseProofVariable,
            types::{BaseVerifyingKeyVariable, FriProofVariable},
            witness::{witnessable::Witnessable, WitnessWriter},
        },
        prelude::*,
    },
    configs::config::{Challenger, Com, PcsProof, StarkGenericConfig},
    machine::{chip::ChipBehavior, keys::BaseVerifyingKey, machine::BaseMachine, proof::BaseProof},
};
use p3_challenger::CanObserve;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::{FieldAlgebra, TwoAdicField};

pub struct SimpleRecursionStdin<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>,
{
    pub vk: BaseVerifyingKey<SC>,
    pub machine: BaseMachine<SC, C>,
    pub base_proofs: Vec<BaseProof<SC>>,
    pub flag_complete: bool,
    pub flag_first_chunk: bool,
    // todo: vk_root
}

pub struct SimpleRecursionStdinVariable<CC, SC>
where
    CC: CircuitConfig,
    CC::F: TwoAdicField,
    SC: FieldFriConfigVariable<CC, Val = CC::F, Domain = TwoAdicMultiplicativeCoset<CC::F>>,
{
    pub vk: BaseVerifyingKeyVariable<CC, SC>,
    pub base_proofs: Vec<BaseProofVariable<CC, SC>>,
    pub flag_complete: Felt<CC::F>,
    pub flag_first_chunk: Felt<CC::F>,
}

impl<SC, C> SimpleRecursionStdin<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>,
{
    pub fn construct(
        machine: &BaseMachine<SC, C>,
        vk: &BaseVerifyingKey<SC>,
        base_challenger: &mut SC::Challenger,
        base_proof: BaseProof<SC>,
    ) -> Self {
        let num_public_values = machine.num_public_values();

        let base_proofs = vec![base_proof.clone()];

        base_challenger.observe(base_proof.commitments.main_commit);
        base_challenger.observe_slice(&base_proof.public_values[0..num_public_values]);

        Self {
            vk: vk.clone(),
            machine: machine.clone(),
            base_proofs,
            flag_complete: true,
            flag_first_chunk: true,
        }
    }
}

impl<CC, SC, C> Witnessable<CC> for SimpleRecursionStdin<SC, C>
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
    Challenger<SC>: Witnessable<CC, WitnessVariable = SC::FriChallengerVariable>,
    Com<SC>: Witnessable<CC, WitnessVariable = SC::DigestVariable>,
    PcsProof<SC>: Witnessable<CC, WitnessVariable = FriProofVariable<CC, SC>>,
    C: ChipBehavior<CC::F>,
{
    type WitnessVariable = SimpleRecursionStdinVariable<CC, SC>;

    fn read(&self, builder: &mut Builder<CC>) -> Self::WitnessVariable {
        let vk = self.vk.read(builder);
        let base_proofs = self.base_proofs.read(builder);
        let flag_complete = CC::F::from_bool(self.flag_complete).read(builder);
        let flag_first_chunk = CC::F::from_bool(self.flag_first_chunk).read(builder);

        SimpleRecursionStdinVariable {
            vk,
            base_proofs,
            flag_complete,
            flag_first_chunk,
        }
    }

    fn write(&self, witness: &mut impl WitnessWriter<CC>) {
        self.vk.write(witness);
        self.base_proofs.write(witness);
        self.flag_complete.write(witness);
        self.flag_first_chunk.write(witness);
    }
}
