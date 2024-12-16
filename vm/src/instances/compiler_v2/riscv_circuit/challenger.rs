use crate::{
    configs::config::{StarkGenericConfig, Val},
    machine::{
        chip::ChipBehavior,
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::BaseVerifyingKey,
        machine::BaseMachine,
        proof::BaseProof,
    },
};
use p3_air::Air;
use p3_challenger::CanObserve;
use std::array;

#[derive(Clone, Debug)]
pub struct RiscvRecursionChallengers<SC: StarkGenericConfig> {
    pub base_challenger: SC::Challenger,
    pub reconstruct_challenger: SC::Challenger,
}

impl<SC: StarkGenericConfig> RiscvRecursionChallengers<SC> {
    pub fn new<C>(
        machine: &BaseMachine<SC, C>,
        vk: &BaseVerifyingKey<SC>,
        all_proofs: &[BaseProof<SC>],
    ) -> Self
    where
        C: ChipBehavior<Val<SC>>
            + for<'b> Air<ProverConstraintFolder<'b, SC>>
            + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
    {
        let [mut base_challenger, mut reconstruct_challenger] =
            array::from_fn(|_| machine.config().challenger());

        // TRICKY: We must initialize the base challenger as the phase-1 step of RiscV proving
        // process, since the RiscV compression program is build as static, it must know the exact
        // the inputs of base challenger (Vec length in challenger).
        vk.observed_by(&mut reconstruct_challenger);
        vk.observed_by(&mut base_challenger);
        let num_public_values = machine.num_public_values();
        all_proofs.iter().for_each(|p| {
            base_challenger.observe(p.clone().commitments.global_main_commit);
            base_challenger.observe_slice(&p.public_values[0..num_public_values]);
        });

        Self {
            base_challenger,
            reconstruct_challenger,
        }
    }
}
