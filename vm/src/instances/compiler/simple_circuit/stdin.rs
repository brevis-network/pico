use crate::{
    compiler::recursion::{
        prelude::*,
        program_builder::{
            hints::{hintable::Hintable, keys::VerifyingKeyHint, proof::BaseProofHint},
            keys::BaseVerifyingKeyVariable,
            p3::challenger::DuplexChallengerVariable,
            proof::BaseProofVariable,
        },
    },
    configs::config::{FieldGenericConfig, StarkGenericConfig},
    instances::{
        configs::{recur_config as rcf, riscv_config::StarkConfig as RiscvSC},
        machine::simple_machine::SimpleMachine,
    },
    machine::{
        chip::ChipBehavior,
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::BaseVerifyingKey,
        machine::MachineBehavior,
        proof::BaseProof,
    },
    recursion::air::Block,
};
use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_challenger::{CanObserve, DuplexChallenger};

pub struct SimpleRecursionStdin<'a, SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>
        + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
{
    pub vk: &'a BaseVerifyingKey<SC>,
    pub machine: &'a SimpleMachine<SC, C>,
    pub base_proofs: Vec<BaseProof<SC>>,
    pub base_challenger: &'a SC::Challenger,
    pub initial_reconstruct_challenger: SC::Challenger,
    pub flag_complete: bool,
}

#[derive(DslVariable, Clone)]
pub struct SimpleRecursionStdinVariable<RC: FieldGenericConfig> {
    pub vk: BaseVerifyingKeyVariable<RC>,
    pub base_proofs: Array<RC, BaseProofVariable<RC>>,
    pub base_challenger: DuplexChallengerVariable<RC>,
    pub initial_reconstruct_challenger: DuplexChallengerVariable<RC>,
    pub flag_complete: Var<RC::N>,
}

impl<'a, SC, C> SimpleRecursionStdin<'a, SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>
        + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
{
    pub fn construct(
        machine: &'a SimpleMachine<SC, C>,
        reconstruct_challenger: &mut SC::Challenger,
        vk: &'a BaseVerifyingKey<SC>,
        base_challenger: &'a mut SC::Challenger,
        base_proof: BaseProof<SC>,
    ) -> Self {
        let num_public_values = machine.num_public_values();

        vk.observed_by(reconstruct_challenger);
        vk.observed_by(base_challenger);

        let base_proofs = vec![base_proof.clone()];

        base_challenger.observe(base_proof.commitments.main_commit);
        base_challenger.observe_slice(&base_proof.public_values[0..num_public_values]);

        Self {
            vk,
            machine,
            base_proofs,
            base_challenger,
            initial_reconstruct_challenger: reconstruct_challenger.clone(),
            flag_complete: true,
        }
    }
}

impl<'a, A> Hintable<rcf::FieldConfig> for SimpleRecursionStdin<'a, RiscvSC, A>
where
    A: ChipBehavior<BabyBear>
        + for<'b> Air<ProverConstraintFolder<'b, RiscvSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RiscvSC>>,
{
    type HintVariable = SimpleRecursionStdinVariable<rcf::FieldConfig>;

    fn read(builder: &mut Builder<rcf::FieldConfig>) -> Self::HintVariable {
        let vk = VerifyingKeyHint::<'a, RiscvSC, A>::read(builder);
        let base_proofs = Vec::<BaseProofHint<'a, RiscvSC, A>>::read(builder);
        let base_challenger = DuplexChallenger::<rcf::Val, rcf::Perm, 16, 8>::read(builder);
        let initial_reconstruct_challenger =
            DuplexChallenger::<rcf::Val, rcf::Perm, 16, 8>::read(builder);
        let flag_complete = builder.hint_var();

        SimpleRecursionStdinVariable {
            vk,
            base_proofs,
            base_challenger,
            initial_reconstruct_challenger,
            flag_complete,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<rcf::FieldConfig as FieldGenericConfig>::F>>> {
        let mut stream = Vec::new();

        let vk_hint = VerifyingKeyHint::<'a, RiscvSC, _>::new(
            self.machine.chips(),
            self.machine.preprocessed_chip_ids(),
            self.vk,
        );

        let proof_hints = self
            .base_proofs
            .iter()
            .map(|proof| BaseProofHint::<RiscvSC, A>::new(self.machine.chips(), proof))
            .collect::<Vec<_>>();

        stream.extend(vk_hint.write());
        stream.extend(proof_hints.write());
        stream.extend(self.base_challenger.write());
        stream.extend(self.initial_reconstruct_challenger.write());
        stream.extend((self.flag_complete as usize).write());

        stream
    }
}
