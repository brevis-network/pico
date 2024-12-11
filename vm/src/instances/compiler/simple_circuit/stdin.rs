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
    configs::config::{Com, FieldGenericConfig, PcsProverData, StarkGenericConfig},
    instances::configs::{recur_config as rcf, riscv_config::StarkConfig as RiscvSC},
    machine::{
        chip::ChipBehavior,
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::BaseVerifyingKey,
        machine::BaseMachine,
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
    pub vk: BaseVerifyingKey<SC>,
    pub machine: BaseMachine<SC, C>,
    pub base_proofs: Vec<BaseProof<SC>>,
    pub base_challenger: &'a SC::Challenger,
    pub initial_reconstruct_challenger: SC::Challenger,
    pub flag_complete: bool,
}

#[derive(DslVariable, Clone)]
pub struct SimpleRecursionStdinVariable<FC: FieldGenericConfig> {
    pub vk: BaseVerifyingKeyVariable<FC>,
    pub base_proofs: Array<FC, BaseProofVariable<FC>>,
    pub base_challenger: DuplexChallengerVariable<FC>,
    pub initial_reconstruct_challenger: DuplexChallengerVariable<FC>,
    pub flag_complete: Var<FC::N>,
}

impl<'a, SC, C> SimpleRecursionStdin<'a, SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>
        + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
    Com<SC>: Send + Sync,
    PcsProverData<SC>: Send + Sync,
{
    pub fn construct(
        machine: &BaseMachine<SC, C>,
        reconstruct_challenger: &mut SC::Challenger,
        vk: &BaseVerifyingKey<SC>,
        base_challenger: &'a mut SC::Challenger,
        base_proof: BaseProof<SC>,
    ) -> Self
    where
        <SC as StarkGenericConfig>::Challenger: std::fmt::Debug,
    {
        let num_public_values = machine.num_public_values();

        vk.observed_by(reconstruct_challenger);
        vk.observed_by(base_challenger);

        let base_proofs = vec![base_proof.clone()];

        base_challenger.observe(base_proof.commitments.main_commit.clone());
        base_challenger.observe_slice(&base_proof.public_values[0..num_public_values]);

        Self {
            vk: vk.clone(),
            machine: machine.clone(),
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
        let vk = VerifyingKeyHint::<RiscvSC, A>::read(builder);
        let base_proofs = Vec::<BaseProofHint<'a, RiscvSC, A>>::read(builder);
        let base_challenger = DuplexChallenger::<rcf::SC_Val, rcf::SC_Perm, 16, 8>::read(builder);
        let initial_reconstruct_challenger =
            DuplexChallenger::<rcf::SC_Val, rcf::SC_Perm, 16, 8>::read(builder);
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

        let vk_hint = VerifyingKeyHint::<RiscvSC, _>::new(
            self.machine.chips(),
            self.machine.preprocessed_chip_ids(),
            self.vk.clone(),
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
