use crate::{
    compiler::recursion::{
        config::InnerConfig,
        ir::{Array, Builder, Config, Var},
        program_builder::{
            hints::{hintable::Hintable, keys::VerifyingKeyHint, proof::BaseProofHint},
            keys::BaseVerifyingKeyVariable,
            proof::BaseProofVariable,
        },
    },
    configs::{
        bb_poseidon2::{BabyBearPoseidon2, InnerPerm, InnerVal},
        config::StarkGenericConfig,
    },
    instances::machine::simple_machine::SimpleMachine,
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
use p3_challenger::DuplexChallenger;

use crate::compiler::recursion::{
    prelude::{DslVariable, *},
    program_builder::p3::challenger::DuplexChallengerVariable,
};

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
    pub leaf_challenger: &'a SC::Challenger,
    pub initial_reconstruct_challenger: SC::Challenger,
    pub is_complete: bool,
}

#[derive(DslVariable, Clone)]
pub struct SimpleRecursionStdinVariable<CF: Config> {
    pub vk: BaseVerifyingKeyVariable<CF>,
    pub base_proofs: Array<CF, BaseProofVariable<CF>>,
    pub leaf_challenger: DuplexChallengerVariable<CF>,
    pub initial_reconstruct_challenger: DuplexChallengerVariable<CF>,
    pub is_complete: Var<CF::N>,
}

impl<'a, A> Hintable<InnerConfig> for SimpleRecursionStdin<'a, BabyBearPoseidon2, A>
where
    A: ChipBehavior<BabyBear>
        + for<'b> Air<ProverConstraintFolder<'b, BabyBearPoseidon2>>
        + for<'b> Air<VerifierConstraintFolder<'b, BabyBearPoseidon2>>,
{
    type HintVariable = SimpleRecursionStdinVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let vk = VerifyingKeyHint::<'a, BabyBearPoseidon2, A>::read(builder);
        let base_proofs = Vec::<BaseProofHint<'a, BabyBearPoseidon2, A>>::read(builder);
        let leaf_challenger = DuplexChallenger::<InnerVal, InnerPerm, 16, 8>::read(builder);
        let initial_reconstruct_challenger =
            DuplexChallenger::<InnerVal, InnerPerm, 16, 8>::read(builder);
        let is_complete = builder.hint_var();

        SimpleRecursionStdinVariable {
            vk,
            base_proofs,
            leaf_challenger,
            initial_reconstruct_challenger,
            is_complete,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<InnerConfig as Config>::F>>> {
        let mut stream = Vec::new();

        let vk_hint = VerifyingKeyHint::<'a, BabyBearPoseidon2, _>::new(
            self.machine.chips(),
            self.machine.preprocessed_chip_ids(),
            self.vk,
        );

        let proof_hints = self
            .base_proofs
            .iter()
            .map(|proof| BaseProofHint::<BabyBearPoseidon2, A>::new(self.machine.chips(), proof))
            .collect::<Vec<_>>();

        stream.extend(vk_hint.write());
        stream.extend(proof_hints.write());
        stream.extend(self.leaf_challenger.write());
        stream.extend(self.initial_reconstruct_challenger.write());
        stream.extend((self.is_complete as usize).write());

        stream
    }
}
