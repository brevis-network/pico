use super::{SimpleMachineRecursionMemoryLayout, SimpleMachineRecursionMemoryLayoutVariable};
use crate::{
    compiler::recursion::{
        config::InnerConfig,
        ir::{Builder, Config},
        program_builder::{
            hints::Hintable,
            stark::{BaseProofHint, VerifyingKeyHint},
        },
    },
    configs::bb_poseidon2::{BabyBearPoseidon2, InnerPerm, InnerVal},
    machine::{
        chip::ChipBehavior,
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
    },
    recursion::air::Block,
};
use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_challenger::DuplexChallenger;
use p3_field::AbstractField;

type C = InnerConfig;

impl<'a, A> Hintable<C> for SimpleMachineRecursionMemoryLayout<'a, BabyBearPoseidon2, A>
where
    A: ChipBehavior<BabyBear>
        + for<'b> Air<ProverConstraintFolder<'b, BabyBearPoseidon2>>
        + for<'b> Air<VerifierConstraintFolder<'b, BabyBearPoseidon2>>,
{
    type HintVariable = SimpleMachineRecursionMemoryLayoutVariable<C>;

    fn read(builder: &mut Builder<C>) -> Self::HintVariable {
        let vk = VerifyingKeyHint::<'a, BabyBearPoseidon2, A>::read(builder);
        let base_proofs = Vec::<BaseProofHint<'a, BabyBearPoseidon2, A>>::read(builder);
        let leaf_challenger = DuplexChallenger::<InnerVal, InnerPerm, 16, 8>::read(builder);
        let initial_reconstruct_challenger =
            DuplexChallenger::<InnerVal, InnerPerm, 16, 8>::read(builder);
        let is_complete = builder.hint_var();

        SimpleMachineRecursionMemoryLayoutVariable {
            vk,
            base_proofs,
            leaf_challenger,
            initial_reconstruct_challenger,
            is_complete,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<C as Config>::F>>> {
        let mut stream = Vec::new();

        let vk_hint = VerifyingKeyHint::<'a, BabyBearPoseidon2, _>::new(self.machine, self.vk);

        let proof_hints = self
            .base_proofs
            .iter()
            .map(|proof| BaseProofHint::<BabyBearPoseidon2, A>::new(self.machine, proof))
            .collect::<Vec<_>>();

        stream.extend(vk_hint.write());
        stream.extend(proof_hints.write());
        stream.extend(self.leaf_challenger.write());
        stream.extend(self.initial_reconstruct_challenger.write());
        stream.extend((self.is_complete as usize).write());

        stream
    }
}
