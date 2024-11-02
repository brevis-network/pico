use crate::{
    compiler::{
        recursion::{
            prelude::*,
            program_builder::{
                hints::{hintable::Hintable, keys::VerifyingKeyHint, proof::BaseProofHint},
                keys::BaseVerifyingKeyVariable,
                p3::challenger::DuplexChallengerVariable,
                proof::BaseProofVariable,
            },
        },
        riscv::program::Program,
    },
    configs::config::{FieldGenericConfig, StarkGenericConfig, Val},
    emulator::riscv::record::EmulationRecord,
    instances::configs::{
        recur_config as rcf, recur_config::FieldConfig as RecursionFC,
        riscv_config::StarkConfig as RiscvSC,
    },
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
use p3_challenger::DuplexChallenger;
use pico_derive::DslVariable;

#[derive(Clone)]
pub struct RiscvRecursionStdin<'a, SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>
        + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
{
    pub vk: &'a BaseVerifyingKey<SC>,
    pub machine: &'a BaseMachine<SC, C>,
    pub proofs: Vec<BaseProof<SC>>,
    pub base_challenger: &'a SC::Challenger,
    pub reconstruct_challenger: SC::Challenger,
    pub flag_complete: bool,
}

#[derive(DslVariable, Clone)]
pub struct RiscvRecursionStdinVariable<FC: FieldGenericConfig> {
    pub vk: BaseVerifyingKeyVariable<FC>,
    pub proofs: Array<FC, BaseProofVariable<FC>>,
    pub base_challenger: DuplexChallengerVariable<FC>,
    pub reconstruct_challenger: DuplexChallengerVariable<FC>,
    pub flag_complete: Var<FC::N>,
}

impl<'a, C> Hintable<RecursionFC> for RiscvRecursionStdin<'a, RiscvSC, C>
where
    C: ChipBehavior<BabyBear, Program = Program, Record = EmulationRecord>
        + for<'b> Air<ProverConstraintFolder<'b, RiscvSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RiscvSC>>,
{
    type HintVariable = RiscvRecursionStdinVariable<RecursionFC>;

    fn read(builder: &mut Builder<RecursionFC>) -> Self::HintVariable {
        let vk = VerifyingKeyHint::<'a, RiscvSC, C>::read(builder);
        let proofs = Vec::<BaseProofHint<'a, RiscvSC, C>>::read(builder);
        let base_challenger = DuplexChallenger::<rcf::Val, rcf::Perm, 16, 8>::read(builder);
        let reconstruct_challenger = DuplexChallenger::<rcf::Val, rcf::Perm, 16, 8>::read(builder);
        let flag_complete = builder.hint_var();

        RiscvRecursionStdinVariable {
            vk,
            proofs,
            base_challenger,
            reconstruct_challenger,
            flag_complete,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<RecursionFC as FieldGenericConfig>::F>>> {
        let mut stream = Vec::new();

        let vk_hint = VerifyingKeyHint::<'a, RiscvSC, _>::new(
            self.machine.chips(),
            self.machine.preprocessed_chip_ids(),
            self.vk,
        );

        let proof_hints = self
            .proofs
            .iter()
            .map(|proof| BaseProofHint::<RiscvSC, C>::new(self.machine.chips(), proof))
            .collect::<Vec<_>>();

        stream.extend(vk_hint.write());
        stream.extend(proof_hints.write());
        stream.extend(self.base_challenger.write());
        stream.extend(self.reconstruct_challenger.write());
        stream.extend((self.flag_complete as usize).write());

        stream
    }
}
