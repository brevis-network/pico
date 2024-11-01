use crate::{
    compiler::recursion::{
        ir::{Array, Builder, Var},
        prelude::*,
        program::RecursionProgram,
        program_builder::{
            hints::{hintable::Hintable, keys::VerifyingKeyHint, proof::BaseProofHint},
            keys::BaseVerifyingKeyVariable,
            proof::BaseProofVariable,
        },
    },
    configs::config::{FieldGenericConfig, StarkGenericConfig, Val},
    instances::configs::{
        recur_config::{FieldConfig as RecursionFC, StarkConfig as RecursionSC},
        riscv_config::StarkConfig as RiscvSC,
    },
    machine::{
        chip::ChipBehavior,
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::BaseVerifyingKey,
        machine::{BaseMachine, MachineBehavior},
        proof::BaseProof,
    },
    recursion::{air::Block, runtime::RecursionRecord},
};
use p3_air::Air;
use pico_derive::DslVariable;

#[derive(Clone)]
pub struct RecursionStdin<'a, SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>
        + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
{
    pub vk: &'a BaseVerifyingKey<SC>,
    pub machine: &'a BaseMachine<SC, C>,
    pub proofs: Vec<BaseProof<SC>>,
    pub flag_complete: bool,
}

#[derive(DslVariable, Clone)]
pub struct RecursionStdinVariable<FC: FieldGenericConfig> {
    pub vk: BaseVerifyingKeyVariable<FC>,
    pub proofs: Array<FC, BaseProofVariable<FC>>,
    pub flag_complete: Var<FC::N>,
}

impl<'a, C> Hintable<RecursionFC> for RecursionStdin<'a, RecursionSC, C>
where
    C: ChipBehavior<
            Val<RecursionSC>,
            Program = RecursionProgram<Val<RecursionSC>>,
            Record = RecursionRecord<Val<RecursionSC>>,
        > + for<'b> Air<ProverConstraintFolder<'b, RecursionSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RecursionSC>>,
{
    type HintVariable = RecursionStdinVariable<RecursionFC>;

    fn read(builder: &mut Builder<RecursionFC>) -> Self::HintVariable {
        let vk = VerifyingKeyHint::<'a, RecursionSC, C>::read(builder);
        let proofs = Vec::<BaseProofHint<'a, RecursionSC, C>>::read(builder);
        let flag_complete = builder.hint_var();

        RecursionStdinVariable {
            vk,
            proofs,
            flag_complete,
        }
    }

    fn write(&self) -> Vec<Vec<Block<<RecursionFC as FieldGenericConfig>::F>>> {
        let mut stream = Vec::new();

        let vk_hint = VerifyingKeyHint::<'a, RecursionSC, _>::new(
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
        stream.extend((self.flag_complete as usize).write());

        stream
    }
}
