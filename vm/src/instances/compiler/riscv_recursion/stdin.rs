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
    configs::config::{RecursionGenericConfig, StarkGenericConfig},
    emulator::riscv::record::EmulationRecord,
    instances::{
        configs::{recur_config as rcf, riscv_config::StarkConfig as RiscvSC},
        machine::riscv_machine::RiscvMachine,
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
use pico_derive::DslVariable;

pub struct RiscvRecursionStdin<'a, SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<SC::Val>
        + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
{
    pub vk: &'a BaseVerifyingKey<SC>,
    pub machine: &'a RiscvMachine<SC, C>,
    pub proofs: Vec<BaseProof<SC>>,
    pub base_challenger: &'a SC::Challenger,
    pub reconstruct_challenger: SC::Challenger,
    pub flag_complete: bool,
}

#[derive(DslVariable, Clone)]
pub struct RiscvRecursionStdinVariable<RC: RecursionGenericConfig> {
    pub vk: BaseVerifyingKeyVariable<RC>,
    pub proofs: Array<RC, BaseProofVariable<RC>>,
    pub base_challenger: DuplexChallengerVariable<RC>,
    pub reconstruct_challenger: DuplexChallengerVariable<RC>,
    pub flag_complete: Var<RC::N>,
}

impl<'a, C> RiscvRecursionStdin<'a, RiscvSC, C>
where
    C: ChipBehavior<BabyBear, Program = Program, Record = EmulationRecord>
        + for<'b> Air<ProverConstraintFolder<'b, RiscvSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RiscvSC>>,
{
    /// Construct the recursion stdin.
    /// base_challenger is assumed to be a fresh new one (has not observed anything)
    pub fn construct(
        vk: &'a BaseVerifyingKey<RiscvSC>,
        machine: &'a RiscvMachine<RiscvSC, C>,
        proofs: &[BaseProof<RiscvSC>],
        base_challenger: &'a mut <RiscvSC as StarkGenericConfig>::Challenger,
        batch_size: usize,
    ) -> Vec<Self> {
        let num_public_values = machine.num_public_values();

        let mut stdin = Vec::new();

        // phase 1 for base_challenger
        vk.observed_by(base_challenger);
        for each_proof in proofs.iter() {
            base_challenger.observe(each_proof.clone().commitments.main_commit);
            base_challenger.observe_slice(&each_proof.public_values[0..num_public_values]);
        }

        // base_challenger is ready for use in phase 2
        // reconstruct challenger is initialized here
        let mut reconstruct_challenger = machine.config().challenger();
        vk.observed_by(&mut reconstruct_challenger);

        let proof_batches = proofs.chunks(batch_size);
        let total = proof_batches.len();

        for (i, batch_proofs) in proof_batches.enumerate() {
            let batch_proofs = batch_proofs.to_vec();
            let flag_complete = i == total - 1;
            stdin.push(RiscvRecursionStdin {
                vk,
                machine,
                proofs: batch_proofs.clone(),
                base_challenger,
                reconstruct_challenger: reconstruct_challenger.clone(),
                flag_complete,
            });

            for each_proof in batch_proofs.iter() {
                // todo: check efficiency
                reconstruct_challenger.observe(each_proof.clone().commitments.main_commit);
                reconstruct_challenger
                    .observe_slice(&each_proof.public_values[0..num_public_values]);
            }
        }

        stdin
    }
}

impl<'a, C> Hintable<rcf::RecursionConfig> for RiscvRecursionStdin<'a, RiscvSC, C>
where
    C: ChipBehavior<BabyBear, Program = Program, Record = EmulationRecord>
        + for<'b> Air<ProverConstraintFolder<'b, RiscvSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RiscvSC>>,
{
    type HintVariable = RiscvRecursionStdinVariable<rcf::RecursionConfig>;

    fn read(builder: &mut Builder<rcf::RecursionConfig>) -> Self::HintVariable {
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

    fn write(&self) -> Vec<Vec<Block<<rcf::RecursionConfig as RecursionGenericConfig>::F>>> {
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
