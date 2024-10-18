use crate::{
    compiler::{
        recursion::{
            config::InnerConfig,
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
    configs::{
        bb_poseidon2::{BabyBearPoseidon2, InnerPerm, InnerVal},
        config::StarkGenericConfig,
    },
    emulator::riscv::record::EmulationRecord,
    instances::machine::riscv_machine::RiscvMachine,
    machine::{
        chip::{ChipBehavior, MetaChip},
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::{BaseProvingKey, BaseVerifyingKey},
        machine::{BaseMachine, MachineBehavior},
        proof::{BaseProof, EnsembleProof, MetaProof},
        witness::ProvingWitness,
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
pub struct RiscvRecursionStdinVariable<CF: Config> {
    pub vk: BaseVerifyingKeyVariable<CF>,
    pub proofs: Array<CF, BaseProofVariable<CF>>,
    pub base_challenger: DuplexChallengerVariable<CF>,
    pub reconstruct_challenger: DuplexChallengerVariable<CF>,
    pub flag_complete: Var<CF::N>,
}

impl<'a, C> RiscvRecursionStdin<'a, BabyBearPoseidon2, C>
where
    C: ChipBehavior<BabyBear, Program = Program, Record = EmulationRecord>
        + for<'b> Air<ProverConstraintFolder<'b, BabyBearPoseidon2>>
        + for<'b> Air<VerifierConstraintFolder<'b, BabyBearPoseidon2>>,
{
    /// Construct the recursion stdin.
    /// base_challenger is assumed to be a fresh new one (has not observed anything)
    pub fn construct(
        vk: &'a BaseVerifyingKey<BabyBearPoseidon2>,
        machine: &'a RiscvMachine<BabyBearPoseidon2, C>,
        proofs: &[BaseProof<BabyBearPoseidon2>],
        base_challenger: &'a mut <BabyBearPoseidon2 as StarkGenericConfig>::Challenger,
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

impl<'a, C> Hintable<InnerConfig> for RiscvRecursionStdin<'a, BabyBearPoseidon2, C>
where
    C: ChipBehavior<BabyBear, Program = Program, Record = EmulationRecord>
        + for<'b> Air<ProverConstraintFolder<'b, BabyBearPoseidon2>>
        + for<'b> Air<VerifierConstraintFolder<'b, BabyBearPoseidon2>>,
{
    type HintVariable = RiscvRecursionStdinVariable<InnerConfig>;

    fn read(builder: &mut Builder<InnerConfig>) -> Self::HintVariable {
        let vk = VerifyingKeyHint::<'a, BabyBearPoseidon2, C>::read(builder);
        let proofs = Vec::<BaseProofHint<'a, BabyBearPoseidon2, C>>::read(builder);
        let base_challenger = DuplexChallenger::<InnerVal, InnerPerm, 16, 8>::read(builder);
        let reconstruct_challenger = DuplexChallenger::<InnerVal, InnerPerm, 16, 8>::read(builder);
        let flag_complete = builder.hint_var();

        RiscvRecursionStdinVariable {
            vk,
            proofs,
            base_challenger,
            reconstruct_challenger,
            flag_complete,
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
            .proofs
            .iter()
            .map(|proof| BaseProofHint::<BabyBearPoseidon2, C>::new(self.machine.chips(), proof))
            .collect::<Vec<_>>();

        stream.extend(vk_hint.write());
        stream.extend(proof_hints.write());
        stream.extend(self.base_challenger.write());
        stream.extend(self.reconstruct_challenger.write());
        stream.extend((self.flag_complete as usize).write());

        stream
    }
}
