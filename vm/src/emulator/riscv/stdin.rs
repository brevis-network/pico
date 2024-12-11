use crate::{
    compiler::{recursion::program::RecursionProgram, riscv::program::Program},
    configs::config::{Challenger, StarkGenericConfig, Val},
    emulator::riscv::record::EmulationRecord,
    instances::{
        compiler::{
            recursion_circuit::stdin::RecursionStdin, riscv_circuit::stdin::RiscvRecursionStdin,
        },
        configs::{recur_config::StarkConfig as RecursionSC, riscv_config::StarkConfig as RiscvSC},
    },
    machine::{
        chip::ChipBehavior,
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::BaseVerifyingKey,
        machine::BaseMachine,
        proof::BaseProof,
    },
    recursion::runtime::RecursionRecord,
};
use alloc::sync::Arc;
use p3_air::Air;
use p3_challenger::CanObserve;
use serde::Serialize;

#[derive(Clone, Default, Serialize)]
pub struct EmulatorStdinBuilder<I> {
    pub buffer: Vec<I>,
}

#[derive(Default, Serialize)]
pub struct EmulatorStdin<I> {
    pub buffer: Arc<[I]>,
    pub cursor: usize,
}

impl<I> Clone for EmulatorStdin<I> {
    fn clone(&self) -> Self {
        Self {
            buffer: self.buffer.clone(),
            cursor: self.cursor,
        }
    }
}

#[allow(clippy::should_implement_trait)]
impl<I> EmulatorStdin<I> {
    //pub fn next(&mut self) -> (&mut I, bool) {
    //    let flag_last = self.cursor == self.buffer.len() - 1;
    //    if self.cursor < self.buffer.len() {
    //        let cursor = self.cursor;
    //        self.cursor += 1;
    //        (&mut self.buffer[cursor], flag_last)
    //    } else {
    //        panic!("EmulatorStdin: out of bounds");
    //    }
    //}

    pub fn get(&self, index: usize) -> (&I, bool) {
        let flag_last = index == self.buffer.len() - 1;
        if index < self.buffer.len() {
            (&self.buffer[index], flag_last)
        } else {
            panic!("EmulatorStdin: out of bounds");
        }
    }

    pub fn new_builder() -> EmulatorStdinBuilder<I>
    where
        I: Default,
    {
        EmulatorStdinBuilder::default()
    }
}

// for riscv machine stdin
impl EmulatorStdinBuilder<Vec<u8>> {
    pub fn write<T: Serialize>(&mut self, data: &T) {
        let mut tmp = Vec::new();
        bincode::serialize_into(&mut tmp, data).expect("serialization failed");
        self.buffer.push(tmp);
    }

    pub fn finalize(self) -> EmulatorStdin<Vec<u8>> {
        EmulatorStdin {
            buffer: self.buffer.into(),
            cursor: 0,
        }
    }
}

// for riscv recursion stdin, both compress and combine
impl<C> EmulatorStdin<RiscvRecursionStdin<RiscvSC, C>>
where
    C: ChipBehavior<Val<RiscvSC>, Program = Program, Record = EmulationRecord>
        + for<'a> Air<ProverConstraintFolder<'a, RiscvSC>>
        + for<'a> Air<VerifierConstraintFolder<'a, RiscvSC>>,
{
    /// Construct the recursion stdin for riscv_compress.
    /// base_challenger is assumed to be a fresh new one (has not observed anything)
    /// batch_size should be greater than 1
    pub fn setup_for_riscv_compress(
        vk: &BaseVerifyingKey<RiscvSC>,
        machine: &BaseMachine<RiscvSC, C>,
        proofs: &[BaseProof<RiscvSC>],
        mut base_challenger: Challenger<RiscvSC>,
    ) -> Self {
        let num_public_values = machine.num_public_values();

        let mut stdin = Vec::new();

        // phase 1 for base_challenger
        vk.observed_by(&mut base_challenger);
        for each_proof in proofs.iter() {
            base_challenger.observe(each_proof.clone().commitments.main_commit);
            base_challenger.observe_slice(&each_proof.public_values[0..num_public_values]);
        }

        let base_challenger = Arc::new(base_challenger);

        // base_challenger is ready for use in phase 2
        // reconstruct challenger is initialized here
        let mut reconstruct_challenger = machine.config().challenger();
        vk.observed_by(&mut reconstruct_challenger);

        let total = proofs.len();

        for (i, proof) in proofs.iter().enumerate() {
            let flag_complete = i == total - 1;
            stdin.push(RiscvRecursionStdin {
                vk: vk.clone(),
                machine: machine.clone(),
                proofs: Arc::new([proof.clone()]),
                base_challenger: base_challenger.clone(),
                reconstruct_challenger: reconstruct_challenger.clone(),
                flag_complete,
            });

            // todo: check efficiency
            reconstruct_challenger.observe(proof.clone().commitments.main_commit);
            reconstruct_challenger.observe_slice(&proof.public_values[0..num_public_values]);
        }

        Self {
            buffer: stdin.into(),
            cursor: 0,
        }
    }

    /// Construct the recursion stdin for riscv_combine.
    /// base_challenger is assumed to be a fresh new one (has not observed anything)
    /// combine_size should be greater than 1
    pub fn setup_for_riscv_combine(
        vk: &BaseVerifyingKey<RiscvSC>,
        machine: &BaseMachine<RiscvSC, C>,
        proofs: &[BaseProof<RiscvSC>],
        mut base_challenger: Challenger<RiscvSC>,
        combine_size: usize,
    ) -> Self {
        assert!(combine_size > 1);

        let num_public_values = machine.num_public_values();

        let mut stdin = Vec::new();

        // phase 1 for base_challenger
        vk.observed_by(&mut base_challenger);
        for each_proof in proofs.iter() {
            base_challenger.observe(each_proof.clone().commitments.main_commit);
            base_challenger.observe_slice(&each_proof.public_values[0..num_public_values]);
        }

        let base_challenger = Arc::new(base_challenger);

        // base_challenger is ready for use in phase 2
        // reconstruct challenger is initialized here
        let mut reconstruct_challenger = machine.config().challenger();
        vk.observed_by(&mut reconstruct_challenger);

        let proof_batches = proofs.chunks(combine_size);
        let total = proof_batches.len();

        for (i, batch_proofs) in proof_batches.enumerate() {
            let batch_proofs: Arc<[_]> = Arc::from(batch_proofs);
            let flag_complete = i == total - 1;
            stdin.push(RiscvRecursionStdin {
                vk: vk.clone(),
                machine: machine.clone(),
                proofs: batch_proofs.clone(),
                base_challenger: base_challenger.clone(),
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

        Self {
            buffer: stdin.into(),
            cursor: 0,
        }
    }
}

// for recursion stdin
impl<C> EmulatorStdin<RecursionStdin<RecursionSC, C>>
where
    C: ChipBehavior<
            Val<RecursionSC>,
            Program = RecursionProgram<Val<RecursionSC>>,
            Record = RecursionRecord<Val<RecursionSC>>,
        > + for<'b> Air<ProverConstraintFolder<'b, RecursionSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RecursionSC>>,
{
    /// Construct the recursion stdin for one layer of combine.
    pub fn setup_for_combine(
        vk: &BaseVerifyingKey<RecursionSC>,
        machine: &BaseMachine<RecursionSC, C>,
        proofs: &[BaseProof<RecursionSC>],
        combine_size: usize,
        flag_complete: bool,
    ) -> Self {
        let mut stdin = Vec::new();

        let proof_batches = proofs.chunks(combine_size);

        for batch_proofs in proof_batches {
            stdin.push(RecursionStdin {
                vk: vk.clone(),
                machine: machine.clone(),
                proofs: batch_proofs.into(),
                flag_complete,
            });
        }

        Self {
            buffer: stdin.into(),
            cursor: 0,
        }
    }

    pub fn setup_for_single(
        vk: &BaseVerifyingKey<RecursionSC>,
        machine: &BaseMachine<RecursionSC, C>,
        proofs: &[BaseProof<RecursionSC>],
    ) -> Self {
        let mut stdin = Vec::new();

        assert_eq!(proofs.len(), 1);

        stdin.push(RecursionStdin {
            vk: vk.clone(),
            machine: machine.clone(),
            proofs: proofs.into(),
            flag_complete: true,
        });

        Self {
            buffer: stdin.into(),
            cursor: 0,
        }
    }
}
