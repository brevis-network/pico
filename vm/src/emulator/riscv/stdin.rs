use crate::{
    compiler::riscv::program::Program,
    configs::config::{Challenger, StarkGenericConfig},
    emulator::riscv::record::EmulationRecord,
    instances::{
        compiler::riscv_circuit::stdin::RiscvRecursionStdin,
        configs::riscv_config::StarkConfig as RiscvSC, machine::riscv_machine::RiscvMachine,
    },
    machine::{
        chip::ChipBehavior,
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::BaseVerifyingKey,
        machine::MachineBehavior,
        proof::BaseProof,
    },
};
use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_challenger::CanObserve;
use serde::Serialize;

#[derive(Clone, Serialize)]
pub struct EmulatorStdin<I> {
    pub buffer: Vec<I>,
    pub cursor: usize,
}

impl<I> EmulatorStdin<I> {
    pub fn default() -> Self {
        Self {
            buffer: Vec::new(),
            cursor: 0,
        }
    }

    pub fn next(&mut self) -> (&mut I, bool) {
        let flag_last = self.cursor == self.buffer.len() - 1;
        if self.cursor < self.buffer.len() {
            let cursor = self.cursor;
            self.cursor += 1;
            (&mut self.buffer[cursor], flag_last)
        } else {
            panic!("EmulatorStdin: out of bounds");
        }
    }

    pub fn get(&self, index: usize) -> (&I, bool) {
        let flag_last = index == self.buffer.len() - 1;
        if index < self.buffer.len() {
            (&self.buffer[index], flag_last)
        } else {
            panic!("EmulatorStdin: out of bounds");
        }
    }
}

// for riscv machine stdin
impl EmulatorStdin<Vec<u8>> {
    pub fn write<T: Serialize>(&mut self, data: &T) {
        let mut tmp = Vec::new();
        bincode::serialize_into(&mut tmp, data).expect("serialization failed");
        self.buffer.push(tmp);
    }
}

// for riscv field_config stdin, both compress and combine
impl<'a, RiscvC> EmulatorStdin<RiscvRecursionStdin<'a, RiscvSC, RiscvC>>
where
    RiscvC: ChipBehavior<BabyBear, Program = Program, Record = EmulationRecord>
        + for<'b> Air<ProverConstraintFolder<'b, RiscvSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RiscvSC>>,
{
    /// Construct the field_config stdin for riscv_compress.
    /// base_challenger is assumed to be a fresh new one (has not observed anything)
    /// batch_size should be greater than 1
    pub fn construct_for_compress(
        vk: &'a BaseVerifyingKey<RiscvSC>,
        machine: &'a RiscvMachine<RiscvSC, RiscvC>,
        proofs: &[BaseProof<RiscvSC>],
        base_challenger: &'a mut Challenger<RiscvSC>,
    ) -> Self {
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

        let total = proofs.len();

        for (i, proof) in proofs.into_iter().enumerate() {
            let flag_complete = i == total - 1;
            stdin.push(RiscvRecursionStdin {
                vk,
                machine,
                proofs: vec![proof.clone()],
                base_challenger,
                reconstruct_challenger: reconstruct_challenger.clone(),
                flag_complete,
            });

            // todo: check efficiency
            reconstruct_challenger.observe(proof.clone().commitments.main_commit);
            reconstruct_challenger.observe_slice(&proof.public_values[0..num_public_values]);
        }

        Self {
            buffer: stdin,
            cursor: 0,
        }
    }

    /// Construct the field_config stdin for riscv_combine.
    /// base_challenger is assumed to be a fresh new one (has not observed anything)
    /// batch_size should be greater than 1
    pub fn construct_for_combine(
        vk: &'a BaseVerifyingKey<RiscvSC>,
        machine: &'a RiscvMachine<RiscvSC, RiscvC>,
        proofs: &[BaseProof<RiscvSC>],
        base_challenger: &'a mut <RiscvSC as StarkGenericConfig>::Challenger,
        batch_size: usize,
    ) -> Self {
        assert!(batch_size > 1);

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

        Self {
            buffer: stdin,
            cursor: 0,
        }
    }
}
