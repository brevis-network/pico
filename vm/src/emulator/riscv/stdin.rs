use crate::{
    compiler::{recursion_v2::program::RecursionProgram, riscv::program::Program},
    configs::config::{Challenger, StarkGenericConfig, Val},
    emulator::riscv::record::EmulationRecord,
    instances::{
        compiler_v2::{
            recursion_circuit::stdin::RecursionStdin,
            riscv_circuit::{challenger::RiscvRecursionChallengers, stdin::RiscvRecursionStdin},
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
    primitives::consts::DIGEST_SIZE,
    recursion_v2::runtime::RecursionRecord,
};
use alloc::sync::Arc;
use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_challenger::CanObserve;
use p3_field::FieldAlgebra;
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

// for riscv recursion stdin, compress
impl<'a, C>
    EmulatorStdin<
        crate::instances::compiler_v2::riscv_circuit::stdin::RiscvRecursionStdin<'a, RiscvSC, C>,
    >
where
    C: ChipBehavior<Val<RiscvSC>, Program = Program, Record = EmulationRecord>
        + for<'b> Air<ProverConstraintFolder<'b, RiscvSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RiscvSC>>,
{
    /// Construct the recursion stdin for riscv_compress.
    /// base_challenger is assumed to be a fresh new one (has not observed anything)
    /// batch_size should be greater than 1
    pub fn setup_for_riscv_compress(
        stdin: crate::instances::compiler_v2::riscv_circuit::stdin::RiscvRecursionStdin<
            'a,
            RiscvSC,
            C,
        >,
    ) -> Self {
        let buffer = vec![stdin];

        Self {
            buffer: buffer.into(),
            cursor: 0,
        }
    }
}

// for riscv recursion stdin, combine
impl<'a, C> EmulatorStdin<RiscvRecursionStdin<'a, RiscvSC, C>>
where
    C: ChipBehavior<Val<RiscvSC>, Program = Program, Record = EmulationRecord>
        + for<'b> Air<ProverConstraintFolder<'b, RiscvSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RiscvSC>>,
{
    /// Construct the recursion stdin for riscv_combine.
    /// base_challenger is assumed to be a fresh new one (has not observed anything)
    /// combine_size should be greater than 1
    pub fn setup_for_riscv_combine(
        _vk: &'a BaseVerifyingKey<RiscvSC>,
        _machine: &'a BaseMachine<RiscvSC, C>,
        _proofs: &[BaseProof<RiscvSC>],
        _base_challenger: &'a mut <RiscvSC as StarkGenericConfig>::Challenger,
        _combine_size: usize,
    ) -> Self {
        panic!("We will not support RiscV combine later");
    }
}

// for recursion stdin
impl<'a, C> EmulatorStdin<RecursionStdin<'a, RecursionSC, C>>
where
    C: ChipBehavior<
            Val<RecursionSC>,
            Program = RecursionProgram<Val<RecursionSC>>,
            Record = RecursionRecord<Val<RecursionSC>>,
        > + for<'b> Air<ProverConstraintFolder<'b, RecursionSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RecursionSC>>,
{
    /// Construct the recursion stdin for one layer of combine.
    pub fn setup_for_combine(stdin: RecursionStdin<'a, RecursionSC, C>) -> Self {
        let buffer = vec![stdin];

        Self {
            buffer: buffer.into(),
            cursor: 0,
        }
    }
}
