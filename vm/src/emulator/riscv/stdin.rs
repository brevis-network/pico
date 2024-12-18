use crate::{
    compiler::{
        recursion_v2::{
            circuit::constraints::RecursiveVerifierConstraintFolder, program::RecursionProgram,
        },
        riscv::program::Program,
    },
    configs::{
        config::{Challenger, StarkGenericConfig, Val},
        stark_config::bb_poseidon2::BabyBearPoseidon2,
    },
    emulator::riscv::record::EmulationRecord,
    instances::{
        chiptype::{recursion_chiptype_v2::RecursionChipType, riscv_chiptype::RiscvChipType},
        compiler_v2::{
            recursion_circuit::{combine::builder::CombineVerifierCircuit, stdin::RecursionStdin},
            riscv_circuit::{convert::builder::ConvertVerifierCircuit, stdin::ConvertStdin},
        },
        configs::{
            recur_config::{FieldConfig as RecursionFC, StarkConfig as RecursionSC},
            riscv_config::StarkConfig as RiscvSC,
        },
    },
    machine::{
        chip::ChipBehavior,
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::BaseVerifyingKey,
        machine::BaseMachine,
        proof::BaseProof,
    },
    primitives::consts::{COMBINE_DEGREE, DIGEST_SIZE},
    recursion_v2::runtime::RecursionRecord,
};
use alloc::sync::Arc;
use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_challenger::CanObserve;
use p3_field::FieldAlgebra;
use serde::Serialize;
use std::array;

#[derive(Clone, Default, Serialize)]
pub struct EmulatorStdinBuilder<I> {
    pub buffer: Vec<I>,
}

#[derive(Default, Serialize)]
pub struct EmulatorStdin<P, I> {
    pub programs: Vec<P>,
    pub inputs: Vec<I>,
    pub pointer: usize,
}

impl<P, I> Clone for EmulatorStdin<P, I>
where
    P: Clone,
    I: Clone,
{
    fn clone(&self) -> Self {
        Self {
            programs: self.programs.clone(),
            inputs: self.inputs.clone(),
            pointer: self.pointer,
        }
    }
}

#[allow(clippy::should_implement_trait)]
impl<P, I> EmulatorStdin<P, I> {
    // get both program and input for emulator
    pub fn get_program_and_input(&self, index: usize) -> (&P, &I, bool) {
        let flag_last = index == self.inputs.len() - 1;
        if index < self.programs.len() && index < self.inputs.len() {
            (&self.programs[index], &self.inputs[index], flag_last)
        } else {
            panic!("EmulatorStdin: out of bounds");
        }
    }

    // get input of the program for emulator
    pub fn get_input(&self, index: usize) -> (&I, bool) {
        let flag_last = index == self.inputs.len() - 1;
        if index < self.inputs.len() {
            (&self.inputs[index], flag_last)
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

    pub fn finalize(self) -> EmulatorStdin<Program, Vec<u8>> {
        EmulatorStdin {
            programs: vec![],
            inputs: self.buffer,
            pointer: 0,
        }
    }
}

// for convert stdin, converting riscv proofs to recursion proofs
impl<'a>
    EmulatorStdin<
        RecursionProgram<Val<RecursionSC>>,
        ConvertStdin<'a, RiscvSC, RiscvChipType<Val<RiscvSC>>>,
    >
{
    /// Construct the recursion stdin for riscv_compress.
    /// base_challenger is assumed to be a fresh new one (has not observed anything)
    /// batch_size should be greater than 1
    pub fn setup_for_convert(
        riscv_vk: &'a BaseVerifyingKey<RiscvSC>,
        vk_root: [Val<RiscvSC>; DIGEST_SIZE],
        machine: &'a BaseMachine<RiscvSC, RiscvChipType<Val<RiscvSC>>>,
        proofs: &[BaseProof<RiscvSC>],
    ) -> Self {
        // initialize for base_ and reconstruct_challenger
        let [mut base_challenger, mut reconstruct_challenger] =
            array::from_fn(|_| machine.config().challenger());

        riscv_vk.observed_by(&mut base_challenger);
        riscv_vk.observed_by(&mut reconstruct_challenger);

        // make base_challenger ready for use in phase 2
        let num_public_values = machine.num_public_values();
        for each_proof in proofs.iter() {
            base_challenger.observe(each_proof.clone().commitments.global_main_commit);
            base_challenger.observe_slice(&each_proof.public_values[0..num_public_values]);
        }

        // construct programs and inputs
        let total = proofs.len();

        let mut inputs = Vec::new();
        let mut programs = Vec::new();

        // todo optimize: parallel
        for (i, proof) in proofs.iter().enumerate() {
            let flag_complete = i == total - 1;
            let flag_first_chunk = i == 0;

            let input = ConvertStdin {
                machine,
                riscv_vk,
                proofs: vec![proof.clone()],
                base_challenger: base_challenger.clone(),
                reconstruct_challenger: reconstruct_challenger.clone(),
                flag_complete,
                flag_first_chunk,
                vk_root,
            };
            let program = ConvertVerifierCircuit::<RecursionFC, RiscvSC>::build(machine, &input);

            programs.push(program);
            inputs.push(input);
        }

        Self {
            programs,
            inputs,
            pointer: 0,
        }
    }
}

// for recursion stdin
impl<'a, C> EmulatorStdin<RecursionProgram<Val<RecursionSC>>, RecursionStdin<'a, RecursionSC, C>>
where
    C: ChipBehavior<
            Val<RecursionSC>,
            Program = RecursionProgram<Val<RecursionSC>>,
            Record = RecursionRecord<Val<RecursionSC>>,
        > + for<'b> Air<ProverConstraintFolder<'b, RecursionSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RecursionSC>>
        + for<'b> Air<RecursiveVerifierConstraintFolder<'b, RecursionFC>>,
{
    /// Construct the recursion stdin for one layer of combine.
    pub fn setup_for_combine(
        vk_root: [Val<RecursionSC>; DIGEST_SIZE],
        vks: &[BaseVerifyingKey<RecursionSC>],
        proofs: &[BaseProof<RecursionSC>],
        machine: &'a BaseMachine<RecursionSC, C>,
        combine_size: usize,
        flag_complete: bool,
    ) -> Self {
        let mut inputs = Vec::new();
        let mut programs = Vec::new();

        assert_eq!(vks.len(), proofs.len());

        // todo optimize: parallel
        proofs
            .chunks(combine_size)
            .zip(vks.chunks(combine_size))
            .for_each(|(batch_proofs, batch_vks)| {
                // todo: optimization to non-copy
                let batch_proofs = batch_proofs.to_vec();
                let batch_vks = batch_vks.to_vec();

                let input = RecursionStdin {
                    machine,
                    vks: batch_vks,
                    proofs: batch_proofs,
                    flag_complete,
                    vk_root,
                };
                let program =
                    CombineVerifierCircuit::<RecursionFC, RecursionSC, C>::build(machine, &input);

                programs.push(program);
                inputs.push(input);
            });

        Self {
            programs,
            inputs,
            pointer: 0,
        }
    }
}
