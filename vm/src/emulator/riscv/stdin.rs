use crate::{
    compiler::recursion_v2::{
        circuit::constraints::RecursiveVerifierConstraintFolder, program::RecursionProgram,
    },
    configs::config::{StarkGenericConfig, Val},
    instances::{
        chiptype::{recursion_chiptype_v2::RecursionChipType, riscv_chiptype::RiscvChipType},
        compiler_v2::{
            recursion_circuit::{combine::builder::CombineVerifierCircuit, stdin::RecursionStdin},
            riscv_circuit::{convert::builder::ConvertVerifierCircuit, stdin::ConvertStdin},
            shapes::compress_shape::RecursionShapeConfig,
            vk_merkle::{
                builder::CombineVkVerifierCircuit, stdin::RecursionVkStdin, VkMerkleManager,
            },
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
    primitives::consts::{COMBINE_DEGREE, CONVERT_DEGREE, DIGEST_SIZE},
    recursion_v2::runtime::RecursionRecord,
};
use alloc::sync::Arc;
use p3_air::Air;
use p3_baby_bear::BabyBear;
use serde::{Deserialize, Serialize};
use std::array;

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct EmulatorStdinBuilder<I> {
    pub buffer: Vec<I>,
}

#[derive(Default, Serialize, Deserialize)]
pub struct EmulatorStdin<P, I> {
    pub programs: Arc<[P]>,
    pub inputs: Arc<[I]>,
    pub flag_empty: bool,
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
            flag_empty: self.flag_empty,
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

    pub fn finalize<P>(self) -> EmulatorStdin<P, Vec<u8>> {
        EmulatorStdin {
            programs: Arc::new([]),
            inputs: self.buffer.into(),
            flag_empty: false,
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
        recursion_config: Option<
            RecursionShapeConfig<BabyBear, RecursionChipType<BabyBear, CONVERT_DEGREE>>,
        >,
    ) -> Self {
        // initialize for base_ and reconstruct_challenger
        let [mut base_challenger, mut reconstruct_challenger] =
            array::from_fn(|_| machine.config().challenger());

        riscv_vk.observed_by(&mut base_challenger);
        riscv_vk.observed_by(&mut reconstruct_challenger);

        // construct programs and inputs
        let total = proofs.len();

        let (programs, inputs): (Vec<_>, Vec<_>) = proofs
            .iter()
            .enumerate()
            .map(|(i, proof)| {
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
                let mut program =
                    ConvertVerifierCircuit::<RecursionFC, RiscvSC>::build(machine, &input);

                if let Some(config) = &recursion_config {
                    config.padding_shape(&mut program);
                }

                program.print_stats();

                (program, input)
            })
            .unzip();

        let flag_empty = programs.is_empty();

        Self {
            programs: programs.into(),
            inputs: inputs.into(),
            flag_empty,
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
        + for<'b> Air<RecursiveVerifierConstraintFolder<'b, RecursionFC>>
        + Send,
{
    /// Construct the recursion stdin for one layer of combine.
    pub fn setup_for_combine(
        vk_root: [Val<RecursionSC>; DIGEST_SIZE],
        vks: &[BaseVerifyingKey<RecursionSC>],
        proofs: &[BaseProof<RecursionSC>],
        machine: &'a BaseMachine<RecursionSC, C>,
        combine_size: usize,
        flag_complete: bool,
    ) -> (
        Self,
        Option<BaseVerifyingKey<RecursionSC>>,
        Option<BaseProof<RecursionSC>>,
    ) {
        assert_eq!(vks.len(), proofs.len());

        let mut last_vk = None;
        let mut last_proof = None;

        let mut programs = Vec::new();
        let mut inputs = Vec::new();

        // TODO: Fix to parallel.
        proofs
            .chunks(combine_size)
            .zip(vks.chunks(combine_size))
            .for_each(|(batch_proofs, batch_vks)| {
                if batch_proofs.len() > 1 {
                    let input = RecursionStdin {
                        machine,
                        vks: batch_vks.into(), // todo: optimization to non-copy
                        proofs: batch_proofs.into(),
                        flag_complete,
                        vk_root,
                    };
                    let program = CombineVerifierCircuit::<RecursionFC, RecursionSC, C>::build(
                        machine, &input,
                    );

                    program.print_stats();

                    programs.push(program);
                    inputs.push(input);
                } else {
                    last_vk = Some(batch_vks[0].clone());
                    last_proof = Some(batch_proofs[0].clone());
                }
            });

        let flag_empty = programs.is_empty();

        (
            Self {
                programs: programs.into(),
                inputs: inputs.into(),
                flag_empty,
                pointer: 0,
            },
            last_vk,
            last_proof,
        )
    }
}

// for recursion_vk stdin
impl<'a, C> EmulatorStdin<RecursionProgram<Val<RecursionSC>>, RecursionVkStdin<'a, RecursionSC, C>>
where
    C: ChipBehavior<
            Val<RecursionSC>,
            Program = RecursionProgram<Val<RecursionSC>>,
            Record = RecursionRecord<Val<RecursionSC>>,
        > + for<'b> Air<ProverConstraintFolder<'b, RecursionSC>>
        + for<'b> Air<VerifierConstraintFolder<'b, RecursionSC>>
        + for<'b> Air<RecursiveVerifierConstraintFolder<'b, RecursionFC>>
        + Send,
{
    /// Construct the recursion stdin for one layer of combine.
    #[allow(clippy::too_many_arguments)]
    pub fn setup_for_combine_vk(
        vk_root: [Val<RecursionSC>; DIGEST_SIZE],
        vks: &[BaseVerifyingKey<RecursionSC>],
        proofs: &[BaseProof<RecursionSC>],
        machine: &'a BaseMachine<RecursionSC, C>,
        combine_size: usize,
        flag_complete: bool,
        vk_manager: &VkMerkleManager,
        recursion_shape_config: &RecursionShapeConfig<
            BabyBear,
            RecursionChipType<BabyBear, COMBINE_DEGREE>,
        >,
    ) -> (
        Self,
        Option<BaseVerifyingKey<RecursionSC>>,
        Option<BaseProof<RecursionSC>>,
    ) {
        assert_eq!(vks.len(), proofs.len());

        let mut last_vk = None;
        let mut last_proof = None;

        let mut programs = Vec::new();
        let mut inputs = Vec::new();

        proofs
            .chunks(combine_size)
            .zip(vks.chunks(combine_size))
            .for_each(|(batch_proofs, batch_vks)| {
                if batch_proofs.len() > 1 {
                    let input = RecursionStdin {
                        machine,
                        vks: batch_vks.into(), // todo: optimization to non-copy
                        proofs: batch_proofs.into(),
                        flag_complete,
                        vk_root,
                    };

                    let input = vk_manager.add_vk_merkle_proof(input);
                    let mut program =
                        CombineVkVerifierCircuit::<RecursionFC, RecursionSC, C>::build(
                            machine, &input,
                        );

                    recursion_shape_config.padding_shape(&mut program);

                    program.print_stats();

                    programs.push(program);
                    inputs.push(input);
                } else {
                    last_vk = Some(batch_vks[0].clone());
                    last_proof = Some(batch_proofs[0].clone());
                }
            });

        let flag_empty = programs.is_empty();

        (
            Self {
                programs: programs.into(),
                inputs: inputs.into(),
                flag_empty,
                pointer: 0,
            },
            last_vk,
            last_proof,
        )
    }
}
