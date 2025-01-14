use crate::{
    chips::{
        chips::{poseidon2_skinny_v2::Poseidon2SkinnyChip, poseidon2_wide_v2::Poseidon2WideChip},
        precompiles::poseidon2::Poseidon2PermuteChip,
    },
    compiler::{
        recursion_v2::{
            circuit::{
                challenger::DuplexChallengerVariable,
                config::{CircuitConfig, FieldFriConfigVariable},
                constraints::RecursiveVerifierConstraintFolder,
                hash::FieldHasher,
                types::FriProofVariable,
                witness::Witnessable,
            },
            ir::{Ext, Felt},
            program::RecursionProgram,
        },
        riscv::program::Program,
    },
    configs::config::{Challenge, Challenger, Com, PcsProof, StarkGenericConfig, Val},
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
    },
    machine::{
        chip::ChipBehavior,
        folder::{ProverConstraintFolder, SymbolicConstraintFolder, VerifierConstraintFolder},
        keys::{BaseVerifyingKey, HashableKey},
        machine::BaseMachine,
        proof::BaseProof,
    },
    primitives::consts::{COMBINE_DEGREE, CONVERT_DEGREE, DIGEST_SIZE, EXTENSION_DEGREE},
    recursion_v2::runtime::RecursionRecord,
};
use alloc::sync::Arc;
use p3_air::Air;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::{extension::BinomiallyExtendable, PrimeField32, TwoAdicField};
use serde::{Deserialize, Serialize};
use std::{array, fmt::Debug};

use super::record::EmulationRecord;

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
impl<SC, const HALF_EXTERNAL_ROUNDS: usize, const NUM_INTERNAL_ROUNDS: usize>
    EmulatorStdin<
        RecursionProgram<Val<SC>>,
        ConvertStdin<SC, RiscvChipType<Val<SC>, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>>,
    >
where
    SC: StarkGenericConfig,
    Val<SC>: PrimeField32,
    Poseidon2PermuteChip<Val<SC>, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>:
        ChipBehavior<Val<SC>, Record = EmulationRecord, Program = Program>,
{
    /// Construct the recursion stdin for riscv_compress.
    /// base_challenger is assumed to be a fresh new one (has not observed anything)
    /// batch_size should be greater than 1
    pub fn setup_for_convert<
        F,
        CC,
        const W: u32,
        const NUM_EXTERNAL_ROUNDS: usize,
        const NUM_INTERNAL_ROUNDS_MINUS_ONE: usize,
    >(
        riscv_vk: &BaseVerifyingKey<SC>,
        vk_root: [Val<SC>; DIGEST_SIZE],
        machine: &BaseMachine<
            SC,
            RiscvChipType<Val<SC>, HALF_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS>,
        >,
        proofs: &[BaseProof<SC>],
        recursion_config: Option<
            RecursionShapeConfig<
                Val<SC>,
                RecursionChipType<
                    Val<SC>,
                    CONVERT_DEGREE,
                    W,
                    NUM_EXTERNAL_ROUNDS,
                    NUM_INTERNAL_ROUNDS,
                    NUM_INTERNAL_ROUNDS_MINUS_ONE,
                >,
            >,
        >,
    ) -> Self
    where
        F: TwoAdicField
            + PrimeField32
            + Witnessable<CC, WitnessVariable = Felt<CC::F>>
            + BinomiallyExtendable<EXTENSION_DEGREE>,
        SC: FieldFriConfigVariable<
            CC,
            Val = F,
            Domain = TwoAdicMultiplicativeCoset<F>,
            FriChallengerVariable = DuplexChallengerVariable<CC>,
            DigestVariable = [Felt<F>; DIGEST_SIZE],
        >,
        CC: CircuitConfig<N = F, F = F, EF = Challenge<SC>, Bit = Felt<F>> + Debug,
        Challenge<SC>: Witnessable<CC, WitnessVariable = Ext<CC::F, CC::EF>>,
        Com<SC>: Witnessable<CC, WitnessVariable = SC::DigestVariable>,
        PcsProof<SC>: Witnessable<CC, WitnessVariable = FriProofVariable<CC, SC>>,
        Challenger<SC>: Witnessable<CC, WitnessVariable = SC::FriChallengerVariable>,
        Poseidon2SkinnyChip<CONVERT_DEGREE, NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS, F>:
            Air<SymbolicConstraintFolder<F>>
                + ChipBehavior<F, Record = RecursionRecord<F>, Program = RecursionProgram<F>>,
        Poseidon2WideChip<
            CONVERT_DEGREE,
            NUM_EXTERNAL_ROUNDS,
            NUM_INTERNAL_ROUNDS,
            NUM_INTERNAL_ROUNDS_MINUS_ONE,
            F,
        >: Air<SymbolicConstraintFolder<F>>
            + ChipBehavior<F, Record = RecursionRecord<F>, Program = RecursionProgram<F>>,
    {
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
                    machine: machine.clone(),
                    riscv_vk: riscv_vk.clone(),
                    proofs: Arc::new([proof.clone()]),
                    base_challenger: base_challenger.clone(),
                    reconstruct_challenger: reconstruct_challenger.clone(),
                    flag_complete,
                    flag_first_chunk,
                    vk_root,
                };
                let mut program = ConvertVerifierCircuit::<
                    CC,
                    SC,
                    HALF_EXTERNAL_ROUNDS,
                    NUM_INTERNAL_ROUNDS,
                >::build(machine, &input);

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
impl<'a, C, SC> EmulatorStdin<RecursionProgram<Val<SC>>, RecursionStdin<'a, SC, C>>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<
            Val<SC>,
            Program = RecursionProgram<Val<SC>>,
            Record = RecursionRecord<Val<SC>>,
        > + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
{
    /// Construct the recursion stdin for one layer of combine.
    pub fn setup_for_combine<F, CC>(
        vk_root: [Val<SC>; DIGEST_SIZE],
        vks: &[BaseVerifyingKey<SC>],
        proofs: &[BaseProof<SC>],
        machine: &'a BaseMachine<SC, C>,
        combine_size: usize,
        flag_complete: bool,
    ) -> (Self, Option<BaseVerifyingKey<SC>>, Option<BaseProof<SC>>)
    where
        F: PrimeField32
            + BinomiallyExtendable<EXTENSION_DEGREE>
            + TwoAdicField
            + Witnessable<CC, WitnessVariable = Felt<CC::F>>,
        CC: CircuitConfig<N = F, F = F, EF = Challenge<SC>, Bit = Felt<F>> + Debug + Send + Sync,
        CC::EF: Witnessable<CC, WitnessVariable = Ext<CC::F, CC::EF>>,
        SC: FieldFriConfigVariable<CC, Val = F, Domain = TwoAdicMultiplicativeCoset<F>>
            + Send
            + Sync,
        C: for<'b> Air<RecursiveVerifierConstraintFolder<'b, CC>> + Send + Sync,
        Com<SC>: Witnessable<CC, WitnessVariable = SC::DigestVariable>,
        PcsProof<SC>: Witnessable<CC, WitnessVariable = FriProofVariable<CC, SC>>,
        BaseVerifyingKey<SC>: Send + Sync,
        BaseProof<SC>: Send + Sync,
    {
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
                    let program = CombineVerifierCircuit::<CC, SC, C>::build(machine, &input);

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
impl<'a, C, SC> EmulatorStdin<RecursionProgram<Val<SC>>, RecursionVkStdin<'a, SC, C>>
where
    SC: StarkGenericConfig + FieldHasher<Val<SC>>,
    C: ChipBehavior<
            Val<SC>,
            Program = RecursionProgram<Val<SC>>,
            Record = RecursionRecord<Val<SC>>,
        > + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>
        + Send,
{
    /// Construct the recursion stdin for one layer of combine.
    #[allow(clippy::too_many_arguments)]
    pub fn setup_for_combine_vk<
        F,
        CC,
        const W: u32,
        const NUM_EXTERNAL_ROUNDS: usize,
        const NUM_INTERNAL_ROUNDS: usize,
        const NUM_INTERNAL_ROUNDS_MINUS_ONE: usize,
    >(
        vk_root: [Val<SC>; DIGEST_SIZE],
        vks: &[BaseVerifyingKey<SC>],
        proofs: &[BaseProof<SC>],
        machine: &'a BaseMachine<SC, C>,
        combine_size: usize,
        flag_complete: bool,
        vk_manager: &VkMerkleManager<SC>,
        recursion_shape_config: &RecursionShapeConfig<
            F,
            RecursionChipType<
                F,
                COMBINE_DEGREE,
                W,
                NUM_EXTERNAL_ROUNDS,
                NUM_INTERNAL_ROUNDS,
                NUM_INTERNAL_ROUNDS_MINUS_ONE,
            >,
        >,
    ) -> (Self, Option<BaseVerifyingKey<SC>>, Option<BaseProof<SC>>)
    where
        F: TwoAdicField
            + PrimeField32
            + Witnessable<CC, WitnessVariable = Felt<CC::F>>
            + BinomiallyExtendable<EXTENSION_DEGREE>,
        SC: FieldFriConfigVariable<
                CC,
                Val = F,
                Domain = TwoAdicMultiplicativeCoset<F>,
                FriChallengerVariable = DuplexChallengerVariable<CC>,
                DigestVariable = [Felt<F>; DIGEST_SIZE],
            > + FieldHasher<Val<SC>, Digest = [Val<SC>; DIGEST_SIZE]>,
        CC: CircuitConfig<N = F, F = F, EF = Challenge<SC>, Bit = Felt<F>> + Debug,
        Challenge<SC>: Witnessable<CC, WitnessVariable = Ext<CC::F, CC::EF>>,
        Com<SC>: Witnessable<CC, WitnessVariable = SC::DigestVariable>,
        PcsProof<SC>: Witnessable<CC, WitnessVariable = FriProofVariable<CC, SC>>,
        Challenger<SC>: Witnessable<CC, WitnessVariable = SC::FriChallengerVariable>,
        BaseVerifyingKey<SC>: HashableKey<F> + Send + Sync,
        BaseProof<SC>: Send + Sync,
        C: for<'b> Air<RecursiveVerifierConstraintFolder<'b, CC>>,

        BaseMachine<SC, C>: Send + Sync,

        Poseidon2SkinnyChip<COMBINE_DEGREE, NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS, F>:
            Air<SymbolicConstraintFolder<F>>
                + ChipBehavior<F, Record = RecursionRecord<F>, Program = RecursionProgram<F>>,
        Poseidon2WideChip<
            COMBINE_DEGREE,
            NUM_EXTERNAL_ROUNDS,
            NUM_INTERNAL_ROUNDS,
            NUM_INTERNAL_ROUNDS_MINUS_ONE,
            F,
        >: Air<SymbolicConstraintFolder<F>>
            + ChipBehavior<F, Record = RecursionRecord<F>, Program = RecursionProgram<F>>,
    {
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
                    let mut program = CombineVkVerifierCircuit::<CC, SC, C>::build(machine, &input);

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
