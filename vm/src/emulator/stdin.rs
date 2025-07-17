use crate::{
    chips::{
        chips::riscv_poseidon2::FieldSpecificPoseidon2Chip as RiscvPoseidon2Chip,
        precompiles::poseidon2::FieldSpecificPrecompilePoseidon2Chip,
    },
    compiler::recursion::{
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
    configs::config::{Challenge, Challenger, Com, PcsProof, StarkGenericConfig, Val},
    emulator::recursion::emulator::RecursionRecord,
    instances::{
        chiptype::{recursion_chiptype::RecursionChipType, riscv_chiptype::RiscvChipType},
        compiler::{
            recursion_circuit::{combine::builder::CombineVerifierCircuit, stdin::RecursionStdin},
            riscv_circuit::{convert::builder::ConvertVerifierCircuit, stdin::ConvertStdin},
            shapes::recursion_shape::RecursionShapeConfig,
            vk_merkle::{
                builder::CombineVkVerifierCircuit, stdin::RecursionStdinVariant,
                vk_verification_enabled, VkMerkleManager,
            },
        },
    },
    machine::{
        chip::ChipBehavior,
        field::FieldSpecificPoseidon2Config,
        keys::{BaseVerifyingKey, HashableKey},
        machine::BaseMachine,
        proof::BaseProof,
    },
    primitives::consts::{DIGEST_SIZE, EXTENSION_DEGREE},
};
use alloc::sync::Arc;
use p3_air::Air;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::{extension::BinomiallyExtendable, PrimeField32, TwoAdicField};
use p3_maybe_rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::{array, fmt::Debug};
use tracing::instrument;

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

    pub fn new_riscv(buf: &[I]) -> Self
    where
        I: Clone,
    {
        Self {
            programs: Arc::new([]),
            inputs: Arc::from(buf),
            flag_empty: false,
            pointer: 0,
        }
    }
}

// for riscv machine stdin
impl EmulatorStdinBuilder<Vec<u8>> {
    pub fn write<T: Serialize>(&mut self, data: &T) {
        let mut tmp = Vec::new();
        bincode::serialize_into(&mut tmp, data).expect("serialization failed");
        self.buffer.push(tmp);
    }

    /// Write a slice of bytes to the buffer.
    pub fn write_slice(&mut self, slice: &[u8]) {
        self.buffer.push(slice.to_vec());
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
impl<SC> EmulatorStdin<RecursionProgram<Val<SC>>, ConvertStdin<SC, RiscvChipType<Val<SC>>>>
where
    SC: StarkGenericConfig + 'static,
    Val<SC>: PrimeField32 + FieldSpecificPoseidon2Config,
{
    /// Construct the recursion stdin for riscv_compress.
    /// base_challenger is assumed to be a fresh new one (has not observed anything)
    /// batch_size should be greater than 1
    #[instrument(name = "setup convert stdin", level = "debug", skip_all)]
    pub fn setup_for_convert<F, CC>(
        riscv_vk: &BaseVerifyingKey<SC>,
        vk_root: [Val<SC>; DIGEST_SIZE],
        machine: &BaseMachine<SC, RiscvChipType<Val<SC>>>,
        proofs: &[BaseProof<SC>],
        shape_config: &Option<RecursionShapeConfig<Val<SC>, RecursionChipType<Val<SC>>>>,
    ) -> Self
    where
        F: TwoAdicField
            + PrimeField32
            + Witnessable<CC, WitnessVariable = Felt<CC::F>>
            + BinomiallyExtendable<EXTENSION_DEGREE>
            + FieldSpecificPoseidon2Config,
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
        RiscvPoseidon2Chip<F>: for<'b> Air<RecursiveVerifierConstraintFolder<'b, CC>>,
        FieldSpecificPrecompilePoseidon2Chip<F>:
            for<'b> Air<RecursiveVerifierConstraintFolder<'b, CC>>,
        SC: Send + Sync,
    {
        // initialize for base_ and reconstruct_challenger
        let [mut base_challenger, mut reconstruct_challenger] =
            array::from_fn(|_| machine.config().challenger());

        riscv_vk.observed_by(&mut base_challenger);
        riscv_vk.observed_by(&mut reconstruct_challenger);

        // construct programs and inputs
        let total = proofs.len();

        let pairs: Vec<_> = proofs
            .par_iter()
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
                let mut program = ConvertVerifierCircuit::<CC, SC>::build(machine, &input);

                if vk_verification_enabled() {
                    if let Some(config) = shape_config {
                        config.padding_shape(&mut program);
                    }
                }

                program.print_stats();

                (program, input)
            })
            .collect();

        let (programs, inputs): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();

        let flag_empty = programs.is_empty();

        Self {
            programs: programs.into(),
            inputs: inputs.into(),
            flag_empty,
            pointer: 0,
        }
    }

    /// Construct the recursion stdin for riscv_compress.
    /// base_challenger is assumed to be a fresh new one (has not observed anything)
    /// batch_size should be greater than 1
    #[instrument(name = "setup convert stdin", level = "debug", skip_all)]
    pub fn setup_for_convert_with_index<F, CC>(
        riscv_vk: &BaseVerifyingKey<SC>,
        vk_root: [Val<SC>; DIGEST_SIZE],
        machine: &BaseMachine<SC, RiscvChipType<Val<SC>>>,
        proof: &BaseProof<SC>,
        shape_config: &Option<RecursionShapeConfig<Val<SC>, RecursionChipType<Val<SC>>>>,
        chunk_index: usize,
        is_last: bool,
    ) -> Self
    where
        F: TwoAdicField
            + PrimeField32
            + Witnessable<CC, WitnessVariable = Felt<CC::F>>
            + BinomiallyExtendable<EXTENSION_DEGREE>
            + FieldSpecificPoseidon2Config,
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
        RiscvPoseidon2Chip<F>: for<'b> Air<RecursiveVerifierConstraintFolder<'b, CC>>,
        FieldSpecificPrecompilePoseidon2Chip<F>:
            for<'b> Air<RecursiveVerifierConstraintFolder<'b, CC>>,
        SC: Send + Sync,
    {
        println!(
            "chunk_index in setup_for_convert_with_index: {:?}",
            chunk_index
        );
        // initialize for base_ and reconstruct_challenger
        let [mut base_challenger, mut reconstruct_challenger] =
            array::from_fn(|_| machine.config().challenger());

        riscv_vk.observed_by(&mut base_challenger);
        riscv_vk.observed_by(&mut reconstruct_challenger);

        // construct programs and inputs
        let flag_complete = is_last;
        let flag_first_chunk = chunk_index == 0;

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

        let mut program = ConvertVerifierCircuit::<CC, SC>::build(machine, &input);

        if vk_verification_enabled() {
            if let Some(config) = shape_config {
                config.padding_shape(&mut program);
            }
        }

        program.print_stats();

        Self {
            programs: Arc::from([program]),
            inputs: Arc::from([input]),
            flag_empty: false,
            pointer: 0,
        }
    }
}

// for recursion_vk stdin
impl<'a, C, SC> EmulatorStdin<RecursionProgram<Val<SC>>, RecursionStdinVariant<'a, SC, C>>
where
    SC: StarkGenericConfig + FieldHasher<Val<SC>>,
    C: ChipBehavior<
            Val<SC>,
            Program = RecursionProgram<Val<SC>>,
            Record = RecursionRecord<Val<SC>>,
        > + Send,
{
    // TODO: should we remove Option for recursion_shape_config? select path only by VK_VERIFICATION
    /// Construct the recursion stdin for one layer of combine.
    #[instrument(name = "setup combine stdin", level = "debug", skip_all)]
    #[allow(clippy::too_many_arguments)]
    pub fn setup_for_combine<F, CC>(
        vk_root: [Val<SC>; DIGEST_SIZE],
        vks: &[BaseVerifyingKey<SC>],
        proofs: &[BaseProof<SC>],
        machine: &'a BaseMachine<SC, C>,
        combine_size: usize,
        flag_complete: bool,
        vk_manager: &VkMerkleManager<SC>,
        recursion_shape_config: Option<&RecursionShapeConfig<F, RecursionChipType<F>>>,
    ) -> (Self, Option<BaseVerifyingKey<SC>>, Option<BaseProof<SC>>)
    where
        F: TwoAdicField
            + PrimeField32
            + Witnessable<CC, WitnessVariable = Felt<CC::F>>
            + BinomiallyExtendable<EXTENSION_DEGREE>
            + FieldSpecificPoseidon2Config,
        SC: FieldFriConfigVariable<
                CC,
                Val = F,
                Domain = TwoAdicMultiplicativeCoset<F>,
                FriChallengerVariable = DuplexChallengerVariable<CC>,
                DigestVariable = [Felt<F>; DIGEST_SIZE],
            > + FieldHasher<Val<SC>, Digest = [Val<SC>; DIGEST_SIZE]>
            + 'static,
        CC: CircuitConfig<N = F, F = F, EF = Challenge<SC>, Bit = Felt<F>> + Debug,
        Challenge<SC>: Witnessable<CC, WitnessVariable = Ext<CC::F, CC::EF>>,
        Com<SC>: Witnessable<CC, WitnessVariable = SC::DigestVariable>,
        PcsProof<SC>: Witnessable<CC, WitnessVariable = FriProofVariable<CC, SC>>,
        Challenger<SC>: Witnessable<CC, WitnessVariable = SC::FriChallengerVariable>,
        BaseVerifyingKey<SC>: HashableKey<F> + Send + Sync,
        BaseProof<SC>: Send + Sync,
        C: for<'b> Air<RecursiveVerifierConstraintFolder<'b, CC>>,

        BaseMachine<SC, C>: Send + Sync,
    {
        assert_eq!(vks.len(), proofs.len());

        let mut last_vk = None;
        let mut last_proof = None;

        let mut programs = Vec::new();
        let mut inputs = Vec::new();

        // TODO: fix to parallel
        proofs
            .chunks(combine_size)
            .zip(vks.chunks(combine_size))
            .for_each(|(batch_proofs, batch_vks)| {
                if batch_proofs.len() > 1 {
                    let input = RecursionStdin {
                        machine,
                        vks: batch_vks.into(),
                        proofs: batch_proofs.into(),
                        flag_complete,
                        vk_root,
                    };

                    let (program, input) = if vk_manager.vk_verification_enabled() {
                        let input = vk_manager.add_vk_merkle_proof(input);
                        let mut temp_program =
                            CombineVkVerifierCircuit::<CC, SC, C>::build(machine, &input);

                        let recursion_shape_config = recursion_shape_config
                            .expect("recursion_shape_config in combine should not be None when VK_VERIFICATION enabled");
                        recursion_shape_config.padding_shape(&mut temp_program);
                        (temp_program, RecursionStdinVariant::WithVk(input))
                    } else {
                        (
                            CombineVerifierCircuit::<CC, SC, C>::build(machine, &input),
                            RecursionStdinVariant::NoVk(input),
                        )
                    };

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
