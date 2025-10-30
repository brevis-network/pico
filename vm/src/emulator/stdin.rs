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
            utils::words_to_bytes,
            witness::Witnessable,
        },
        ir::{Ext, Felt},
        program::RecursionProgram,
    },
    configs::config::{Challenge, Challenger, Com, PcsProof, StarkGenericConfig, Val},
    emulator::recursion::{emulator::RecursionRecord, public_values::RecursionPublicValues},
    instances::{
        chiptype::{recursion_chiptype::RecursionChipType, riscv_chiptype::RiscvChipType},
        compiler::{
            recursion_circuit::{combine::builder::CombineVerifierCircuit, stdin::RecursionStdin},
            riscv_circuit::{
                convert::builder::ConvertVerifierCircuit,
                deferred::builder::DeferredVerifierCircuit,
                stdin::{ConvertStdin, DeferredStdin},
            },
            shapes::recursion_shape::RecursionShapeConfig,
            vk_merkle::{
                builder::CombineVkVerifierCircuit, stdin::RecursionStdinVariant,
                vk_verification_enabled, HasStaticVkManager, VkMerkleManager,
            },
        },
    },
    machine::{
        chip::ChipBehavior,
        field::FieldSpecificPoseidon2Config,
        keys::{BaseVerifyingKey, HashableKey},
        machine::BaseMachine,
        proof::{BaseProof, MetaProof},
    },
    primitives::{
        consts::{DIGEST_SIZE, EXTENSION_DEGREE},
        hash_deferred_proof, Poseidon2HashField,
    },
};
use alloc::sync::Arc;
use p3_air::Air;
use p3_commit::{Pcs, TwoAdicMultiplicativeCoset};
use p3_field::{extension::BinomiallyExtendable, PrimeField32, TwoAdicField};
use p3_maybe_rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::{array, borrow::Borrow, fmt::Debug};
use tracing::{debug, instrument, warn};

// (combine_proof, riscv_vk)
pub type PicoProofPair<SC> = (MetaProof<SC>, BaseVerifyingKey<SC>);

#[derive(Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "I: Serialize, PicoProofPair<SC>: Serialize",
    deserialize = "I: Deserialize<'de>, PicoProofPair<SC>: Deserialize<'de>"
))]
pub struct EmulatorStdinBuilder<I, SC: StarkGenericConfig> {
    pub buffer: Vec<I>,
    pub pico_proofs: Vec<PicoProofPair<SC>>,
}

impl<I, SC: StarkGenericConfig> Default for EmulatorStdinBuilder<I, SC> {
    fn default() -> Self {
        Self {
            buffer: Vec::new(),
            pico_proofs: Vec::new(),
        }
    }
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

    pub fn new_builder<SC>() -> EmulatorStdinBuilder<I, SC>
    where
        I: Default,
        SC: StarkGenericConfig,
    {
        EmulatorStdinBuilder::<I, SC>::default()
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
impl<SC: StarkGenericConfig> EmulatorStdinBuilder<Vec<u8>, SC> {
    pub fn write<T: Serialize>(&mut self, data: &T) {
        let mut tmp = Vec::new();
        bincode::serialize_into(&mut tmp, data).expect("serialization failed");
        self.buffer.push(tmp);
    }

    /// Write a slice of bytes to the buffer.
    pub fn write_slice(&mut self, slice: &[u8]) {
        self.buffer.push(slice.to_vec());
    }

    pub fn write_pico_proof(&mut self, proof: MetaProof<SC>, vk: BaseVerifyingKey<SC>) {
        self.pico_proofs.push((proof, vk));
    }

    pub fn finalize<P>(self) -> (EmulatorStdin<P, Vec<u8>>, Vec<PicoProofPair<SC>>) {
        let emu_stdin = EmulatorStdin {
            programs: Arc::new([]),
            inputs: self.buffer.into(),
            flag_empty: false,
            pointer: 0,
        };
        (emu_stdin, self.pico_proofs)
    }
}

// for convert stdin, converting riscv proofs to recursion proofs
impl<SC> EmulatorStdin<RecursionProgram<Val<SC>>, ConvertStdin<SC, RiscvChipType<Val<SC>>>>
where
    SC: StarkGenericConfig,
    Val<SC>: PrimeField32 + FieldSpecificPoseidon2Config,
{
    /// Construct the recursion stdin for riscv_compress.
    /// base_challenger is assumed to be a fresh new one (has not observed anything)
    /// batch_size should be greater than 1
    #[instrument(name = "setup convert stdin", level = "debug", skip_all)]
    pub fn setup_for_convert<F, CC>(
        riscv_vk: &BaseVerifyingKey<SC>,
        vk_root: [Val<SC>; DIGEST_SIZE],
        deferred_digest: [Val<SC>; DIGEST_SIZE],
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
                    deferred_digest,
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
    #[allow(clippy::too_many_arguments)]
    pub fn setup_for_convert_with_index<F, CC>(
        riscv_vk: &BaseVerifyingKey<SC>,
        vk_root: [Val<SC>; DIGEST_SIZE],
        deferred_digest: [Val<SC>; DIGEST_SIZE],
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
            deferred_digest,
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

// for convert stdin, converting riscv proofs to recursion proofs
impl<SC> EmulatorStdin<RecursionProgram<Val<SC>>, DeferredStdin<SC, RecursionChipType<Val<SC>>>>
where
    SC: StarkGenericConfig + HasStaticVkManager + 'static,
    Val<SC>: PrimeField32 + FieldSpecificPoseidon2Config,
    <SC as StarkGenericConfig>::Val: BinomiallyExtendable<4>,
    BaseVerifyingKey<SC>: HashableKey<Val<SC>>,
{
    #[instrument(name = "setup deferred stdin", level = "debug", skip_all)]
    pub fn setup_for_deferred<F, CC>(
        riscv_vk: &BaseVerifyingKey<SC>,
        vk_root: [Val<SC>; DIGEST_SIZE],
        machine: &BaseMachine<SC, RecursionChipType<Val<SC>>>,
        shape_config: &Option<RecursionShapeConfig<Val<SC>, RecursionChipType<Val<SC>>>>,
        deferred_proofs: &[MetaProof<SC>],
        deferred_riscv_vks: &[BaseVerifyingKey<SC>],
    ) -> (Self, [Val<SC>; DIGEST_SIZE])
    where
        F: TwoAdicField
            + PrimeField32
            + Witnessable<CC, WitnessVariable = Felt<CC::F>>
            + BinomiallyExtendable<EXTENSION_DEGREE>
            + FieldSpecificPoseidon2Config
            + Poseidon2HashField,
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
        FieldSpecificPrecompilePoseidon2Chip<F>:
            for<'b> Air<RecursiveVerifierConstraintFolder<'b, CC>>,
        SC: Send + Sync,
        <<SC as StarkGenericConfig>::Pcs as Pcs<
            <SC as StarkGenericConfig>::Challenge,
            <SC as StarkGenericConfig>::Challenger,
        >>::ProverData: Send,
        RecursionChipType<F>: for<'b> Air<RecursiveVerifierConstraintFolder<'b, CC>>,
    {
        let mut digest_acc = [Val::<SC>::ZERO; DIGEST_SIZE];
        let mut pairs = Vec::new();
        let vk_manager = <SC as HasStaticVkManager>::static_vk_manager();

        // TODO: reduce cloning
        for (deferred_proof, _deferred_riscv_vk) in
            deferred_proofs.iter().zip(deferred_riscv_vks.iter())
        {
            // only vks in temp_stdin is useful: to get merkle proof in vk_map
            let temp_stdin = RecursionStdin {
                machine,
                vks: [deferred_proof.vks[0].clone()].into(),
                proofs: [deferred_proof.proofs[0].clone()].into(),
                flag_complete: false,
                vk_root,
            };
            let temp_stdin = vk_manager.add_vk_merkle_proof(temp_stdin);

            let input = DeferredStdin {
                proof: deferred_proof.proofs[0].clone(),
                recursion_vk: deferred_proof.vks[0].clone(),
                recursion_vk_merkle_data: temp_stdin.merkle_proof_stdin,
                start_reconstruct_deferred_digest: digest_acc,
                machine: machine.clone(),
                riscv_vk_digest: riscv_vk.hash_field(),
                end_pc: riscv_vk.pc_start,
            };
            let mut program = DeferredVerifierCircuit::<CC, SC>::build(machine, &input);
            if vk_verification_enabled() {
                if let Some(cfg) = shape_config.as_ref() {
                    cfg.padding_shape(&mut program);
                } else {
                    warn!("No recursion shape_config provided; using default configuration for defer_stdin padding.");
                    let recursion_shape_config =
                        RecursionShapeConfig::<Val<SC>, RecursionChipType<Val<SC>>>::default();
                    recursion_shape_config.padding_shape(&mut program);
                }
            }
            // (input, program)
            pairs.push((input, program));
            debug!("digest_acc before: {:?}", digest_acc);
            digest_acc = accumulate_digest(digest_acc, deferred_proof);
            debug!("digest_acc after: {:?}", digest_acc);
        }

        let (inputs, programs): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
        let flag_empty = programs.is_empty();

        let stdin = Self {
            programs: programs.into(),
            inputs: inputs.into(),
            flag_empty,
            pointer: 0,
        };
        (stdin, digest_acc)
    }
}

fn accumulate_digest<SC>(
    prev_digest: [Val<SC>; DIGEST_SIZE],
    proof: &MetaProof<SC>,
) -> [Val<SC>; DIGEST_SIZE]
where
    SC: StarkGenericConfig,
    Val<SC>: PrimeField32 + FieldSpecificPoseidon2Config,
    <SC as StarkGenericConfig>::Val: Poseidon2HashField,
{
    let pv: &RecursionPublicValues<Val<SC>> = proof.proofs[0].public_values.as_ref().borrow();

    let committed_values_digest = words_to_bytes(&pv.committed_value_digest);

    hash_deferred_proof(
        &prev_digest,
        &pv.riscv_vk_digest,
        &committed_values_digest.try_into().unwrap(),
    )
}
