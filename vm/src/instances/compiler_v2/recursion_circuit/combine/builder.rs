use super::super::stdin::{RecursionStdin, RecursionStdinVariable};
use crate::{
    chips::chips::riscv_cpu::MAX_CPU_LOG_DEGREE,
    compiler::{
        recursion_v2::{
            circuit::{
                challenger::{
                    CanObserveVariable, DuplexChallengerVariable, FieldChallengerVariable,
                },
                config::{BabyBearFriConfig, BabyBearFriConfigVariable, CircuitConfig},
                constraints::RecursiveVerifierConstraintFolder,
                stark::StarkVerifier,
                utils::uninit_challenger_pv,
                witness::Witnessable,
                CircuitV2Builder,
            },
            instruction::commit_public_values,
            ir::{compiler, compiler::DslIrCompiler},
            prelude::*,
            program::RecursionProgram,
        },
        word::Word,
    },
    configs::{
        config::{Com, FieldGenericConfig, StarkGenericConfig, Val},
        stark_config::bb_poseidon2::{BabyBearPoseidon2, SC_Challenge, SC_Val, SC_ValMmcs},
    },
    emulator::riscv::public_values::PublicValues,
    instances::{
        chiptype::{recursion_chiptype_v2::RecursionChipType, riscv_chiptype::RiscvChipType},
        configs::{
            recur_config::{
                FieldConfig as RiscvFC, FieldConfig as RecursionFC, StarkConfig as RecursionSC,
            },
            riscv_config::StarkConfig as RiscvSC,
        },
    },
    machine::{
        chip::ChipBehavior,
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        machine::BaseMachine,
    },
    primitives::{
        consts::{
            ADDR_NUM_BITS, DIGEST_SIZE, EMPTY, MAX_LOG_CHUNK_SIZE, MAX_LOG_NUMBER_OF_CHUNKS,
            POSEIDON_NUM_WORDS, PV_DIGEST_NUM_WORDS, RISCV_COMPRESS_DEGREE,
        },
        consts_v2::RECURSION_NUM_PVS_V2,
    },
    recursion_v2::{
        air::{
            assert_recursion_public_values_valid, embed_public_values_digest,
            recursion_public_values_digest, ChallengerPublicValues, RecursionPublicValues,
        },
        runtime::RecursionRecord,
    },
};
use itertools::{izip, Itertools};
use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_commit::{Mmcs, TwoAdicMultiplicativeCoset};
use p3_field::{FieldAlgebra, PrimeField32, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;
use std::{
    array,
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
    mem::MaybeUninit,
};

#[derive(Debug, Clone, Copy)]
pub struct RecursionCombineVerifierCircuit<FC: FieldGenericConfig, SC: StarkGenericConfig, C>(
    PhantomData<(FC, SC, C)>,
);

impl<C> RecursionCombineVerifierCircuit<RecursionFC, RecursionSC, C>
where
    C: ChipBehavior<
            Val<RecursionSC>,
            Program = RecursionProgram<Val<RecursionSC>>,
            Record = RecursionRecord<Val<RecursionSC>>,
        > + for<'a> Air<ProverConstraintFolder<'a, RecursionSC>>
        + for<'a> Air<VerifierConstraintFolder<'a, RecursionSC>>
        + for<'a> Air<RecursiveVerifierConstraintFolder<'a, RecursionFC>>,
{
    pub fn build(
        machine: &BaseMachine<RecursionSC, C>,
        input: &RecursionStdin<RecursionSC, C>,
    ) -> RecursionProgram<Val<RecursionSC>> {
        // Construct the builder.
        let mut builder = Builder::<RecursionFC>::new();
        let input = input.read(&mut builder);
        Self::build_verifier(&mut builder, machine, input);

        let operations = builder.into_operations();

        // Compile the program.
        let mut compiler = DslIrCompiler::<RiscvFC>::default();
        compiler.compile(operations)
    }
}

impl<CC, SC, C> RecursionCombineVerifierCircuit<CC, SC, C>
where
    SC: BabyBearFriConfigVariable<CC>,
    CC: CircuitConfig<F = SC::Val, EF = SC::Challenge>,
    C: ChipBehavior<
            Val<SC>,
            Program = RecursionProgram<Val<SC>>,
            Record = RecursionRecord<Val<SC>>,
        > + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>
        + for<'a> Air<RecursiveVerifierConstraintFolder<'a, CC>>,
{
    pub fn build_verifier(
        builder: &mut Builder<CC>,
        machine: &BaseMachine<SC, C>,
        input: RecursionStdinVariable<CC, SC>,
    ) {
        // Read input.
        let RecursionStdinVariable {
            vks,
            proofs,
            flag_complete,
            vk_root,
        } = input;

        // Make sure there is at least one proof.
        assert!(!vks.is_empty());
        assert_eq!(vks.len(), proofs.len());

        let zero: Felt<_> = builder.eval(CC::F::ZERO);
        let one: Felt<_> = builder.eval(CC::F::ONE);
        let zero_ext: Ext<CC::F, CC::EF> = builder.eval(zero);

        /*
        Initializations
        */

        // Public values output.
        let mut compress_public_values_stream = [zero; RECURSION_NUM_PVS_V2];
        let compress_public_values: &mut RecursionPublicValues<_> =
            compress_public_values_stream.as_mut_slice().borrow_mut();

        // Digests
        let mut committed_value_digest: [Word<Felt<_>>; PV_DIGEST_NUM_WORDS] =
            array::from_fn(|_| Word(array::from_fn(|_| builder.uninit())));
        let mut riscv_vk_digest: [Felt<_>; DIGEST_SIZE] = array::from_fn(|_| builder.uninit());

        // PC and chunk values
        let mut current_pc: Felt<_> = builder.uninit();
        let mut current_chunk: Felt<_> = builder.uninit();
        let mut current_execution_chunk: Felt<_> = builder.uninit();
        let mut contains_execution_chunk: Felt<_> = builder.eval(zero);

        // Challengers
        let mut start_reconstruct_challenger_values: ChallengerPublicValues<Felt<CC::F>> =
            unsafe { uninit_challenger_pv(builder) };
        let mut current_reconstruct_challenger_values: ChallengerPublicValues<Felt<CC::F>> =
            unsafe { uninit_challenger_pv(builder) };
        let mut base_challenger_values: ChallengerPublicValues<Felt<CC::F>> =
            unsafe { uninit_challenger_pv(builder) };

        // Address bits
        let mut current_initialize_addr_bits: [Felt<_>; ADDR_NUM_BITS] =
            array::from_fn(|_| builder.uninit());
        let mut current_finalize_addr_bits: [Felt<_>; ADDR_NUM_BITS] =
            array::from_fn(|_| builder.uninit());

        // Cumsum
        let mut global_cumulative_sum = [zero; 4];

        /*
        Verification circuits
         */
        proofs
            .iter()
            .zip(vks.iter())
            .enumerate()
            .for_each(|(i, (chunk_proof, vk))| {
                /*
                Verify chunk proof
                 */
                {
                    // Prepare a challenger.
                    let mut challenger = machine.config().challenger_variable(builder);

                    vk.observed_by(builder, &mut challenger);

                    // Observe the main commitment and public values.
                    challenger.observe_slice(
                        builder,
                        chunk_proof.public_values[0..machine.num_public_values()]
                            .iter()
                            .copied(),
                    );

                    StarkVerifier::verify_chunk(
                        builder,
                        &vk,
                        machine,
                        &mut challenger,
                        &chunk_proof,
                        &[zero_ext, zero_ext],
                    );
                }

                // Get public values and conduct sanity checks
                let current_public_values: &RecursionPublicValues<Felt<CC::F>> =
                    chunk_proof.public_values.as_slice().borrow();

                // validate digest
                assert_recursion_public_values_valid::<CC, SC>(builder, current_public_values);

                // validate vk_root
                for (expected, actual) in vk_root.iter().zip(current_public_values.vk_root.iter()) {
                    builder.assert_felt_eq(*expected, *actual);
                }

                if i == 0 {
                    /*
                    Initialize global variables
                     */

                    // PC and chunk values.
                    compress_public_values.start_pc = current_public_values.start_pc;
                    compress_public_values.start_chunk = current_public_values.start_chunk;
                    compress_public_values.start_execution_chunk =
                        current_public_values.start_execution_chunk;
                    current_execution_chunk = current_public_values.start_execution_chunk;

                    // Address bits.
                    for i in 0..ADDR_NUM_BITS {
                        compress_public_values.previous_initialize_addr_bits[i] =
                            current_public_values.previous_initialize_addr_bits[i];
                        current_initialize_addr_bits[i] =
                            current_public_values.previous_initialize_addr_bits[i];
                        compress_public_values.previous_finalize_addr_bits[i] =
                            current_public_values.previous_finalize_addr_bits[i];
                        current_finalize_addr_bits[i] =
                            current_public_values.previous_finalize_addr_bits[i];
                    }

                    // Challengers
                    base_challenger_values = current_public_values.base_challenger;
                    start_reconstruct_challenger_values =
                        current_public_values.start_reconstruct_challenger;
                    current_reconstruct_challenger_values =
                        current_public_values.start_reconstruct_challenger;

                    // Digests
                    for i in 0..DIGEST_SIZE {
                        riscv_vk_digest[i] = current_public_values.riscv_vk_digest[i];
                    }

                    for (word, current_word) in committed_value_digest
                        .iter_mut()
                        .zip_eq(current_public_values.committed_value_digest.iter())
                    {
                        for (byte, current_byte) in word.0.iter_mut().zip_eq(current_word.0.iter())
                        {
                            *byte = *current_byte;
                        }
                    }
                } else {
                    /*
                    Check current status
                     */

                    // PC and chunk numbers
                    builder.assert_felt_eq(current_pc, current_public_values.start_pc);
                    builder.assert_felt_eq(current_chunk, current_public_values.start_chunk);

                    // Address bits
                    for i in 0..ADDR_NUM_BITS {
                        builder.assert_felt_eq(
                            current_initialize_addr_bits[i],
                            current_public_values.previous_initialize_addr_bits[i],
                        );
                        builder.assert_felt_eq(
                            current_finalize_addr_bits[i],
                            current_public_values.previous_finalize_addr_bits[i],
                        );
                    }

                    // Challenger
                    for (current, expected) in base_challenger_values
                        .into_iter()
                        .zip(current_public_values.base_challenger)
                    {
                        builder.assert_felt_eq(current, expected);
                    }

                    // Assert that the current challenger matches the start reconstruct challenger.
                    for (current, expected) in current_reconstruct_challenger_values
                        .into_iter()
                        .zip(current_public_values.start_reconstruct_challenger)
                    {
                        builder.assert_felt_eq(current, expected);
                    }

                    // Digests
                    for i in 0..DIGEST_SIZE {
                        builder.assert_felt_eq(
                            riscv_vk_digest[i],
                            current_public_values.riscv_vk_digest[i],
                        );
                    }
                }

                // todo: Optimize
                /*
                Execution chunk
                 */
                {
                    // Flag is boolean.
                    builder.assert_felt_eq(
                        current_public_values.contains_execution_chunk
                            * (one - current_public_values.contains_execution_chunk),
                        zero,
                    );
                    // A flag to indicate whether the first execution chunk has been seen. We have:
                    // - `is_first_execution_chunk_seen`  = current_contains_execution_chunk &&
                    //                                     !execution_chunk_seen_before.
                    // Since `contains_execution_chunk` is the boolean flag used to denote if we have
                    // seen an execution chunk, we can use it to denote if we have seen an execution
                    // chunk before.
                    let is_first_execution_chunk_seen: Felt<_> = builder.eval(
                        current_public_values.contains_execution_chunk
                            * (one - contains_execution_chunk),
                    );

                    // If this is the first execution chunk, then we update the start execution chunk
                    // and the `execution_chunk` values.
                    compress_public_values.start_execution_chunk = builder.eval(
                        current_public_values.start_execution_chunk * is_first_execution_chunk_seen
                            + compress_public_values.start_execution_chunk
                                * (one - is_first_execution_chunk_seen),
                    );
                    current_execution_chunk = builder.eval(
                        current_public_values.start_execution_chunk * is_first_execution_chunk_seen
                            + current_execution_chunk * (one - is_first_execution_chunk_seen),
                    );

                    // If this is an execution chunk, make the assertion that the value is consistent.
                    builder.assert_felt_eq(
                        current_public_values.contains_execution_chunk
                            * (current_execution_chunk
                                - current_public_values.start_execution_chunk),
                        zero,
                    );
                }

                // todo: optimize
                /*
                Digest constraints.
                 */
                {
                    // If `committed_value_digest` is not zero, then `public_values.committed_value_digest
                    // should be the current.

                    // Set a flags to indicate whether `committed_value_digest` is non-zero. The flags
                    // are given by the elements of the array, and they will be used as filters to
                    // constrain the equality.
                    let mut is_non_zero_flags = vec![];
                    for word in committed_value_digest {
                        for byte in word {
                            is_non_zero_flags.push(byte);
                        }
                    }

                    // Using the flags, we can constrain the equality.
                    for is_non_zero in is_non_zero_flags {
                        for (word_current, word_public) in committed_value_digest
                            .into_iter()
                            .zip(current_public_values.committed_value_digest)
                        {
                            for (byte_current, byte_public) in
                                word_current.into_iter().zip(word_public)
                            {
                                builder.assert_felt_eq(
                                    is_non_zero * (byte_current - byte_public),
                                    zero,
                                );
                            }
                        }
                    }

                    // Update the committed value digest.
                    for (word, current_word) in committed_value_digest
                        .iter_mut()
                        .zip_eq(current_public_values.committed_value_digest.iter())
                    {
                        for (byte, current_byte) in word.0.iter_mut().zip_eq(current_word.0.iter())
                        {
                            *byte = *current_byte;
                        }
                    }
                }

                /*
                Update global variables
                 */

                // PC and chunk numbers
                current_pc = current_public_values.next_pc;
                current_chunk = current_public_values.next_chunk;

                // Execution chunk flag
                contains_execution_chunk = builder.eval(
                    contains_execution_chunk
                        + current_public_values.contains_execution_chunk
                            * (SymbolicFelt::ONE - contains_execution_chunk),
                );

                // Execution chunk value
                current_execution_chunk = builder.eval(
                    current_public_values.next_execution_chunk
                        * current_public_values.contains_execution_chunk
                        + current_execution_chunk
                            * (SymbolicFelt::ONE - current_public_values.contains_execution_chunk),
                );

                // Address bits.
                for i in 0..ADDR_NUM_BITS {
                    current_initialize_addr_bits[i] =
                        current_public_values.last_initialize_addr_bits[i];
                    current_finalize_addr_bits[i] =
                        current_public_values.last_finalize_addr_bits[i];
                }

                // Cumsum
                for (sum_element, current_sum_element) in global_cumulative_sum
                    .iter_mut()
                    .zip_eq(current_public_values.cumulative_sum.iter())
                {
                    *sum_element = builder.eval(*sum_element + *current_sum_element);
                }
            });

        // for (i, (vk, chunk_proof)) in vks_and_proofs.into_iter().enumerate() {
        //
        // }

        /*
        Completeness check
         */
        // Flag is boolean.
        builder.assert_felt_eq(flag_complete * (flag_complete - one), zero);

        // Assert that `next_pc` is equal to zero (so program execution has completed)
        builder.assert_felt_eq(flag_complete * current_pc, zero);

        // Assert that start shard is equal to 1.
        builder.assert_felt_eq(
            flag_complete * (compress_public_values.start_chunk - one),
            zero,
        );

        // Should contain execution chunk
        builder.assert_felt_eq(flag_complete * (contains_execution_chunk - one), zero);
        // Start execution chunk is one
        builder.assert_felt_eq(
            flag_complete * (compress_public_values.start_execution_chunk - one),
            zero,
        );

        // Assert that the cumulative sum is zero.
        for b in global_cumulative_sum.iter() {
            builder.assert_felt_eq(flag_complete * *b, zero);
        }

        /*
        Update public values
         */
        compress_public_values.next_pc = current_pc;
        compress_public_values.next_chunk = current_chunk;
        compress_public_values.next_execution_chunk = current_execution_chunk;
        compress_public_values.contains_execution_chunk = contains_execution_chunk;

        compress_public_values.last_initialize_addr_bits = current_initialize_addr_bits;
        compress_public_values.last_finalize_addr_bits = current_finalize_addr_bits;

        compress_public_values.base_challenger = base_challenger_values;
        compress_public_values.start_reconstruct_challenger = start_reconstruct_challenger_values;
        compress_public_values.end_reconstruct_challenger = current_reconstruct_challenger_values;

        compress_public_values.vk_root = vk_root;
        compress_public_values.flag_complete = flag_complete;
        compress_public_values.cumulative_sum = global_cumulative_sum;

        compress_public_values.committed_value_digest = committed_value_digest;
        compress_public_values.riscv_vk_digest = riscv_vk_digest;
        compress_public_values.digest =
            recursion_public_values_digest::<CC, SC>(builder, compress_public_values);

        /*
        Commit public values
         */
        SC::commit_recursion_public_values(builder, *compress_public_values);
    }
}
