use super::super::stdin::{RecursionStdin, RecursionStdinVariable};
use crate::{
    compiler::{
        recursion::{
            circuit::{
                builder::CircuitBuilder,
                challenger::CanObserveVariable,
                config::{CircuitConfig, FieldFriConfigVariable},
                constraints::RecursiveVerifierConstraintFolder,
                stark::StarkVerifier,
                types::FriProofVariable,
                witness::Witnessable,
            },
            ir::compiler::DslIrCompiler,
            prelude::*,
            program::RecursionProgram,
        },
        word::Word,
    },
    configs::config::{Challenge, Com, FieldGenericConfig, PcsProof, StarkGenericConfig, Val},
    emulator::recursion::{
        emulator::RecursionRecord,
        public_values::{
            assert_deferred_digest_complete, assert_recursion_public_values_valid,
            recursion_public_values_digest, RecursionPublicValues,
        },
    },
    machine::{chip::ChipBehavior, machine::BaseMachine},
    primitives::consts::{
        ADDR_NUM_BITS, DIGEST_SIZE, EXTENSION_DEGREE, PV_DIGEST_NUM_WORDS, RECURSION_NUM_PVS,
    },
};
use itertools::Itertools;
use p3_air::Air;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::{extension::BinomiallyExtendable, FieldAlgebra, PrimeField32, TwoAdicField};
use std::{
    array,
    borrow::{Borrow, BorrowMut},
    fmt::Debug,
    marker::PhantomData,
};

#[derive(Debug, Clone, Copy)]
pub struct CombineVerifierCircuit<FC: FieldGenericConfig, SC: StarkGenericConfig, C>(
    PhantomData<(FC, SC, C)>,
);

impl<F, CC, SC, C> CombineVerifierCircuit<CC, SC, C>
where
    F: PrimeField32
        + BinomiallyExtendable<EXTENSION_DEGREE>
        + TwoAdicField
        + Witnessable<CC, WitnessVariable = Felt<CC::F>>,
    CC: CircuitConfig<N = F, F = F, EF = Challenge<SC>, Bit = Felt<F>> + Debug,
    CC::EF: Witnessable<CC, WitnessVariable = Ext<CC::F, CC::EF>>,
    SC: FieldFriConfigVariable<CC, Val = F, Domain = TwoAdicMultiplicativeCoset<F>>,
    Com<SC>: Witnessable<CC, WitnessVariable = SC::DigestVariable>,
    PcsProof<SC>: Witnessable<CC, WitnessVariable = FriProofVariable<CC, SC>>,
    C: ChipBehavior<
            Val<SC>,
            Program = RecursionProgram<Val<SC>>,
            Record = RecursionRecord<Val<SC>>,
        > + for<'a> Air<RecursiveVerifierConstraintFolder<'a, CC>>,
{
    pub fn build(
        machine: &BaseMachine<SC, C>,
        input: &RecursionStdin<SC, C>,
    ) -> RecursionProgram<Val<SC>> {
        // Construct the builder.
        let mut builder = Builder::<CC>::new();
        let input = input.read(&mut builder);
        Self::build_verifier(&mut builder, machine, input);

        let operations = builder.into_operations();

        // Compile the program.
        let mut compiler = DslIrCompiler::<CC>::default();
        compiler.compile(operations)
    }
}

impl<CC, SC, C> CombineVerifierCircuit<CC, SC, C>
where
    CC: CircuitConfig,
    CC::F: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE> + TwoAdicField,
    SC: FieldFriConfigVariable<
        CC,
        Val = CC::F,
        Challenge = CC::EF,
        Domain = TwoAdicMultiplicativeCoset<Val<SC>>,
    >,
    C: ChipBehavior<
            Val<SC>,
            Program = RecursionProgram<Val<SC>>,
            Record = RecursionRecord<Val<SC>>,
        > + for<'a> Air<RecursiveVerifierConstraintFolder<'a, CC>>,
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

        /*
        Initializations
        */

        // Public values output.
        let mut compress_public_values_stream = [zero; RECURSION_NUM_PVS];
        let compress_public_values: &mut RecursionPublicValues<_> =
            compress_public_values_stream.as_mut_slice().borrow_mut();

        // Digests
        let mut committed_value_digest: [Word<Felt<_>>; PV_DIGEST_NUM_WORDS] =
            array::from_fn(|_| Word(array::from_fn(|_| builder.uninit())));
        let mut deferred_proofs_digest: [Felt<_>; DIGEST_SIZE] =
            array::from_fn(|_| builder.uninit());
        let mut riscv_vk_digest: [Felt<_>; DIGEST_SIZE] = array::from_fn(|_| builder.uninit());
        let mut reconstruct_deferred_digest: [Felt<_>; DIGEST_SIZE] =
            array::from_fn(|_| builder.uninit());

        // PC and chunk values
        let mut current_pc: Felt<_> = builder.uninit();
        let mut current_chunk: Felt<_> = builder.uninit();
        let mut current_execution_chunk: Felt<_> = builder.uninit();
        let mut contains_execution_chunk: Felt<_> = builder.eval(zero);

        // Address bits
        let mut current_initialize_addr_bits: [Felt<_>; ADDR_NUM_BITS] =
            array::from_fn(|_| builder.uninit());
        let mut current_finalize_addr_bits: [Felt<_>; ADDR_NUM_BITS] =
            array::from_fn(|_| builder.uninit());

        // Cumsum
        let mut global_cumulative_sums = Vec::new();

        /*
        Verification circuits
         */
        proofs
            .iter()
            .zip(vks.iter())
            .enumerate()
            .for_each(|(i, (chunk_proof, vk))| {
                // Prepare a challenger.
                let mut challenger = {
                    let mut challenger = machine.config().challenger_variable(builder);
                    vk.observed_by(builder, &mut challenger);

                    challenger.observe_slice(
                        builder,
                        chunk_proof.public_values[0..machine.num_public_values()]
                            .iter()
                            .copied(),
                    );

                    challenger
                };

                /*
                Verify chunk proof
                 */
                StarkVerifier::verify_chunk(builder, vk, machine, &mut challenger, chunk_proof);

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

                    // Digests
                    riscv_vk_digest[..DIGEST_SIZE]
                        .copy_from_slice(&current_public_values.riscv_vk_digest[..DIGEST_SIZE]);
                    // Initialize the start of deferred digests.
                    for i in 0..DIGEST_SIZE {
                        reconstruct_deferred_digest[i] =
                            current_public_values.start_reconstruct_deferred_digest[i];
                        compress_public_values.start_reconstruct_deferred_digest[i] =
                            current_public_values.start_reconstruct_deferred_digest[i];
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
                    for (digest, current_digest) in deferred_proofs_digest
                        .iter_mut()
                        .zip_eq(current_public_values.deferred_proofs_digest.iter())
                    {
                        *digest = *current_digest;
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

                    // Digests
                    for i in 0..DIGEST_SIZE {
                        builder.assert_felt_eq(
                            riscv_vk_digest[i],
                            current_public_values.riscv_vk_digest[i],
                        );
                    }
                }

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

                    //  If `deferred_proofs_digest` is not zero, then the current value should be
                    // `public_values.deferred_proofs_digest`. We will use a similar approach as above.
                    let mut is_non_zero_flags = vec![];
                    for element in deferred_proofs_digest {
                        is_non_zero_flags.push(element);
                    }

                    for is_non_zero in is_non_zero_flags {
                        for (digest_current, digest_public) in deferred_proofs_digest
                            .into_iter()
                            .zip(current_public_values.deferred_proofs_digest)
                        {
                            builder.assert_felt_eq(
                                is_non_zero * (digest_current - digest_public),
                                zero,
                            );
                        }
                    }

                    // Update the deferred proofs digest.
                    for (digest, current_digest) in deferred_proofs_digest
                        .iter_mut()
                        .zip_eq(current_public_values.deferred_proofs_digest.iter())
                    {
                        *digest = *current_digest;
                    }

                    // Assert that the start deferred digest is equal to the current deferred digest.
                    for (digest, current_digest) in reconstruct_deferred_digest.iter().zip_eq(
                        current_public_values
                            .start_reconstruct_deferred_digest
                            .iter(),
                    ) {
                        builder.assert_felt_eq(*digest, *current_digest);
                    }

                    // Update the reconstruct deferred proof digest.
                    for (digest, current_digest) in reconstruct_deferred_digest
                        .iter_mut()
                        .zip_eq(current_public_values.end_reconstruct_deferred_digest.iter())
                    {
                        *digest = *current_digest;
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
                current_initialize_addr_bits[..ADDR_NUM_BITS].copy_from_slice(
                    &current_public_values.last_initialize_addr_bits[..ADDR_NUM_BITS],
                );
                current_finalize_addr_bits[..ADDR_NUM_BITS].copy_from_slice(
                    &current_public_values.last_finalize_addr_bits[..ADDR_NUM_BITS],
                );

                // Cumsum
                global_cumulative_sums.push(current_public_values.global_cumulative_sum);
            });

        /*
        Completeness check
         */
        // Flag is boolean.
        builder.assert_felt_eq(flag_complete * (flag_complete - one), zero);

        // Assert that `next_pc` is equal to zero (so program execution has completed)
        builder.assert_felt_eq(flag_complete * current_pc, zero);

        // Assert that start chunk is equal to 1.
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

        let global_cumulative_sum = builder.sum_digest(global_cumulative_sums);

        /*
        Update public values
         */
        compress_public_values.next_pc = current_pc;
        compress_public_values.next_chunk = current_chunk;
        compress_public_values.next_execution_chunk = current_execution_chunk;
        compress_public_values.contains_execution_chunk = contains_execution_chunk;

        compress_public_values.last_initialize_addr_bits = current_initialize_addr_bits;
        compress_public_values.last_finalize_addr_bits = current_finalize_addr_bits;

        compress_public_values.vk_root = vk_root;
        compress_public_values.flag_complete = flag_complete;
        compress_public_values.global_cumulative_sum = global_cumulative_sum;

        compress_public_values.committed_value_digest = committed_value_digest;
        compress_public_values.deferred_proofs_digest = deferred_proofs_digest;
        compress_public_values.end_reconstruct_deferred_digest = reconstruct_deferred_digest;
        compress_public_values.riscv_vk_digest = riscv_vk_digest;

        // Deferred Proof Digest Completeness Verification
        assert_deferred_digest_complete(builder, compress_public_values, flag_complete);
        compress_public_values.digest =
            recursion_public_values_digest::<CC, SC>(builder, compress_public_values);

        /*
        Commit public values
         */
        SC::commit_recursion_public_values(builder, *compress_public_values);
    }
}
