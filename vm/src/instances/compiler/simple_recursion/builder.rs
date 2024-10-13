use std::{
    array,
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
};

use super::utils::{assert_complete, commit_public_values};
use crate::{
    compiler::{
        recursion::{
            config::InnerConfig,
            ir::{Array, Builder, Config, Ext, ExtConst, Felt, Var},
            prelude::{DslVariable, *},
            program::RecursionProgram,
            program_builder::{
                challenger::{CanObserveVariable, DuplexChallengerVariable},
                fri::TwoAdicFriPcsVariable,
                hints::Hintable,
                stark::{StarkVerifier, EMPTY},
                types::{BaseProofVariable, VerifyingKeyVariable},
                utils::{
                    const_fri_config, felt2var, get_challenger_public_values, hash_vkey, var2felt,
                },
            },
        },
        word::Word,
    },
    configs::{
        bb_poseidon2::BabyBearPoseidon2,
        config::{Com, StarkGenericConfig, Val},
    },
    emulator::riscv::public_values::{PublicValues, POSEIDON_NUM_WORDS},
    instances::{chiptype::fib_chiptype::FibChipType, machine::simple_machine::SimpleMachine},
    machine::{
        chip::ChipBehavior,
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::BaseVerifyingKey,
        machine::MachineBehavior,
        proof::BaseProof,
    },
    primitives::{consts::WORD_SIZE, types::RecursionProgramType},
    recursion::core::{
        air::{RecursionPublicValues, RECURSIVE_PROOF_NUM_PV_ELTS},
        runtime::DIGEST_SIZE,
    },
};
use itertools::Itertools;
use p3_air::Air;
use p3_baby_bear::BabyBear;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::{AbstractField, PrimeField32, TwoAdicField};

// TODO: Move
const MAX_CPU_LOG_DEGREE: usize = 22;

/// A program for recursively verifying a batch of Pico proofs.
#[derive(Debug, Clone, Copy)]
pub struct SimpleMachineRecursiveVerifier<C: Config, SC: StarkGenericConfig> {
    _phantom: PhantomData<(C, SC)>,
}

pub struct SimpleMachineRecursionMemoryLayout<'a, SC: StarkGenericConfig, A: ChipBehavior<SC::Val>>
where
    SC: StarkGenericConfig,
    A: ChipBehavior<Val<SC>>
        + for<'b> Air<ProverConstraintFolder<'b, SC>>
        + for<'b> Air<VerifierConstraintFolder<'b, SC>>,
{
    pub vk: &'a BaseVerifyingKey<SC>,
    pub machine: &'a SimpleMachine<SC, A>,
    pub base_proofs: Vec<BaseProof<SC>>,
    pub leaf_challenger: &'a SC::Challenger,
    pub initial_reconstruct_challenger: SC::Challenger,
    pub is_complete: bool,
}

#[derive(DslVariable, Clone)]
pub struct SimpleMachineRecursionMemoryLayoutVariable<C: Config> {
    pub vk: VerifyingKeyVariable<C>,
    pub base_proofs: Array<C, BaseProofVariable<C>>,
    pub leaf_challenger: DuplexChallengerVariable<C>,
    pub initial_reconstruct_challenger: DuplexChallengerVariable<C>,
    pub is_complete: Var<C::N>,
}

impl SimpleMachineRecursiveVerifier<InnerConfig, BabyBearPoseidon2> {
    /// Create a new instance of the program for the [BabyBearPoseidon2] config.
    pub fn build(
        machine: &SimpleMachine<BabyBearPoseidon2, FibChipType<BabyBear>>,
    ) -> RecursionProgram<BabyBear> {
        let mut builder = Builder::<InnerConfig>::new(RecursionProgramType::Core);

        let input: SimpleMachineRecursionMemoryLayoutVariable<_> = builder.uninit();
        SimpleMachineRecursionMemoryLayout::<BabyBearPoseidon2, FibChipType<_>>::witness(
            &input,
            &mut builder,
        );

        let pcs = TwoAdicFriPcsVariable {
            config: const_fri_config(&mut builder, machine.config().pcs().fri_config()),
        };
        Self::build_verifier_circuit(&mut builder, &pcs, machine, input);

        builder.halt();

        builder.compile_program()
    }
}

// TODO-Alan: refactor and clean up
impl<C: Config, SC: StarkGenericConfig> SimpleMachineRecursiveVerifier<C, SC>
where
    C::F: PrimeField32 + TwoAdicField,
    SC: StarkGenericConfig<
        Val = C::F,
        Challenge = C::EF,
        Domain = TwoAdicMultiplicativeCoset<C::F>,
    >,
    Com<SC>: Into<[SC::Val; DIGEST_SIZE]>,
{
    /// Verify a batch of Pico chunk proofs and aggregate their public values.
    ///
    /// This program represents a first recursive step in the verification of a Pico proof
    /// consisting of one or more chunks. Each chunk proof is verified and its public values are
    /// aggregated into a single set representing the start and end state of the program execution
    /// across all chunks.
    ///
    /// # Constraints
    ///
    /// ## Verifying the STARK proofs.
    /// For each chunk, the verifier asserts the correctness of the STARK proof which is composed
    /// of verifying the FRI proof for openings and verifying the constraints.
    ///
    /// ## Aggregating the chunk public values.
    /// See [PicoProver::verify] for the verification algorithm of a complete Pico proof. In this
    /// function, we are aggregating several chunk proofs and attesting to an aggregated state which
    /// represents all the chunks.
    ///
    /// ## The leaf challenger.
    /// A key difference between the recursive tree verification and the complete one in
    /// [PicoProver::verify] is that the recursive verifier has no way of reconstructing the
    /// challenger only from a part of the chunk proof. Therefore, the value of the leaf challenger
    /// is witnessed in the program and the verifier asserts correctness given this challenger.
    /// In the course of the recursive verification, the challenger is reconstructed by observing
    /// the commitments one by one, and in the final step, the challenger is asserted to be the same
    /// as the one witnessed here.
    pub fn build_verifier_circuit(
        builder: &mut Builder<C>,
        pcs: &TwoAdicFriPcsVariable<C>,
        machine: &SimpleMachine<SC, FibChipType<SC::Val>>,
        input: SimpleMachineRecursionMemoryLayoutVariable<C>,
    ) {
        // Read input.
        let SimpleMachineRecursionMemoryLayoutVariable {
            vk,
            base_proofs,
            leaf_challenger,
            initial_reconstruct_challenger,
            is_complete,
        } = input;

        // Initialize chunk variables.
        // let initial_chunk = builder.uninit();
        // let current_chunk = builder.uninit();

        // // Initialize execution chunk variables.
        // let initial_execution_chunk = builder.uninit();
        // let current_execution_chunk = builder.uninit();

        // Initialize program counter variables.
        // let start_pc = builder.uninit();
        // let current_pc = builder.uninit();

        // Initialize memory initialization and finalization variables.
        // let initial_previous_init_addr_bits: [Felt<_>; 32] = array::from_fn(|_| builder.uninit());
        // let initial_previous_finalize_addr_bits: [Felt<_>; 32] =
        //     array::from_fn(|_| builder.uninit());
        // let current_init_addr_bits: [Felt<_>; 32] = array::from_fn(|_| builder.uninit());
        // let current_finalize_addr_bits: [Felt<_>; 32] = array::from_fn(|_| builder.uninit());

        // Initialize the exit code variable.
        // let exit_code: Felt<_> = builder.uninit();

        // Initialize the public values digest.
        // let committed_value_digest: [Word<Felt<_>>; PV_DIGEST_NUM_WORDS] =
        //     array::from_fn(|_| Word(array::from_fn(|_| builder.uninit())));

        // Initialize the challenger variables.
        let leaf_challenger_public_values = get_challenger_public_values(builder, &leaf_challenger);
        let mut reconstruct_challenger: DuplexChallengerVariable<_> =
            initial_reconstruct_challenger.copy(builder);

        // Initialize the cumulative sum.
        let cumulative_sum: Ext<_, _> = builder.eval(C::EF::zero().cons());

        // Assert that the number of proofs is not zero.
        // builder.assert_usize_eq(base_proofs.len(), 1);
        builder.assert_usize_ne(base_proofs.len(), 0);

        // Verify proofs, validate transitions, and update accumulation variables.
        builder.range(0, base_proofs.len()).for_each(|i, builder| {
            // Load the proof.
            let proof = builder.get(&base_proofs, i);

            // Compute some flags about which chips exist in the chunk.
            // let contains_cpu: Var<_> = builder.eval(C::N::zero());
            // let contains_memory_init: Var<_> = builder.eval(C::N::zero());
            // let contains_memory_finalize: Var<_> = builder.eval(C::N::zero());
            // for (i, chip) in machine.chips().iter().enumerate() {
            //     let index = builder.get(&proof.sorted_idxs, i);
            //     if chip.name() == "Cpu" {
            //         builder
            //             .if_ne(index, C::N::from_canonical_usize(EMPTY))
            //             .then(|builder| {
            //                 builder.assign(contains_cpu, C::N::one());
            //             });
            //     } else if chip.name() == "MemoryInit" {
            //         builder
            //             .if_ne(index, C::N::from_canonical_usize(EMPTY))
            //             .then(|builder| {
            //                 builder.assign(contains_memory_init, C::N::one());
            //             });
            //     } else if chip.name() == "MemoryFinalize" {
            //         builder
            //             .if_ne(index, C::N::from_canonical_usize(EMPTY))
            //             .then(|builder| {
            //                 builder.assign(contains_memory_finalize, C::N::one());
            //             });
            //     }
            // }

            // Extract public values.
            let mut pv_elements = Vec::new();
            for i in 0..machine.num_public_values() {
                let element = builder.get(&proof.public_values, i);
                pv_elements.push(element);
            }
            let public_values: &PublicValues<Word<Felt<_>>, Felt<_>> =
                pv_elements.as_slice().borrow();

            // If this is the first proof in the batch, initialize the variables.
            builder.if_eq(i, C::N::zero()).then(|builder| {
                // Chunk.
                // builder.assign(initial_chunk, public_values.chunk);
                // builder.assign(current_chunk, public_values.chunk);

                // Execution chunk.
                // builder.assign(initial_execution_chunk, public_values.execution_chunk);
                // builder.assign(current_execution_chunk, public_values.execution_chunk);

                // Program counter.
                // builder.assign(start_pc, public_values.start_pc);
                // builder.assign(current_pc, public_values.start_pc);

                // Memory initialization & finalization.
                // for ((bit, pub_bit), first_bit) in current_init_addr_bits
                //     .iter()
                //     .zip(public_values.previous_init_addr_bits.iter())
                //     .zip(initial_previous_init_addr_bits.iter())
                // {
                //     builder.assign(*bit, *pub_bit);
                //     builder.assign(*first_bit, *pub_bit);
                // }
                // for ((bit, pub_bit), first_bit) in current_finalize_addr_bits
                //     .iter()
                //     .zip(public_values.previous_finalize_addr_bits.iter())
                //     .zip(initial_previous_finalize_addr_bits.iter())
                // {
                //     builder.assign(*bit, *pub_bit);
                //     builder.assign(*first_bit, *pub_bit);
                // }
                //
                // // Exit code.
                // builder.assign(exit_code, public_values.exit_code);
                //
                // // Committed public values digests.
                // for (word, first_word) in committed_value_digest
                //     .iter()
                //     .zip_eq(public_values.committed_value_digest.iter())
                // {
                //     for (byte, first_byte) in word.0.iter().zip_eq(first_word.0.iter()) {
                //         builder.assign(*byte, *first_byte);
                //     }
                // }
            });

            // If the chunk is the first chunk, assert that the initial challenger is equal to a
            // fresh challenger observing the verifier key and the initial pc.
            // let chunk = felt2var(builder, public_values.chunk);
            // TODO: Enable for multiple chunks
            // builder.if_eq(chunk, C::N::one()).then(|builder| {
            let mut first_initial_challenger = DuplexChallengerVariable::new(builder);
            first_initial_challenger.observe(builder, vk.commitment.clone());
            first_initial_challenger.observe(builder, vk.pc_start);
            initial_reconstruct_challenger.assert_eq(builder, &first_initial_challenger);
            // });

            // Verify the chunk.
            //
            // Do not verify the cumulative sum here, since the permutation challenge is shared
            // between all chunks.
            let mut challenger = leaf_challenger.copy(builder);

            StarkVerifier::<C, SC>::verify_chunk(
                builder,
                &vk,
                pcs,
                machine,
                &mut challenger,
                &proof,
                false,
            );

            // First chunk has a "CPU" constraint.
            {
                // TODO: Enable for multiple chunks
                // builder.if_eq(chunk, C::N::one()).then(|builder| {
                // builder.assert_var_eq(contains_cpu, C::N::one());
                // });
            }

            // CPU log degree bound check constraints.
            // {
            //     for (i, chip) in machine.chips().iter().enumerate() {
            //         if chip.name() == "Cpu" {
            //             builder.if_eq(contains_cpu, C::N::one()).then(|builder| {
            //                 let index = builder.get(&proof.sorted_idxs, i);
            //                 let cpu_log_degree =
            //                     builder.get(&proof.opened_values.chips, index).log_main_degree;
            //                 let cpu_log_degree_lt_max: Var<_> = builder.eval(C::N::zero());
            //                 builder
            //                     .range(0, MAX_CPU_LOG_DEGREE + 1)
            //                     .for_each(|j, builder| {
            //                         builder.if_eq(j, cpu_log_degree).then(|builder| {
            //                             builder.assign(cpu_log_degree_lt_max, C::N::one());
            //                         });
            //                     });
            //                 builder.assert_var_eq(cpu_log_degree_lt_max, C::N::one());
            //             });
            //         }
            //     }
            // }

            // Chunk constraints.
            {
                // Assert that the chunk of the proof is equal to the current chunk.
                // builder.assert_felt_eq(current_chunk, public_values.chunk);

                // Increment the current chunk by one.
                // builder.assign(current_chunk, current_chunk + C::F::one());
            }

            // Execution chunk constraints.
            // let execution_chunk = felt2var(builder, public_values.execution_chunk);
            {
                // Assert that the chunk of the proof is equal to the current chunk.
                // builder.if_eq(contains_cpu, C::N::one()).then(|builder| {
                //     builder.assert_felt_eq(current_execution_chunk, public_values.execution_chunk);
                // });

                // If the chunk has a "CPU" chip, then the execution chunk should be incremented by
                // 1.
                // builder.if_eq(contains_cpu, C::N::one()).then(|builder| {
                //     builder.assign(
                //         current_execution_chunk,
                //         current_execution_chunk + C::F::one(),
                //     );
                // });
            }

            // Program counter constraints.
            {
                // If it's the first chunk (which is the first execution chunk), then the start_pc
                // should be vk.pc_start.
                // builder.if_eq(chunk, C::N::one()).then(|builder| {
                //     builder.assert_felt_eq(public_values.start_pc, vk.pc_start);
                // });

                // Assert that the start_pc of the proof is equal to the current pc.
                // builder.assert_felt_eq(current_pc, public_values.start_pc);

                // If it's not a chunk with "CPU", then assert that the start_pc equals the next_pc.
                // builder.if_ne(contains_cpu, C::N::one()).then(|builder| {
                //     builder.assert_felt_eq(public_values.start_pc, public_values.next_pc);
                // });

                // // If it's a chunk with "CPU", then assert that the start_pc is not zero.
                // builder.if_eq(contains_cpu, C::N::one()).then(|builder| {
                //     builder.assert_felt_ne(public_values.start_pc, C::F::zero());
                // });

                // Update current_pc to be the end_pc of the current proof.
                // builder.assign(current_pc, public_values.next_pc);
            }

            // Exit code constraints.
            {
                // Assert that the exit code is zero (success) for all proofs.
                // builder.assert_felt_eq(exit_code, C::F::zero());
            }

            // Memory initialization & finalization constraints.
            {
                // Assert that `init_addr_bits` and `finalize_addr_bits` are zero for the first
                // execution chunk.
                // TODO: Enable for multiple chunks
                // builder.if_eq(execution_chunk, C::N::one()).then(|builder| {
                // Assert that the MemoryInitialize address bits are zero.
                // for bit in current_init_addr_bits.iter() {
                //     builder.assert_felt_eq(*bit, C::F::zero());
                // }

                // Assert that the MemoryFinalize address bits are zero.
                // for bit in current_finalize_addr_bits.iter() {
                //     builder.assert_felt_eq(*bit, C::F::zero());
                // }
                // });

                // Assert that the MemoryInitialize address bits match the current loop variable.
                // for (bit, current_bit) in current_init_addr_bits
                //     .iter()
                //     .zip_eq(public_values.previous_init_addr_bits.iter())
                // {
                //     builder.assert_felt_eq(*bit, *current_bit);
                // }

                // Assert that the MemoryFinalize address bits match the current loop variable.
                // for (bit, current_bit) in current_finalize_addr_bits
                //     .iter()
                //     .zip_eq(public_values.previous_finalize_addr_bits.iter())
                // {
                //     builder.assert_felt_eq(*bit, *current_bit);
                // }

                // Assert that if MemoryInit is not present, then the address bits are the same.
                // builder
                //     .if_ne(contains_memory_init, C::N::one())
                //     .then(|builder| {
                //         for (prev_bit, last_bit) in public_values
                //             .previous_init_addr_bits
                //             .iter()
                //             .zip_eq(public_values.last_init_addr_bits.iter())
                //         {
                //             builder.assert_felt_eq(*prev_bit, *last_bit);
                //         }
                //     });

                // Assert that if MemoryFinalize is not present, then the address bits are the same.
                // builder
                //     .if_ne(contains_memory_finalize, C::N::one())
                //     .then(|builder| {
                //         for (prev_bit, last_bit) in public_values
                //             .previous_finalize_addr_bits
                //             .iter()
                //             .zip_eq(public_values.last_finalize_addr_bits.iter())
                //         {
                //             builder.assert_felt_eq(*prev_bit, *last_bit);
                //         }
                //     });

                // Update the MemoryInitialize address bits.
                // for (bit, pub_bit) in current_init_addr_bits
                //     .iter()
                //     .zip(public_values.last_init_addr_bits.iter())
                // {
                //     builder.assign(*bit, *pub_bit);
                // }

                // Update the MemoryFinalize address bits.
                // for (bit, pub_bit) in current_finalize_addr_bits
                //     .iter()
                //     .zip(public_values.last_finalize_addr_bits.iter())
                // {
                //     builder.assign(*bit, *pub_bit);
                // }
            }

            // Digest constraints.
            {
                // If `committed_value_digest` is not zero, then `public_values.committed_value_digest
                // should be the current value.
                // let is_zero: Var<_> = builder.eval(C::N::one());
                // #[allow(clippy::needless_range_loop)]
                // for i in 0..committed_value_digest.len() {
                //     for j in 0..WORD_SIZE {
                //         let d = felt2var(builder, committed_value_digest[i][j]);
                //         builder.if_ne(d, C::N::zero()).then(|builder| {
                //             builder.assign(is_zero, C::N::zero());
                //         });
                //     }
                // }
                // builder.if_eq(is_zero, C::N::zero()).then(|builder| {
                //     #[allow(clippy::needless_range_loop)]
                //     for i in 0..committed_value_digest.len() {
                //         for j in 0..WORD_SIZE {
                //             builder.assert_felt_eq(
                //                 committed_value_digest[i][j],
                //                 public_values.committed_value_digest[i][j],
                //             );
                //         }
                //     }
                // });
                //
                // // If it's not a chunk with "CPU", then the committed value digest should not
                // // change.
                // builder.if_ne(contains_cpu, C::N::one()).then(|builder| {
                //     #[allow(clippy::needless_range_loop)]
                //     for i in 0..committed_value_digest.len() {
                //         for j in 0..WORD_SIZE {
                //             builder.assert_felt_eq(
                //                 committed_value_digest[i][j],
                //                 public_values.committed_value_digest[i][j],
                //             );
                //         }
                //     }
                // });
                //
                // // Update the committed value digest.
                // #[allow(clippy::needless_range_loop)]
                // for i in 0..committed_value_digest.len() {
                //     for j in 0..WORD_SIZE {
                //         builder.assign(
                //             committed_value_digest[i][j],
                //             public_values.committed_value_digest[i][j],
                //         );
                //     }
                // }
            }

            // Verify that the number of chunks is not too large.
            // builder.range_check_f(public_values.chunk, 16);

            // Update the reconstruct challenger.
            reconstruct_challenger.observe(builder, proof.commitment.main_commit.clone());
            for j in 0..machine.num_public_values() {
                let element = builder.get(&proof.public_values, j);
                reconstruct_challenger.observe(builder, element);
            }

            // Cumulative sum is updated by sums of all chips.
            // TODO: This should be enabled when verifying multiple chunks
            let opened_values = proof.opened_values.chips;
            builder
                .range(0, opened_values.len())
                .for_each(|k, builder| {
                    let values = builder.get(&opened_values, k);
                    let sum = values.cumulative_sum;
                    builder.assign(cumulative_sum, cumulative_sum + sum);
                });
        });

        // Write all values to the public values struct and commit to them.
        {
            // Compute the vk digest.
            let vk_digest = hash_vkey(builder, &vk);
            let vk_digest: [Felt<_>; DIGEST_SIZE] = array::from_fn(|i| builder.get(&vk_digest, i));

            // Collect the public values for challengers.
            let initial_challenger_public_values =
                get_challenger_public_values(builder, &initial_reconstruct_challenger);
            let final_challenger_public_values =
                get_challenger_public_values(builder, &reconstruct_challenger);

            // Collect the cumulative sum.
            let cumulative_sum_array = builder.ext2felt(cumulative_sum);
            let cumulative_sum_array = array::from_fn(|i| builder.get(&cumulative_sum_array, i));

            // Collect the deferred proof digests.
            let zero: Felt<_> = builder.eval(C::F::zero());
            let start_deferred_digest = [zero; POSEIDON_NUM_WORDS];
            let end_deferred_digest = [zero; POSEIDON_NUM_WORDS];

            // Collect the is_complete flag.
            let is_complete_felt = var2felt(builder, is_complete);

            // Initialize the public values we will commit to.
            let mut recursion_public_values_stream = [zero; RECURSIVE_PROOF_NUM_PV_ELTS];
            let recursion_public_values: &mut RecursionPublicValues<_> =
                recursion_public_values_stream.as_mut_slice().borrow_mut();
            // recursion_public_values.committed_value_digest = committed_value_digest;
            // recursion_public_values.start_pc = start_pc;
            // recursion_public_values.next_pc = current_pc;
            // recursion_public_values.start_chunk = initial_chunk;
            // recursion_public_values.next_chunk = current_chunk;
            // recursion_public_values.start_execution_chunk = initial_execution_chunk;
            // recursion_public_values.next_execution_chunk = current_execution_chunk;
            // recursion_public_values.previous_init_addr_bits = initial_previous_init_addr_bits;
            // recursion_public_values.last_init_addr_bits = current_init_addr_bits;
            // recursion_public_values.previous_finalize_addr_bits =
            //     initial_previous_finalize_addr_bits;
            // recursion_public_values.last_finalize_addr_bits = current_finalize_addr_bits;
            recursion_public_values.pico_vk_digest = vk_digest;
            recursion_public_values.leaf_challenger = leaf_challenger_public_values;
            recursion_public_values.start_reconstruct_challenger = initial_challenger_public_values;
            recursion_public_values.end_reconstruct_challenger = final_challenger_public_values;
            recursion_public_values.cumulative_sum = cumulative_sum_array;
            // recursion_public_values.start_reconstruct_deferred_digest = start_deferred_digest;
            // recursion_public_values.end_reconstruct_deferred_digest = end_deferred_digest;
            // recursion_public_values.exit_code = exit_code;
            recursion_public_values.is_complete = is_complete_felt;

            // If the proof represents a complete proof, make completeness assertions.
            //
            // *Remark*: In this program, this only happens if there is one chunk and the program
            // has no deferred proofs to verify. However, the completeness check is
            // independent of these facts.
            builder.if_eq(is_complete, C::N::one()).then(|builder| {
                assert_complete(builder, recursion_public_values, &reconstruct_challenger)
            });

            commit_public_values(builder, recursion_public_values);
        }
    }
}
