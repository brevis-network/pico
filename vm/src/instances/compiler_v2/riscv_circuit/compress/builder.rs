use super::super::stdin::{RiscvRecursionStdin, RiscvRecursionStdinVariable};
use crate::{
    chips::chips::riscv_cpu::MAX_CPU_LOG_DEGREE,
    compiler::{
        recursion_v2::{
            circuit::{
                challenger::{
                    CanObserveVariable, DuplexChallengerVariable, FieldChallengerVariable,
                },
                config::{BabyBearFriConfig, BabyBearFriConfigVariable, CircuitConfig},
                stark::StarkVerifier,
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
        chiptype::riscv_chiptype::RiscvChipType,
        configs::{
            recur_config::{FieldConfig as RiscvFC, FieldConfig as RecursionFC},
            riscv_config::StarkConfig as RiscvSC,
        },
    },
    machine::{chip::ChipBehavior, machine::BaseMachine},
    primitives::{
        consts::{
            ADDR_NUM_BITS, DIGEST_SIZE, EMPTY, MAX_LOG_CHUNK_SIZE, MAX_LOG_NUMBER_OF_CHUNKS,
            POSEIDON_NUM_WORDS, PV_DIGEST_NUM_WORDS,
        },
        consts_v2::RECURSION_NUM_PVS_V2,
    },
    recursion_v2::air::{recursion_public_values_digest, RecursionPublicValues},
};
use itertools::Itertools;
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

/// Circuit that verifies a single riscv proof and checks constraints
#[derive(Debug, Clone, Copy)]
pub struct RiscvCompressVerifierCircuit<CC: CircuitConfig, SC: BabyBearFriConfig> {
    _phantom: PhantomData<(CC, SC)>,
}

impl RiscvCompressVerifierCircuit<RecursionFC, BabyBearPoseidon2> {
    pub fn build(
        machine: &BaseMachine<BabyBearPoseidon2, RiscvChipType<BabyBear>>,
        input: &RiscvRecursionStdin<BabyBearPoseidon2, RiscvChipType<BabyBear>>,
    ) -> RecursionProgram<Val<RiscvSC>> {
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

impl<CC, SC> RiscvCompressVerifierCircuit<CC, SC>
where
    SC: BabyBearFriConfigVariable<
        CC,
        FriChallengerVariable = DuplexChallengerVariable<CC>,
        DigestVariable = [Felt<BabyBear>; DIGEST_SIZE],
    >,
    CC: CircuitConfig<F = SC::Val, EF = SC::Challenge, Bit = Felt<BabyBear>>,
{
    pub fn build_verifier(
        builder: &mut Builder<CC>,
        machine: &BaseMachine<SC, RiscvChipType<SC::Val>>,
        input: RiscvRecursionStdinVariable<CC, SC>,
    ) {
        // Read input.
        let RiscvRecursionStdinVariable {
            riscv_vk,
            proofs,
            base_challenger,
            reconstruct_challenger,
            flag_complete,
            flag_first_chunk,
            vk_root,
        } = input;

        // Assert that the number of proofs is one.
        assert_eq!(proofs.len(), 1);

        /*
        Extract public values
         */
        let public_values: &PublicValues<Word<Felt<_>>, Felt<_>> =
            proofs[0].public_values.as_slice().borrow();

        /*
        Initializations
        */
        // chunk numbers
        let mut current_chunk = public_values.chunk;
        let mut current_execution_chunk = public_values.execution_chunk;

        // for reconstruct challenger
        let mut current_reconstruct_challenger: DuplexChallengerVariable<_> =
            reconstruct_challenger.copy(builder);

        // flags
        let flag_cpu = proofs[0].contains_cpu();
        let flag_memory_initialize = proofs[0].contains_memory_initialize();
        let flag_memory_finalize = proofs[0].contains_memory_finalize();

        /*
        Verify chunk proof
         */
        {
            let mut challenger = base_challenger.copy(builder);

            let global_permutation_challenges =
                (0..2).map(|_| challenger.sample_ext(builder)).collect_vec();

            StarkVerifier::verify_chunk(
                builder,
                &riscv_vk,
                machine,
                &mut challenger,
                &proofs[0],
                &global_permutation_challenges,
            );
        }

        /*
        Beginning constraints
         */
        {
            // boolean assertion
            builder.assert_felt_eq(
                flag_first_chunk * (flag_first_chunk - CC::F::ONE),
                CC::F::ZERO,
            );

            // Chunk index assertion
            builder.assert_felt_eq(
                flag_first_chunk * (public_values.chunk - CC::F::ONE),
                CC::F::ZERO,
            );
            builder.assert_felt_ne(
                (SymbolicFelt::ONE - flag_first_chunk) * public_values.chunk,
                CC::F::ONE,
            );

            // Starting challenger assertion
            let mut starting_challenger = machine.config().challenger_variable(builder);
            riscv_vk.observed_by(builder, &mut starting_challenger);
            let starting_challenger_public_values = starting_challenger.public_values(builder);
            let reconstruct_challenger_public_values =
                reconstruct_challenger.public_values(builder);
            for (c0, c1) in starting_challenger_public_values
                .into_iter()
                .zip(reconstruct_challenger_public_values)
            {
                builder.assert_felt_eq(flag_first_chunk * (c0 - c1), CC::F::ZERO);
            }

            // `start_pc` equals `vk.pc_start`.
            builder.assert_felt_eq(
                flag_first_chunk * (public_values.start_pc - riscv_vk.pc_start),
                CC::F::ZERO,
            );

            // Assert that previous `init_addr_bits` and `finalize_addr_bits` are zeros
            for bit in public_values.previous_initialize_addr_bits.iter() {
                builder.assert_felt_eq(flag_first_chunk * *bit, CC::F::ZERO);
            }
            for bit in public_values.previous_finalize_addr_bits.iter() {
                builder.assert_felt_eq(flag_first_chunk * *bit, CC::F::ZERO);
            }
        }

        /*
        Chunk number constraints and updates
         */
        {
            // range check
            CC::range_check_felt(builder, public_values.chunk, MAX_LOG_NUMBER_OF_CHUNKS);

            // current chunk is incremented by 1
            current_chunk = builder.eval(current_chunk + CC::F::ONE);

            // If the chunk has a "CPU" chip, then the execution chunk should be incremented by 1.
            if flag_cpu {
                current_execution_chunk = builder.eval(current_execution_chunk + CC::F::ONE);
            }
        }

        /*
        CPU constraints
         */

        {
            if !flag_cpu {
                builder.assert_felt_ne(current_chunk, CC::F::ONE);

                builder.assert_felt_eq(public_values.start_pc, public_values.next_pc);
            }
            if flag_cpu {
                let log_degree_cpu = proofs[0].log_degree_cpu();
                assert!(log_degree_cpu <= MAX_CPU_LOG_DEGREE);

                builder.assert_felt_ne(public_values.start_pc, CC::F::ZERO);
            }
        }

        /*
        Memory constraints
         */
        {
            if !flag_memory_initialize {
                for i in 0..ADDR_NUM_BITS {
                    builder.assert_felt_eq(
                        public_values.previous_initialize_addr_bits[i],
                        public_values.last_initialize_addr_bits[i],
                    );
                }
            }

            if !flag_memory_finalize {
                for i in 0..ADDR_NUM_BITS {
                    builder.assert_felt_eq(
                        public_values.previous_finalize_addr_bits[i],
                        public_values.last_finalize_addr_bits[i],
                    );
                }
            }
        }

        /*
        Completeness constraints
         */
        {
            // Assert that the last exit code is zero.
            builder.assert_felt_eq(public_values.exit_code, CC::F::ZERO);
        }

        /*
        Update bookkeeping
         */
        // update reconstruct challenger
        current_reconstruct_challenger.observe(builder, proofs[0].commitments.global_main_commit);
        for element in proofs[0]
            .public_values
            .iter()
            .take(machine.num_public_values())
        {
            current_reconstruct_challenger.observe(builder, *element);
        }

        // cumulative sum
        let mut global_cumulative_sum: Ext<_, _> = builder.eval(CC::EF::ZERO.cons());
        for values in proofs[0].opened_values.chips_opened_values.iter() {
            global_cumulative_sum =
                builder.eval(global_cumulative_sum + values.global_cumulative_sum);
        }

        /*
        Update public values and commit
        */
        {
            // Compute the vk digest.
            let vk_digest = riscv_vk.hash_babybear(builder);

            // challenger pvs
            let base_challenger_public_values = base_challenger.public_values(builder);
            let start_challenger_public_values = reconstruct_challenger.public_values(builder);
            let end_challenger_public_values =
                current_reconstruct_challenger.public_values(builder);

            // Collect the cumulative sum.
            let global_cumulative_sum_array = builder.ext2felt_v2(global_cumulative_sum);

            let zero: Felt<_> = builder.eval(CC::F::ZERO);

            // Initialize the public values we will commit to.
            let mut recursion_public_values_stream = [zero; RECURSION_NUM_PVS_V2];
            let recursion_public_values: &mut RecursionPublicValues<_> =
                recursion_public_values_stream.as_mut_slice().borrow_mut();

            // Update recursion public values
            recursion_public_values.committed_value_digest = public_values.committed_value_digest;
            recursion_public_values.start_pc = public_values.start_pc;
            recursion_public_values.next_pc = public_values.next_pc;
            recursion_public_values.start_chunk = public_values.chunk;
            recursion_public_values.next_chunk = current_chunk;
            recursion_public_values.start_execution_chunk = public_values.execution_chunk;
            recursion_public_values.next_execution_chunk = current_execution_chunk;
            recursion_public_values.contains_execution_chunk =
                builder.eval(CC::F::from_bool(flag_cpu));

            recursion_public_values.previous_initialize_addr_bits =
                public_values.previous_initialize_addr_bits;
            recursion_public_values.last_initialize_addr_bits =
                public_values.last_initialize_addr_bits;
            recursion_public_values.previous_finalize_addr_bits =
                public_values.previous_finalize_addr_bits;
            recursion_public_values.last_finalize_addr_bits = public_values.last_finalize_addr_bits;

            recursion_public_values.base_challenger = base_challenger_public_values;
            recursion_public_values.start_reconstruct_challenger = start_challenger_public_values;
            recursion_public_values.end_reconstruct_challenger = end_challenger_public_values;

            recursion_public_values.riscv_vk_digest = vk_digest;
            recursion_public_values.vk_root = vk_root;

            recursion_public_values.cumulative_sum = global_cumulative_sum_array;
            recursion_public_values.exit_code = public_values.exit_code;
            recursion_public_values.flag_complete = flag_complete;

            // Calculate the digest and set it in the public values.
            recursion_public_values.digest =
                recursion_public_values_digest::<CC, SC>(builder, recursion_public_values);

            SC::commit_recursion_public_values(builder, *recursion_public_values);
        }
    }
}
