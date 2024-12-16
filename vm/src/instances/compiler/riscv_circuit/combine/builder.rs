use crate::{
    compiler::{
        recursion::{
            prelude::*,
            program::RecursionProgram,
            program_builder::{
                hints::hintable::Hintable,
                p3::{
                    challenger::{CanObserveVariable, DuplexChallengerVariable},
                    fri::TwoAdicFriPcsVariable,
                },
                stark::StarkVerifier,
                utils::{
                    assert_challenger_eq_pv, const_fri_config, felt2var,
                    get_challenger_public_values, hash_vkey, var2felt,
                },
            },
        },
        word::Word,
    },
    configs::config::{FieldGenericConfig, StarkGenericConfig},
    emulator::riscv::public_values::PublicValues,
    instances::{
        chiptype::riscv_chiptype::RiscvChipType,
        compiler::{
            riscv_circuit::stdin::{RiscvRecursionStdin, RiscvRecursionStdinVariable},
            utils::commit_public_values,
        },
        configs::{recur_config as rcf, riscv_config::StarkConfig as RiscvSC},
    },
    machine::{chip::ChipBehavior, machine::BaseMachine},
    primitives::consts::{
        ADDR_NUM_BITS, DIGEST_SIZE, EMPTY, MAX_LOG_CHUNK_SIZE, RECURSION_NUM_PVS,
    },
    recursion::air::RecursionPublicValues,
};
use p3_baby_bear::BabyBear;
use p3_field::FieldAlgebra;
use std::{
    array,
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
};

#[derive(Debug, Clone, Copy)]
pub struct RiscvCombineVerifierCircuit<FC: FieldGenericConfig, SC: StarkGenericConfig> {
    _phantom: PhantomData<(FC, SC)>,
}

impl RiscvCombineVerifierCircuit<rcf::FieldConfig, RiscvSC> {
    pub fn build(
        machine: &BaseMachine<RiscvSC, RiscvChipType<BabyBear>>,
    ) -> RecursionProgram<BabyBear> {
        let mut builder = Builder::<rcf::FieldConfig>::new();

        let stdin: RiscvRecursionStdinVariable<_> = builder.uninit();
        RiscvRecursionStdin::<RiscvSC, RiscvChipType<BabyBear>>::witness(&stdin, &mut builder);

        let pcs = TwoAdicFriPcsVariable {
            config: const_fri_config(&mut builder, machine.config().fri_config()),
        };

        Self::build_verifier(&mut builder, &pcs, machine, stdin);
        builder.halt();
        builder.compile_program()
    }

    // Non-recursion version: vm/src/instances/machine/riscv_machine.rs
    pub fn build_verifier(
        builder: &mut Builder<rcf::FieldConfig>,
        pcs: &TwoAdicFriPcsVariable<rcf::FieldConfig>,
        machine: &BaseMachine<RiscvSC, RiscvChipType<BabyBear>>,
        stdin: RiscvRecursionStdinVariable<rcf::FieldConfig>,
    ) {
        let RiscvRecursionStdinVariable {
            vk,
            proofs,
            base_challenger,
            reconstruct_challenger,
            flag_complete,
        } = stdin;

        // Assert number of proofs > 0
        builder.assert_usize_ne(proofs.len(), 0);

        // todo: support commit and deferred digests

        /*
        Initializations
        */
        let start_pc = builder.uninit();
        let current_pc = builder.uninit();

        let start_chunk = builder.uninit();
        let current_chunk = builder.uninit();

        let start_execution_chunk = builder.uninit();
        let current_execution_chunk = builder.uninit();

        let start_previous_initialize_addr_bits: [Felt<_>; ADDR_NUM_BITS] =
            array::from_fn(|_| builder.uninit());
        let current_previous_initialize_addr_bits: [Felt<_>; ADDR_NUM_BITS] =
            array::from_fn(|_| builder.uninit());

        let start_previous_finalize_addr_bits: [Felt<_>; ADDR_NUM_BITS] =
            array::from_fn(|_| builder.uninit());
        let current_previous_finalize_addr_bits: [Felt<_>; ADDR_NUM_BITS] =
            array::from_fn(|_| builder.uninit());

        // for bottom-level challenger
        let base_challenger_public_values = get_challenger_public_values(builder, &base_challenger);

        // for reconstruct challenger
        let mut current_reconstruct_challenger: DuplexChallengerVariable<_> =
            reconstruct_challenger.copy(builder);

        let global_cumulative_sum: Ext<_, _> =
            builder.eval(<rcf::FieldConfig as FieldGenericConfig>::EF::ZERO.cons());

        let exit_code: Felt<_> = builder.uninit();

        // Iteratively verify proofs and check constraints
        builder.range(0, proofs.len()).for_each(|i, builder| {
            /*
            verify chunk proof
             */
            let proof = builder.get(&proofs, i);

            let mut challenger = base_challenger.copy(builder);

            StarkVerifier::<rcf::FieldConfig, RiscvSC>::verify_chunk(
                builder,
                &vk,
                pcs,
                &machine.chips(),
                &machine.preprocessed_chip_ids(),
                &mut challenger,
                &proof,
                false,
            );

            /*
            Extract public values
             */
            let mut public_values_stream = Vec::new();
            for j in 0..machine.num_public_values() {
                public_values_stream.push(builder.get(&proof.public_values, j));
            }
            let public_values: &PublicValues<Word<Felt<_>>, Felt<_>> =
                public_values_stream.as_slice().borrow();

            /*
            Flags
             */
            let flag_cpu: Var<_> = builder.eval(<rcf::FieldConfig as FieldGenericConfig>::N::ZERO);
            let index_cpu: Var<_> = builder.eval(<rcf::FieldConfig as FieldGenericConfig>::N::ZERO);
            let flag_memory_initialize: Var<_> =
                builder.eval(<rcf::FieldConfig as FieldGenericConfig>::N::ZERO);
            let flag_memory_finalize: Var<_> =
                builder.eval(<rcf::FieldConfig as FieldGenericConfig>::N::ZERO);
            let flag_starting_chunk: Var<_> =
                builder.eval(<rcf::FieldConfig as FieldGenericConfig>::N::ZERO);

            /*
            Initialize when on the first proof in the batch
             */
            builder
                .if_eq(i, <rcf::FieldConfig as FieldGenericConfig>::N::ZERO)
                .then(|builder| {
                    builder.assign(start_pc, public_values.start_pc);
                    builder.assign(current_pc, public_values.start_pc);

                    builder.assign(start_chunk, public_values.chunk);
                    builder.assign(current_chunk, public_values.chunk);

                    builder.assign(start_execution_chunk, public_values.execution_chunk);
                    builder.assign(current_execution_chunk, public_values.execution_chunk);

                    for i in 0..ADDR_NUM_BITS {
                        builder.assign(
                            start_previous_initialize_addr_bits[i],
                            public_values.previous_initialize_addr_bits[i],
                        );
                        builder.assign(
                            current_previous_initialize_addr_bits[i],
                            public_values.previous_initialize_addr_bits[i],
                        );
                        builder.assign(
                            start_previous_finalize_addr_bits[i],
                            public_values.previous_finalize_addr_bits[i],
                        );
                        builder.assign(
                            current_previous_finalize_addr_bits[i],
                            public_values.previous_finalize_addr_bits[i],
                        );
                    }
                });

            /*
            Set flags
             */
            for (i, chip) in machine.chips().iter().enumerate() {
                let index = builder.get(&proof.sorted_indices, i);
                if chip.name() == "Cpu" {
                    builder
                        .if_ne(
                            index,
                            <rcf::FieldConfig as FieldGenericConfig>::N::from_canonical_usize(
                                EMPTY,
                            ),
                        )
                        .then(|builder| {
                            builder
                                .assign(flag_cpu, <rcf::FieldConfig as FieldGenericConfig>::N::ONE);
                            builder.assign(index_cpu, index);
                        });
                }
                if chip.name() == "MemoryInitialize" {
                    builder
                        .if_ne(
                            index,
                            <rcf::FieldConfig as FieldGenericConfig>::N::from_canonical_usize(
                                EMPTY,
                            ),
                        )
                        .then(|builder| {
                            builder.assign(
                                flag_memory_initialize,
                                <rcf::FieldConfig as FieldGenericConfig>::N::ONE,
                            );
                        });
                }
                if chip.name() == "MemoryFinalize" {
                    builder
                        .if_ne(
                            index,
                            <rcf::FieldConfig as FieldGenericConfig>::N::from_canonical_usize(
                                EMPTY,
                            ),
                        )
                        .then(|builder| {
                            builder.assign(
                                flag_memory_finalize,
                                <rcf::FieldConfig as FieldGenericConfig>::N::ONE,
                            );
                        });
                }
            }
            let chunk = felt2var(builder, public_values.chunk);
            builder
                .if_eq(chunk, <rcf::FieldConfig as FieldGenericConfig>::F::ONE)
                .then(|builder| {
                    builder.assign(
                        flag_starting_chunk,
                        <rcf::FieldConfig as FieldGenericConfig>::N::ONE,
                    );
                });

            /*
            Beginning constraints
             */
            builder
                .if_eq(
                    flag_starting_chunk,
                    <rcf::FieldConfig as FieldGenericConfig>::N::ONE,
                )
                .then(|builder| {
                    // first chunk start_pc should be vk.start_pc
                    builder.assert_felt_eq(public_values.start_pc, vk.pc_start);

                    // first chunk should include cpu
                    builder
                        .assert_var_eq(flag_cpu, <rcf::FieldConfig as FieldGenericConfig>::N::ONE);

                    // initialize and finalize addr bits should be zero
                    for i in 0..ADDR_NUM_BITS {
                        builder.assert_felt_eq(
                            current_previous_initialize_addr_bits[i],
                            <rcf::FieldConfig as FieldGenericConfig>::F::ZERO,
                        );
                        builder.assert_felt_eq(
                            current_previous_finalize_addr_bits[i],
                            <rcf::FieldConfig as FieldGenericConfig>::F::ZERO,
                        );
                    }

                    // reconstruct challenger match
                    let mut starting_challenger = DuplexChallengerVariable::new(builder);
                    starting_challenger.observe(builder, vk.commitment.clone());
                    starting_challenger.observe(builder, vk.pc_start);
                    starting_challenger.assert_eq(builder, &reconstruct_challenger);
                });

            /*
            Chunk number constraints and updates
             */

            builder.assert_felt_eq(current_chunk, public_values.chunk);
            builder.assign(
                current_chunk,
                current_chunk + <rcf::FieldConfig as FieldGenericConfig>::F::ONE,
            );

            builder
                .if_eq(flag_cpu, <rcf::FieldConfig as FieldGenericConfig>::N::ONE)
                .then(|builder| {
                    builder.assert_felt_eq(current_execution_chunk, public_values.execution_chunk);
                    builder.assign(
                        current_execution_chunk,
                        current_execution_chunk + <rcf::FieldConfig as FieldGenericConfig>::F::ONE,
                    );
                });

            /*
            cpu constraints
             */

            builder
                .if_eq(flag_cpu, <rcf::FieldConfig as FieldGenericConfig>::N::ONE)
                .then_or_else(
                    |builder| {
                        // assert log_main_degree is in [0, MAX_LOG_CHUNK_SIZE]
                        let log_main_degree = builder
                            .get(&proof.opened_values.chips_opened_values, index_cpu)
                            .log_main_degree;

                        let degree_match: Var<_> =
                            builder.eval(<rcf::FieldConfig as FieldGenericConfig>::N::ZERO);
                        builder
                            .range(0, MAX_LOG_CHUNK_SIZE + 1)
                            .for_each(|j, builder| {
                                builder.if_eq(log_main_degree, j).then(|builder| {
                                    builder.assign(
                                        degree_match,
                                        <rcf::FieldConfig as FieldGenericConfig>::N::ONE,
                                    );
                                });
                            });
                        builder.assert_var_eq(
                            degree_match,
                            <rcf::FieldConfig as FieldGenericConfig>::N::ONE,
                        );

                        // start_pc should not be zero
                        builder.assert_felt_ne(
                            public_values.start_pc,
                            <rcf::FieldConfig as FieldGenericConfig>::F::ZERO,
                        );
                    },
                    |builder| {
                        // assert start_pc == next_pc
                        builder.assert_felt_eq(public_values.start_pc, public_values.next_pc);
                    },
                );

            /*
            memory constraints
            */
            for i in 0..ADDR_NUM_BITS {
                builder.assert_felt_eq(
                    current_previous_initialize_addr_bits[i],
                    public_values.previous_initialize_addr_bits[i],
                );
                builder.assert_felt_eq(
                    current_previous_finalize_addr_bits[i],
                    public_values.previous_finalize_addr_bits[i],
                );
            }

            builder
                .if_eq(
                    flag_memory_initialize,
                    <rcf::FieldConfig as FieldGenericConfig>::N::ZERO,
                )
                .then(|builder| {
                    for i in 0..ADDR_NUM_BITS {
                        builder.assert_felt_eq(
                            public_values.previous_initialize_addr_bits[i],
                            public_values.last_initialize_addr_bits[i],
                        );
                    }
                });

            builder
                .if_eq(
                    flag_memory_finalize,
                    <rcf::FieldConfig as FieldGenericConfig>::N::ZERO,
                )
                .then(|builder| {
                    for i in 0..ADDR_NUM_BITS {
                        builder.assert_felt_eq(
                            public_values.previous_finalize_addr_bits[i],
                            public_values.last_finalize_addr_bits[i],
                        );
                    }
                });

            /*
            Transition constraints
             */

            // all exit codes should be zeros
            builder.assert_felt_eq(
                public_values.exit_code,
                <rcf::FieldConfig as FieldGenericConfig>::F::ZERO,
            );

            // current_pc should be start_pc
            builder.assert_felt_eq(current_pc, public_values.start_pc);

            // todo: digests

            // update reconstruct challenger
            current_reconstruct_challenger.observe(builder, proof.commitment.main_commit.clone());
            for j in 0..machine.num_public_values() {
                let public_values_j = builder.get(&proof.public_values, j);
                current_reconstruct_challenger.observe(builder, public_values_j);
            }

            // cumulative sum
            let opened_values = proof.opened_values.chips_opened_values;
            builder
                .range(0, opened_values.len())
                .for_each(|k, builder| {
                    // We only need to cumulate the global sum here.
                    let opened_values = builder.get(&opened_values, k);
                    let sum = opened_values.global_cumulative_sum;
                    builder.assign(global_cumulative_sum, global_cumulative_sum + sum);
                });

            /*
            update bookkeeping
             */
            builder.assign(current_pc, public_values.next_pc);
            for i in 0..ADDR_NUM_BITS {
                builder.assign(
                    current_previous_initialize_addr_bits[i],
                    public_values.last_initialize_addr_bits[i],
                );
                builder.assign(
                    current_previous_finalize_addr_bits[i],
                    public_values.last_finalize_addr_bits[i],
                );
            }
        });

        /*
        Completeness constraints
         */
        // challengers
        let start_challenger_public_values =
            get_challenger_public_values(builder, &reconstruct_challenger);
        let end_challenger_public_values =
            get_challenger_public_values(builder, &current_reconstruct_challenger);

        // cumulative sum
        let global_cumulative_sum = builder.ext2felt(global_cumulative_sum);
        let global_cumulative_sum = array::from_fn(|i| builder.get(&global_cumulative_sum, i));

        builder
            .if_eq(
                flag_complete,
                <rcf::FieldConfig as FieldGenericConfig>::N::ONE,
            )
            .then(|builder| {
                // last pc should be zero
                builder.assert_felt_eq(
                    current_pc,
                    <rcf::FieldConfig as FieldGenericConfig>::F::ZERO,
                );

                assert_challenger_eq_pv(
                    builder,
                    &current_reconstruct_challenger,
                    base_challenger_public_values,
                );

                // note: "cumulative_sum=0 if is_complete" constraints should be verified outside of the circuit
                // if the final proof is not one proof.

                // for each in cumulative_sum.iter() {
                //     builder.assert_felt_eq(
                //         *each,
                //         <rcf::FieldConfig as FieldGenericConfig>::F::ZERO,
                //     );
                // }
            });

        /*
        Update public values and commit
        */
        // vk hash
        let vk_digest = hash_vkey(builder, &vk);
        let vk_digest: [Felt<_>; DIGEST_SIZE] = array::from_fn(|i| builder.get(&vk_digest, i));

        // Update public values
        let zero: Felt<_> = builder.eval(<rcf::FieldConfig as FieldGenericConfig>::F::ZERO);
        let mut recursion_public_values_stream = [zero; RECURSION_NUM_PVS];
        let recursion_public_values: &mut RecursionPublicValues<_> =
            recursion_public_values_stream.as_mut_slice().borrow_mut();

        recursion_public_values.start_pc = start_pc;
        recursion_public_values.next_pc = current_pc;
        recursion_public_values.start_chunk = start_chunk;
        recursion_public_values.next_chunk = current_chunk;
        recursion_public_values.start_execution_chunk = start_execution_chunk;
        recursion_public_values.next_execution_chunk = current_execution_chunk;
        recursion_public_values.previous_initialize_addr_bits = start_previous_initialize_addr_bits;
        recursion_public_values.last_init_addr_bits = current_previous_initialize_addr_bits;
        recursion_public_values.previous_finalize_addr_bits = start_previous_finalize_addr_bits;
        recursion_public_values.last_finalize_addr_bits = current_previous_finalize_addr_bits;

        recursion_public_values.riscv_vk_digest = vk_digest;
        recursion_public_values.base_challenger = base_challenger_public_values;
        recursion_public_values.start_reconstruct_challenger = start_challenger_public_values;
        recursion_public_values.end_reconstruct_challenger = end_challenger_public_values;

        recursion_public_values.cumulative_sum = global_cumulative_sum;
        recursion_public_values.exit_code = exit_code;
        recursion_public_values.flag_complete = var2felt(builder, flag_complete);

        // todo: check Commit the public values
        commit_public_values(builder, recursion_public_values);
    }
}
