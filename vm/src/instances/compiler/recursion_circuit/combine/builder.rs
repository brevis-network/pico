use crate::{
    compiler::recursion::{
        ir::{Builder, Felt},
        program::RecursionProgram,
        program_builder::{
            hints::hintable::Hintable,
            p3::{
                challenger::{CanObserveVariable, DuplexChallengerVariable},
                fri::TwoAdicFriPcsVariable,
            },
            stark::StarkVerifier,
            utils::{
                assert_challenger_eq_pv, assign_challenger_from_pv, const_fri_config,
                get_challenger_public_values, hash_vkey, var2felt,
            },
        },
    },
    configs::config::{FieldGenericConfig, StarkGenericConfig, Val},
    instances::{
        chiptype::recursion_chiptype::RecursionChipType,
        compiler::{
            recursion_circuit::stdin::{RecursionStdin, RecursionStdinVariable},
            utils::commit_public_values,
        },
        configs::recur_config::{FieldConfig as RecursionFC, StarkConfig as RecursionSC},
    },
    machine::machine::BaseMachine,
    primitives::{
        consts::{
            ADDR_NUM_BITS, DIGEST_SIZE, EXTENSION_DEGREE, RECURSION_NUM_PVS, RISCV_COMPRESS_DEGREE,
        },
        types::RecursionProgramType,
    },
    recursion::air::RecursionPublicValues,
};
use itertools::Itertools;
use p3_field::AbstractField;
use std::{
    array,
    borrow::{Borrow, BorrowMut},
    marker::PhantomData,
};

#[derive(Debug, Clone, Copy)]
pub struct RecursionCombineVerifierCircuit<FC: FieldGenericConfig, SC: StarkGenericConfig> {
    _phantom: PhantomData<(FC, SC)>,
}

impl RecursionCombineVerifierCircuit<RecursionFC, RecursionSC> {
    pub fn build(
        machine: &BaseMachine<
            RecursionSC,
            RecursionChipType<Val<RecursionSC>, RISCV_COMPRESS_DEGREE>,
        >,
    ) -> RecursionProgram<Val<RecursionSC>> {
        let mut builder = Builder::<RecursionFC>::new(RecursionProgramType::Combine);

        let stdin: RecursionStdinVariable<_> = builder.uninit();
        RecursionStdin::<RecursionSC, RecursionChipType<Val<RecursionSC>, RISCV_COMPRESS_DEGREE>>::witness(
            &stdin,
            &mut builder,
        );

        let pcs = TwoAdicFriPcsVariable {
            config: const_fri_config(&mut builder, machine.config().pcs().fri_config()),
        };

        Self::build_verifier(&mut builder, &pcs, machine, stdin);
        builder.halt();
        builder.compile_program()
    }

    pub fn build_verifier(
        builder: &mut Builder<RecursionFC>,
        pcs: &TwoAdicFriPcsVariable<RecursionFC>,
        machine: &BaseMachine<
            RecursionSC,
            RecursionChipType<Val<RecursionSC>, RISCV_COMPRESS_DEGREE>,
        >,
        stdin: RecursionStdinVariable<RecursionFC>,
    ) {
        let RecursionStdinVariable {
            vk,
            proofs,
            flag_complete,
        } = stdin;

        // Assert number of proofs > 0
        builder.assert_usize_ne(proofs.len(), 0);

        // todo: support commit and deferred digests

        /*
        Initializations
        */
        // counters
        let start_pc = builder.uninit();
        let current_pc = builder.uninit();

        let start_chunk = builder.uninit();
        let current_chunk = builder.uninit();

        let start_execution_chunk = builder.uninit();
        let current_execution_chunk = builder.uninit();

        // addresses
        let start_previous_initialize_addr_bits: [Felt<_>; ADDR_NUM_BITS] =
            array::from_fn(|_| builder.uninit());
        let current_previous_initialize_addr_bits: [Felt<_>; ADDR_NUM_BITS] =
            array::from_fn(|_| builder.uninit());

        let start_previous_finalize_addr_bits: [Felt<_>; ADDR_NUM_BITS] =
            array::from_fn(|_| builder.uninit());
        let current_previous_finalize_addr_bits: [Felt<_>; ADDR_NUM_BITS] =
            array::from_fn(|_| builder.uninit());

        let riscv_vk_digest: [Felt<_>; DIGEST_SIZE] = array::from_fn(|_| builder.uninit());

        // challengers
        let mut base_challenger = DuplexChallengerVariable::new(builder);
        let mut start_reconstruct_challenger = DuplexChallengerVariable::new(builder);
        let mut current_reconstruct_challenger = DuplexChallengerVariable::new(builder);

        // checkers
        let cumulative_sum: [Felt<_>; EXTENSION_DEGREE] =
            array::from_fn(|_| builder.eval(<RecursionFC as FieldGenericConfig>::F::zero()));

        // Iteratively verify proofs and check constraints
        builder.range(0, proofs.len()).for_each(|i, builder| {
            /*
            verify chunk proof
             */
            let proof = builder.get(&proofs, i);

            let mut challenger = DuplexChallengerVariable::new(builder);

            // observe vk and start pc
            challenger.observe(builder, vk.commitment.clone());
            challenger.observe(builder, vk.pc_start);

            // commitment and pv
            challenger.observe(builder, proof.commitment.main_commit.clone());
            for j in 0..RECURSION_NUM_PVS {
                let pv = builder.get(&proof.public_values, j);
                challenger.observe(builder, pv);
            }

            // verify proof
            StarkVerifier::<RecursionFC, RecursionSC>::verify_chunk(
                builder,
                &vk,
                pcs,
                machine.chips(),
                &machine.preprocessed_chip_ids(),
                &mut challenger,
                &proof,
                false,
            );

            /*
            Extract public values
             */
            let mut public_values_stream = Vec::new();
            for j in 0..RECURSION_NUM_PVS {
                public_values_stream.push(builder.get(&proof.public_values, j));
            }
            let public_values: &RecursionPublicValues<
                Felt<<RecursionFC as FieldGenericConfig>::F>,
            > = public_values_stream.as_slice().borrow();

            // todo
            // verify_public_values_hash(builder, public_values);

            /*
            The first proof in the batch
             */
            builder
                .if_eq(i, <RecursionFC as FieldGenericConfig>::N::zero())
                .then(|builder| {
                    builder.assign(start_pc, public_values.start_pc);
                    builder.assign(current_pc, public_values.start_pc);

                    builder.assign(start_chunk, public_values.start_chunk);
                    builder.assign(current_chunk, public_values.start_chunk);

                    builder.assign(start_execution_chunk, public_values.start_execution_chunk);
                    builder.assign(current_execution_chunk, public_values.start_execution_chunk);

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

                    for (digest, first_digest) in riscv_vk_digest
                        .iter()
                        .zip_eq(public_values.riscv_vk_digest.iter())
                    {
                        builder.assign(*digest, *first_digest);
                    }

                    assign_challenger_from_pv(
                        builder,
                        &mut base_challenger,
                        public_values.base_challenger,
                    );
                    assign_challenger_from_pv(
                        builder,
                        &mut start_reconstruct_challenger,
                        public_values.start_reconstruct_challenger,
                    );
                    assign_challenger_from_pv(
                        builder,
                        &mut current_reconstruct_challenger,
                        public_values.start_reconstruct_challenger,
                    );
                });

            /*
            check current status
             */

            builder.assert_felt_eq(current_pc, public_values.start_pc);
            builder.assert_felt_eq(current_chunk, public_values.start_chunk);
            builder.assert_felt_eq(current_execution_chunk, public_values.start_execution_chunk);

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

            for i in 0..DIGEST_SIZE {
                builder.assert_felt_eq(riscv_vk_digest[i], public_values.riscv_vk_digest[i]);
            }

            assert_challenger_eq_pv(builder, &base_challenger, public_values.base_challenger);
            assert_challenger_eq_pv(
                builder,
                &current_reconstruct_challenger,
                public_values.start_reconstruct_challenger,
            );

            /*
            update current status
             */
            builder.assign(current_pc, public_values.next_pc);
            builder.assign(current_chunk, public_values.next_chunk);
            builder.assign(current_execution_chunk, public_values.next_execution_chunk);

            for i in 0..ADDR_NUM_BITS {
                builder.assign(
                    current_previous_initialize_addr_bits[i],
                    public_values.last_init_addr_bits[i],
                );
                builder.assign(
                    current_previous_finalize_addr_bits[i],
                    public_values.last_finalize_addr_bits[i],
                );
            }

            assign_challenger_from_pv(
                builder,
                &mut current_reconstruct_challenger,
                public_values.end_reconstruct_challenger,
            );

            // update cumulative sum
            for (cumsum_entry, pv_cumsum_entry) in cumulative_sum
                .iter()
                .zip_eq(public_values.cumulative_sum.iter())
            {
                builder.assign(*cumsum_entry, *cumsum_entry + *pv_cumsum_entry);
            }
        });

        let base_challenger_public_values = get_challenger_public_values(builder, &base_challenger);
        let start_challenger_public_values =
            get_challenger_public_values(builder, &start_reconstruct_challenger);
        let end_challenger_public_values =
            get_challenger_public_values(builder, &current_reconstruct_challenger);

        /*
        completeness constraints
         */
        builder
            .if_eq(flag_complete, <RecursionFC as FieldGenericConfig>::N::one())
            .then(|builder| {
                builder.assert_felt_eq(current_pc, <RecursionFC as FieldGenericConfig>::F::zero());
                builder.assert_felt_eq(start_chunk, <RecursionFC as FieldGenericConfig>::F::one());
                builder
                    .assert_felt_ne(current_chunk, <RecursionFC as FieldGenericConfig>::F::one());
                builder.assert_felt_eq(
                    start_execution_chunk,
                    <RecursionFC as FieldGenericConfig>::F::one(),
                );
                builder.assert_felt_ne(
                    current_execution_chunk,
                    <RecursionFC as FieldGenericConfig>::F::one(),
                );

                assert_challenger_eq_pv(
                    builder,
                    &current_reconstruct_challenger,
                    base_challenger_public_values,
                );

                for b in cumulative_sum.iter() {
                    builder.assert_felt_eq(*b, <RecursionFC as FieldGenericConfig>::F::zero());
                }
            });

        /*
        update public values and commit
         */
        let zero: Felt<_> = builder.eval(<RecursionFC as FieldGenericConfig>::F::zero());
        let mut recursion_public_values_stream = [zero; RECURSION_NUM_PVS];
        let recursion_public_values: &mut RecursionPublicValues<_> =
            recursion_public_values_stream.as_mut_slice().borrow_mut();

        // vk digests
        let recursion_vk_digest = hash_vkey(builder, &vk);
        let recursion_vk_digest: [Felt<_>; DIGEST_SIZE] =
            array::from_fn(|i| builder.get(&recursion_vk_digest, i));

        recursion_public_values.riscv_vk_digest = riscv_vk_digest;
        recursion_public_values.recursion_vk_digest = recursion_vk_digest;

        // update public values
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

        recursion_public_values.base_challenger = base_challenger_public_values;

        recursion_public_values.start_reconstruct_challenger = start_challenger_public_values;
        recursion_public_values.end_reconstruct_challenger = end_challenger_public_values;

        recursion_public_values.cumulative_sum = cumulative_sum;
        recursion_public_values.flag_complete = var2felt(builder, flag_complete);

        commit_public_values(builder, recursion_public_values);
    }
}
