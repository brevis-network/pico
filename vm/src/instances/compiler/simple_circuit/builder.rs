use super::stdin::{SimpleRecursionStdin, SimpleRecursionStdinVariable};
use crate::{
    compiler::recursion::{
        ir::{Builder, Ext, ExtConst, Felt},
        program::RecursionProgram,
        program_builder::{
            hints::hintable::Hintable,
            p3::{
                challenger::{CanObserveVariable, DuplexChallengerVariable},
                fri::TwoAdicFriPcsVariable,
            },
            stark::StarkVerifier,
            utils::{
                assert_challenger_eq_pv, const_fri_config, get_challenger_public_values, var2felt,
            },
        },
    },
    configs::config::{Com, FieldGenericConfig, StarkGenericConfig},
    instances::{
        chiptype::riscv_chiptype::RiscvChipType,
        compiler::utils::commit_public_values,
        configs::{recur_config as rcf, riscv_config::StarkConfig as RiscvSC},
    },
    machine::machine::BaseMachine,
    primitives::{
        consts::{DIGEST_SIZE, RECURSION_NUM_PVS},
        types::RecursionProgramType,
    },
    recursion::air::RecursionPublicValues,
};
use p3_baby_bear::BabyBear;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::{AbstractField, PrimeField32, TwoAdicField};
use std::{array, borrow::BorrowMut, marker::PhantomData};

/// A program for recursively verifying a batch of Pico proofs.
#[derive(Debug, Clone, Copy)]
pub struct SimpleVerifierCircuit<FC: FieldGenericConfig, SC: StarkGenericConfig> {
    _phantom: PhantomData<(FC, SC)>,
}

impl SimpleVerifierCircuit<rcf::FieldConfig, RiscvSC> {
    /// Create a new instance of the program for the [RiscvSC] config.
    pub fn build(
        machine: &BaseMachine<RiscvSC, RiscvChipType<BabyBear>>,
    ) -> RecursionProgram<BabyBear> {
        let mut builder = Builder::<rcf::FieldConfig>::new(RecursionProgramType::Riscv);

        let input: SimpleRecursionStdinVariable<_> = builder.uninit();
        SimpleRecursionStdin::<RiscvSC, RiscvChipType<_>>::witness(&input, &mut builder);

        let pcs = TwoAdicFriPcsVariable {
            config: const_fri_config(&mut builder, machine.config().pcs().fri_config()),
        };
        Self::build_verifier(&mut builder, &pcs, machine, input);

        builder.halt();

        builder.compile_program()
    }
}

impl<FC: FieldGenericConfig, SC: StarkGenericConfig> SimpleVerifierCircuit<FC, SC>
where
    FC::F: PrimeField32 + TwoAdicField,
    SC: StarkGenericConfig<
        Val = FC::F,
        Challenge = FC::EF,
        Domain = TwoAdicMultiplicativeCoset<FC::F>,
    >,
    Com<SC>: Into<[SC::Val; DIGEST_SIZE]>,
{
    pub fn build_verifier(
        builder: &mut Builder<FC>,
        pcs: &TwoAdicFriPcsVariable<FC>,
        machine: &BaseMachine<SC, RiscvChipType<SC::Val>>,
        input: SimpleRecursionStdinVariable<FC>,
    ) {
        // Read input.
        let SimpleRecursionStdinVariable {
            vk,
            base_proofs,
            base_challenger,
            initial_reconstruct_challenger,
            flag_complete,
        } = input;

        // Initialize the challenger variables.
        let leaf_challenger_public_values = get_challenger_public_values(builder, &base_challenger);
        let mut reconstruct_challenger: DuplexChallengerVariable<_> =
            initial_reconstruct_challenger.copy(builder);

        // Initialize the cumulative sum.
        let cumulative_sum: Ext<_, _> = builder.eval(FC::EF::zero().cons());

        // Assert that the number of proofs is not zero.
        // builder.assert_usize_eq(base_proofs.len(), 1);
        builder.assert_usize_ne(base_proofs.len(), 0);

        // Verify proofs, validate transitions, and update accumulation variables.
        builder.range(0, base_proofs.len()).for_each(|i, builder| {
            // Load the proof.
            let proof = builder.get(&base_proofs, i);

            // Verify each chunk
            let mut challenger = base_challenger.copy(builder);

            StarkVerifier::<FC, SC>::verify_chunk(
                builder,
                &vk,
                pcs,
                machine.chips(),
                &machine.preprocessed_chip_ids(),
                &mut challenger,
                &proof,
                false,
            );

            // Update the reconstruct challenger.
            reconstruct_challenger.observe(builder, proof.commitment.main_commit.clone());
            for j in 0..machine.num_public_values() {
                let element = builder.get(&proof.public_values, j);
                reconstruct_challenger.observe(builder, element);
            }

            // Cumulative sum is updated by sums of all chips.
            let opened_values = proof.opened_values.chips_opened_values;
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
            // Collect the cumulative sum.
            let cumulative_sum_array = builder.ext2felt(cumulative_sum);
            let cumulative_sum_array = array::from_fn(|i| builder.get(&cumulative_sum_array, i));

            // Collect the flag_complete flag.
            let is_complete_felt = var2felt(builder, flag_complete);

            // Initialize the public values we will commit to.
            let zero: Felt<_> = builder.eval(FC::F::zero());

            let mut recursion_public_values_stream = [zero; RECURSION_NUM_PVS];
            let recursion_public_values: &mut RecursionPublicValues<_> =
                recursion_public_values_stream.as_mut_slice().borrow_mut();

            recursion_public_values.base_challenger = leaf_challenger_public_values;
            recursion_public_values.cumulative_sum = cumulative_sum_array;
            recursion_public_values.flag_complete = is_complete_felt;

            // Assert complete
            builder.if_eq(flag_complete, FC::N::one()).then(|builder| {
                Self::assert_simple_complete(
                    builder,
                    recursion_public_values,
                    &reconstruct_challenger,
                )
            });

            commit_public_values(builder, recursion_public_values);
        }
    }

    pub(crate) fn assert_simple_complete(
        builder: &mut Builder<FC>,
        public_values: &RecursionPublicValues<Felt<FC::F>>,
        end_reconstruct_challenger: &DuplexChallengerVariable<FC>,
    ) {
        let RecursionPublicValues {
            cumulative_sum,
            base_challenger,
            ..
        } = public_values;

        // Assert that the end reconstruct challenger is equal to the leaf challenger.
        assert_challenger_eq_pv(builder, end_reconstruct_challenger, *base_challenger);

        // Assert that the cumulative sum is zero.
        for b in cumulative_sum.iter() {
            builder.assert_felt_eq(*b, FC::F::zero());
        }
    }
}
