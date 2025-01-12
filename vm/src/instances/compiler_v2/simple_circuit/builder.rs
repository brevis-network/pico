use super::stdin::{SimpleRecursionStdin, SimpleRecursionStdinVariable};
use crate::{
    compiler::recursion_v2::{
        circuit::{
            challenger::{CanObserveVariable, DuplexChallengerVariable},
            config::{BabyBearFriConfig, BabyBearFriConfigVariable, CircuitConfig},
            stark::StarkVerifier,
            witness::Witnessable,
            CircuitV2Builder,
        },
        ir::{compiler::DslIrCompiler, Builder, Felt},
        program::RecursionProgram,
    },
    configs::stark_config::bb_poseidon2::BabyBearPoseidon2,
    instances::{
        chiptype::riscv_chiptype::RiscvChipType, configs::recur_config::FieldConfig as RiscvFC,
    },
    machine::machine::BaseMachine,
    primitives::consts::{DIGEST_SIZE, RECURSION_NUM_PVS_V2},
    recursion_v2::air::RecursionPublicValues,
};
use p3_baby_bear::BabyBear;
use p3_field::FieldAlgebra;
use std::{borrow::BorrowMut, marker::PhantomData};

/// A program for recursively verifying a batch of Pico proofs.
#[derive(Debug, Clone, Copy)]
pub struct SimpleVerifierCircuit<CC: CircuitConfig, SC: BabyBearFriConfig> {
    _phantom: PhantomData<(CC, SC)>,
}

impl SimpleVerifierCircuit<RiscvFC, BabyBearPoseidon2> {
    pub fn build(
        machine: &BaseMachine<BabyBearPoseidon2, RiscvChipType<BabyBear>>,
        input: &SimpleRecursionStdin<BabyBearPoseidon2, RiscvChipType<BabyBear>>,
    ) -> RecursionProgram<BabyBear> {
        let mut builder = Builder::<RiscvFC>::default();

        let input = input.read(&mut builder);

        Self::build_verifier(&mut builder, machine, input);

        let operations = builder.into_operations();

        // Compile the program.
        let mut compiler = DslIrCompiler::<RiscvFC>::default();

        compiler.compile(operations)
    }
}

impl<CC, SC> SimpleVerifierCircuit<CC, SC>
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
        input: SimpleRecursionStdinVariable<CC, SC>,
    ) {
        // Read input.
        let SimpleRecursionStdinVariable {
            vk,
            base_proofs,
            flag_complete: _,
            flag_first_chunk: _,
        } = input;

        // Initialize the cumulative sum.
        let mut global_cumulative_sums = Vec::new();

        // Assert that the number of proofs is not zero.
        // builder.assert_usize_eq(base_proofs.len(), 1);
        assert!(!base_proofs.is_empty());

        // Verify proofs, validate transitions, and update accumulation variables.
        for base_proof in base_proofs.into_iter() {
            // Prepare a challenger.
            let mut challenger = {
                let mut challenger = machine.config().challenger_variable(builder);
                vk.observed_by(builder, &mut challenger);

                challenger.observe_slice(
                    builder,
                    base_proof.public_values[0..machine.num_public_values()]
                        .iter()
                        .copied(),
                );

                challenger
            };

            /*
            Verify chunk proof
             */
            StarkVerifier::<CC, SC, RiscvChipType<SC::Val>>::verify_chunk(
                builder,
                &vk,
                machine,
                &mut challenger,
                &base_proof,
            );

            // Cumulative sum is updated by sums of all chips.
            for values in base_proof.opened_values.chips_opened_values.iter() {
                global_cumulative_sums.push(values.global_cumulative_sum);
            }
        }

        // Write all values to the public values struct and commit to them.
        {
            // Collect the cumulative sum.
            let global_cumulative_sum = builder.sum_digest_v2(global_cumulative_sums);

            // Initialize the public values we will commit to.
            let zero: Felt<_> = builder.eval(CC::F::ZERO);

            let mut recursion_public_values_stream = [zero; RECURSION_NUM_PVS_V2];
            let recursion_public_values: &mut RecursionPublicValues<_> =
                recursion_public_values_stream.as_mut_slice().borrow_mut();

            recursion_public_values.global_cumulative_sum = global_cumulative_sum;

            SC::commit_recursion_public_values(builder, *recursion_public_values);
        }
    }
}
