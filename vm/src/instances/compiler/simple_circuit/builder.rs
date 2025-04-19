use super::stdin::{SimpleRecursionStdin, SimpleRecursionStdinVariable};
use crate::{
    chips::{
        chips::riscv_poseidon2::FieldSpecificPoseidon2Chip,
        precompiles::poseidon2::FieldSpecificPrecompilePoseidon2Chip,
    },
    compiler::recursion::{
        circuit::{
            challenger::{CanObserveVariable, DuplexChallengerVariable},
            config::{CircuitConfig, FieldFriConfig, FieldFriConfigVariable},
            constraints::RecursiveVerifierConstraintFolder,
            stark::StarkVerifier,
            types::FriProofVariable,
            witness::Witnessable,
            CircuitBuilder,
        },
        ir::{compiler::DslIrCompiler, Builder, Ext, Felt},
        program::RecursionProgram,
    },
    configs::config::{Challenger, Com, PcsProof, Val},
    emulator::recursion::public_values::RecursionPublicValues,
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::{field::FieldSpecificPoseidon2Config, machine::BaseMachine},
    primitives::consts::{DIGEST_SIZE, RECURSION_NUM_PVS},
};
use p3_air::Air;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::{PrimeField32, TwoAdicField};
use std::{borrow::BorrowMut, fmt::Debug, marker::PhantomData};

/// A program for recursively verifying a batch of Pico proofs.
#[derive(Debug, Clone, Copy)]
pub struct SimpleVerifierCircuit<CC: CircuitConfig, SC: FieldFriConfig> {
    _phantom: PhantomData<(CC, SC)>,
}

impl<F, CC, SC> SimpleVerifierCircuit<CC, SC>
where
    F: TwoAdicField
        + PrimeField32
        + Witnessable<CC, WitnessVariable = Felt<CC::F>>
        + FieldSpecificPoseidon2Config,
    CC: CircuitConfig<N = F, F = F, Bit = Felt<F>> + Debug,
    CC::EF: Witnessable<CC, WitnessVariable = Ext<CC::F, CC::EF>>,
    SC: FieldFriConfigVariable<
        CC,
        Val = F,
        Challenge = CC::EF,
        Domain = TwoAdicMultiplicativeCoset<F>,
        FriChallengerVariable = DuplexChallengerVariable<CC>,
        DigestVariable = [Felt<F>; DIGEST_SIZE],
    >,
    Com<SC>: Witnessable<CC, WitnessVariable = SC::DigestVariable>,
    PcsProof<SC>: Witnessable<CC, WitnessVariable = FriProofVariable<CC, SC>>,
    Challenger<SC>: Witnessable<CC, WitnessVariable = SC::FriChallengerVariable>,
    FieldSpecificPoseidon2Chip<F>: for<'b> Air<RecursiveVerifierConstraintFolder<'b, CC>>,
    FieldSpecificPrecompilePoseidon2Chip<F>: for<'b> Air<RecursiveVerifierConstraintFolder<'b, CC>>,
{
    pub fn build(
        machine: &BaseMachine<SC, RiscvChipType<Val<SC>>>,
        input: &SimpleRecursionStdin<SC, RiscvChipType<Val<SC>>>,
    ) -> RecursionProgram<Val<SC>> {
        let mut builder = Builder::<CC>::default();

        let input = input.read(&mut builder);

        Self::build_verifier(&mut builder, machine, input);

        let operations = builder.into_operations();

        // Compile the program.
        let mut compiler = DslIrCompiler::<CC>::default();

        compiler.compile(operations)
    }
}

impl<F, CC, SC> SimpleVerifierCircuit<CC, SC>
where
    F: TwoAdicField + PrimeField32 + FieldSpecificPoseidon2Config,
    CC: CircuitConfig<N = F, F = F, EF = SC::Challenge, Bit = Felt<F>> + Debug,
    SC: FieldFriConfigVariable<
        CC,
        Val = F,
        Domain = TwoAdicMultiplicativeCoset<F>,
        FriChallengerVariable = DuplexChallengerVariable<CC>,
        DigestVariable = [Felt<F>; DIGEST_SIZE],
    >,
    FieldSpecificPoseidon2Chip<F>: for<'b> Air<RecursiveVerifierConstraintFolder<'b, CC>>,
    FieldSpecificPrecompilePoseidon2Chip<F>: for<'b> Air<RecursiveVerifierConstraintFolder<'b, CC>>,
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
            for values in base_proof.opened_values.iter() {
                global_cumulative_sums.push(values.global_cumulative_sum);
            }
        }

        // Write all values to the public values struct and commit to them.
        {
            // Collect the cumulative sum.
            let global_cumulative_sum = builder.sum_digest(global_cumulative_sums);

            // Initialize the public values we will commit to.
            let zero: Felt<_> = builder.eval(CC::F::ZERO);

            let mut recursion_public_values_stream = [zero; RECURSION_NUM_PVS];
            let recursion_public_values: &mut RecursionPublicValues<_> =
                recursion_public_values_stream.as_mut_slice().borrow_mut();

            recursion_public_values.global_cumulative_sum = global_cumulative_sum;

            SC::commit_recursion_public_values(builder, *recursion_public_values);
        }
    }
}
