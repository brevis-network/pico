use super::super::stdin::{RecursionStdin, RecursionStdinVariable};
use crate::{
    compiler::recursion::{
        circuit::{
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
    configs::config::{Challenge, Com, FieldGenericConfig, PcsProof, StarkGenericConfig, Val},
    emulator::recursion::public_values::{
        assert_recursion_public_values_valid, embed_public_values_digest, RecursionPublicValues,
    },
    instances::chiptype::recursion_chiptype::RecursionChipType,
    machine::{chip::ChipBehavior, field::FieldSpecificPoseidon2Config, machine::BaseMachine},
    primitives::consts::{COMPRESS_DEGREE, EXTENSION_DEGREE},
};
use p3_air::Air;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::{extension::BinomiallyExtendable, FieldAlgebra, PrimeField32, TwoAdicField};
use std::{borrow::BorrowMut, fmt::Debug, marker::PhantomData};

#[derive(Debug, Clone, Copy)]
pub struct EmbedVerifierCircuit<FC: FieldGenericConfig, SC: StarkGenericConfig>(
    PhantomData<(FC, SC)>,
);

impl<F, CC, SC> EmbedVerifierCircuit<CC, SC>
where
    F: PrimeField32
        + TwoAdicField
        + Witnessable<CC, WitnessVariable = Felt<CC::F>>
        + BinomiallyExtendable<EXTENSION_DEGREE>
        + FieldSpecificPoseidon2Config,
    CC: CircuitConfig<N = F, F = F, EF = Challenge<SC>, Bit = Felt<F>> + Debug,
    CC::EF: Witnessable<CC, WitnessVariable = Ext<CC::F, CC::EF>>,
    SC: FieldFriConfigVariable<CC, Val = F, Domain = TwoAdicMultiplicativeCoset<F>>,
    Com<SC>: Witnessable<CC, WitnessVariable = SC::DigestVariable>,
    PcsProof<SC>: Witnessable<CC, WitnessVariable = FriProofVariable<CC, SC>>,

    RecursionChipType<Val<SC>, COMPRESS_DEGREE>:
        ChipBehavior<Val<SC>> + for<'b> Air<RecursiveVerifierConstraintFolder<'b, CC>>,
{
    pub fn build(
        machine: &BaseMachine<SC, RecursionChipType<Val<SC>, COMPRESS_DEGREE>>,
        input: &RecursionStdin<SC, RecursionChipType<Val<SC>, COMPRESS_DEGREE>>,
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

impl<CC, SC> EmbedVerifierCircuit<CC, SC>
where
    CC: CircuitConfig<EF = Challenge<SC>>,
    CC::F: TwoAdicField
        + PrimeField32
        + BinomiallyExtendable<EXTENSION_DEGREE>
        + FieldSpecificPoseidon2Config,
    SC: FieldFriConfigVariable<CC, Val = CC::F, Domain = TwoAdicMultiplicativeCoset<CC::F>>,

    RecursionChipType<Val<SC>, COMPRESS_DEGREE>:
        ChipBehavior<Val<SC>> + for<'b> Air<RecursiveVerifierConstraintFolder<'b, CC>>,
{
    pub fn build_verifier(
        builder: &mut Builder<CC>,
        machine: &BaseMachine<SC, RecursionChipType<SC::Val, COMPRESS_DEGREE>>,
        input: RecursionStdinVariable<CC, SC>,
    ) {
        // Read input.
        let RecursionStdinVariable {
            mut vks,
            mut proofs,
            flag_complete,
            vk_root,
        } = input;

        // Must only have one proof.
        assert_eq!(proofs.len(), 1);
        assert_eq!(vks.len(), 1);

        let vk = vks.pop().unwrap();
        let chunk_proof = proofs.pop().unwrap();

        let one: Felt<_> = builder.eval(CC::F::ONE);

        // Flag must be complete.
        builder.assert_felt_eq(flag_complete, one);

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

            StarkVerifier::verify_chunk(builder, &vk, machine, &mut challenger, &chunk_proof);
        }

        /*
        Update public values
         */
        let mut compress_public_values_stream = chunk_proof.public_values;
        let compress_public_values: &mut RecursionPublicValues<_> =
            compress_public_values_stream.as_mut_slice().borrow_mut();

        // validate digest
        assert_recursion_public_values_valid::<CC, SC>(builder, compress_public_values);

        // validate vk_root
        for (expected, actual) in vk_root.iter().zip(compress_public_values.vk_root.iter()) {
            builder.assert_felt_eq(*expected, *actual);
        }

        compress_public_values.digest =
            embed_public_values_digest::<CC, SC>(builder, compress_public_values);

        /*
        Commit public values
         */
        SC::commit_recursion_public_values(builder, *compress_public_values);
    }
}
