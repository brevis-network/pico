use super::super::stdin::{RecursionStdin, RecursionStdinVariable};
use crate::{
    compiler::recursion_v2::{
        circuit::{
            challenger::CanObserveVariable,
            config::{BabyBearFriConfigVariable, CircuitConfig},
            stark::StarkVerifier,
            witness::Witnessable,
        },
        ir::compiler::DslIrCompiler,
        prelude::*,
        program::RecursionProgram,
    },
    configs::config::{FieldGenericConfig, StarkGenericConfig, Val},
    instances::{
        chiptype::recursion_chiptype_v2::RecursionChipType,
        configs::recur_config::{
            FieldConfig as RiscvFC, FieldConfig as RecursionFC, StarkConfig as RecursionSC,
        },
    },
    machine::machine::BaseMachine,
    primitives::consts::COMPRESS_DEGREE,
    recursion_v2::air::{
        assert_recursion_public_values_valid, embed_public_values_digest, RecursionPublicValues,
    },
};
use p3_field::FieldAlgebra;
use std::{borrow::BorrowMut, marker::PhantomData};

#[derive(Debug, Clone, Copy)]
pub struct EmbedVerifierCircuit<FC: FieldGenericConfig, SC: StarkGenericConfig>(
    PhantomData<(FC, SC)>,
);

impl EmbedVerifierCircuit<RecursionFC, RecursionSC> {
    pub fn build(
        machine: &BaseMachine<RecursionSC, RecursionChipType<Val<RecursionSC>, COMPRESS_DEGREE>>,
        input: &RecursionStdin<RecursionSC, RecursionChipType<Val<RecursionSC>, COMPRESS_DEGREE>>,
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

impl<CC, SC> EmbedVerifierCircuit<CC, SC>
where
    SC: BabyBearFriConfigVariable<CC>,
    CC: CircuitConfig<F = SC::Val, EF = SC::Challenge>,
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
            ..
        } = input;

        // Must only have one proof.
        assert_eq!(proofs.len(), 1);
        assert_eq!(vks.len(), 1);

        let vk = vks.pop().unwrap();
        let chunk_proof = proofs.pop().unwrap();

        let one: Felt<_> = builder.eval(CC::F::ONE);
        let zero: Felt<_> = builder.eval(CC::F::ZERO);
        let zero_ext: Ext<CC::F, CC::EF> = builder.eval(zero);

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

            StarkVerifier::verify_chunk(
                builder,
                &vk,
                machine,
                &mut challenger,
                &chunk_proof,
                &[zero_ext, zero_ext],
            );
        }

        /*
        Update public values
         */
        let mut compress_public_values_stream = chunk_proof.public_values;
        let compress_public_values: &mut RecursionPublicValues<_> =
            compress_public_values_stream.as_mut_slice().borrow_mut();

        // validate digest
        assert_recursion_public_values_valid::<CC, SC>(builder, compress_public_values);

        compress_public_values.digest =
            embed_public_values_digest::<CC, SC>(builder, compress_public_values);

        /*
        Commit public values
         */
        SC::commit_recursion_public_values(builder, *compress_public_values);
    }
}
