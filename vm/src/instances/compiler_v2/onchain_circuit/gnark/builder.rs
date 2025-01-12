use crate::{
    compiler::recursion_v2::{
        circuit::{
            challenger::CanObserveVariable,
            config::BabyBearFriConfigVariable,
            stark::StarkVerifier,
            utils::{babybear_bytes_to_bn254, babybears_to_bn254, words_to_bytes},
            witness::Witnessable,
        },
        constraints::{Constraint, ConstraintCompiler},
        ir::{Builder, Witness},
    },
    configs::config::{FieldGenericConfig, StarkGenericConfig, Val},
    instances::{
        chiptype::recursion_chiptype_v2::RecursionChipType,
        compiler_v2::onchain_circuit::stdin::{OnchainStdin, OnchainStdinVariable},
        configs::embed_config::{FieldConfig as EmbedFC, StarkConfig as EmbedSC},
    },
    machine::machine::BaseMachine,
    primitives::consts::EMBED_DEGREE,
    recursion_v2::air::{assert_embed_public_values_valid, RecursionPublicValues},
};
use p3_baby_bear::BabyBear;
use std::{borrow::Borrow, marker::PhantomData};

#[derive(Debug, Clone, Copy)]
pub struct OnchainVerifierCircuit<FC: FieldGenericConfig, SC: StarkGenericConfig>(
    PhantomData<(FC, SC)>,
);

impl OnchainVerifierCircuit<EmbedFC, EmbedSC> {
    pub fn build(
        input: &OnchainStdin<EmbedSC, RecursionChipType<Val<EmbedSC>, EMBED_DEGREE>>,
    ) -> (Vec<Constraint>, Witness<EmbedFC>) {
        tracing::info!("building gnark constraints");
        let constraints = {
            let mut builder = Builder::<EmbedFC>::default();

            let input_var = input.read(&mut builder);

            Self::build_verifier(&mut builder, input.machine, &input_var);

            let mut backend = ConstraintCompiler::<EmbedFC>::default();
            backend.emit(builder.into_operations())
        };

        tracing::info!("building gnark witness");

        let witness = {
            let binding = input.proof.public_values.to_vec();
            let pv: &RecursionPublicValues<BabyBear> = binding.as_slice().borrow();
            let vkey_hash = babybears_to_bn254(&pv.riscv_vk_digest);
            let committed_values_digest_bytes: [BabyBear; 32] =
                words_to_bytes(&pv.committed_value_digest)
                    .try_into()
                    .unwrap();
            let committed_values_digest = babybear_bytes_to_bn254(&committed_values_digest_bytes);

            let mut witness = Witness::default();
            input.write(&mut witness);
            witness.write_committed_values_digest(committed_values_digest);
            witness.write_vkey_hash(vkey_hash);
            witness
        };

        (constraints, witness)
    }

    pub fn build_verifier(
        builder: &mut Builder<EmbedFC>,
        machine: &BaseMachine<EmbedSC, RecursionChipType<BabyBear, EMBED_DEGREE>>,
        input: &OnchainStdinVariable<EmbedFC, EmbedSC>,
    ) {
        let OnchainStdinVariable { vk, proof, .. } = input;

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
                proof.public_values[0..machine.num_public_values()]
                    .iter()
                    .copied(),
            );

            StarkVerifier::verify_chunk(builder, vk, machine, &mut challenger, proof);
        }

        // Get the public values, and assert that they are valid.
        let embed_public_values = proof.public_values.as_slice().borrow();

        assert_embed_public_values_valid::<EmbedFC, EmbedSC>(builder, embed_public_values);

        // Reflect the public values to the next level.
        EmbedSC::commit_recursion_public_values(builder, *embed_public_values);
    }
}
