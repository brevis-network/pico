use crate::{
    compiler::recursion_v2::{
        circuit::{
            challenger::{CanObserveVariable, MultiField32ChallengerVariable},
            config::{CircuitConfig, FieldFriConfigVariable},
            constraints::RecursiveVerifierConstraintFolder,
            stark::{BaseProofVariable, StarkVerifier},
            types::{BaseVerifyingKeyVariable, FriProofVariable},
            utils::{field_bytes_to_bn254, fields_to_bn254, words_to_bytes},
            witness::Witnessable,
        },
        constraints::{Constraint, ConstraintCompiler},
        ir::{Builder, Ext, Felt, Var, Witness},
    },
    configs::config::{Com, FieldGenericConfig, PcsProof, PcsProverData, StarkGenericConfig, Val},
    instances::{
        chiptype::recursion_chiptype_v2::RecursionChipType,
        compiler_v2::onchain_circuit::stdin::{OnchainStdin, OnchainStdinVariable},
    },
    machine::{chip::ChipBehavior, keys::BaseVerifyingKey, machine::BaseMachine, proof::BaseProof},
    primitives::consts::{
        EMBED_DEGREE, EXTENSION_DEGREE, MULTI_FIELD_CHALLENGER_DIGEST_SIZE,
        MULTI_FIELD_CHALLENGER_RATE, MULTI_FIELD_CHALLENGER_WIDTH,
    },
    recursion_v2::air::{assert_embed_public_values_valid, RecursionPublicValues},
};
use p3_air::Air;
use p3_bn254_fr::{Bn254Fr, Poseidon2Bn254};
use p3_challenger::MultiField32Challenger;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::{extension::BinomiallyExtendable, PrimeField32, TwoAdicField};
use std::{borrow::Borrow, fmt::Debug, marker::PhantomData};

#[derive(Debug, Clone, Copy)]
pub struct OnchainVerifierCircuit<
    FC: FieldGenericConfig,
    SC: StarkGenericConfig,
    const W: u32,
    const NUM_EXTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS_MINUS_ONE: usize,
>(PhantomData<(FC, SC)>);

impl<
        CC,
        SC,
        const W: u32,
        const NUM_EXTERNAL_ROUNDS: usize,
        const NUM_INTERNAL_ROUNDS: usize,
        const NUM_INTERNAL_ROUNDS_MINUS_ONE: usize,
    >
    OnchainVerifierCircuit<
        CC,
        SC,
        W,
        NUM_EXTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS_MINUS_ONE,
    >
where
    CC: CircuitConfig<N = Bn254Fr> + Debug,
    CC::F: TwoAdicField
        + PrimeField32
        + BinomiallyExtendable<EXTENSION_DEGREE>
        + Witnessable<CC, WitnessVariable = Felt<Val<SC>>>,
    CC::EF: Witnessable<CC, WitnessVariable = Ext<CC::F, CC::EF>>,
    SC: FieldFriConfigVariable<
        CC,
        Val = CC::F,
        Domain = TwoAdicMultiplicativeCoset<CC::F>,
        FriChallengerVariable = MultiField32ChallengerVariable<CC>,
        Challenger = MultiField32Challenger<
            CC::F,
            Bn254Fr,
            Poseidon2Bn254<{ MULTI_FIELD_CHALLENGER_WIDTH }>,
            { MULTI_FIELD_CHALLENGER_WIDTH },
            { MULTI_FIELD_CHALLENGER_RATE },
        >,
        DigestVariable = [Var<Bn254Fr>; MULTI_FIELD_CHALLENGER_DIGEST_SIZE],
    >,
    Com<SC>: Witnessable<CC, WitnessVariable = SC::DigestVariable> + Send + Sync,
    PcsProof<SC>: Witnessable<CC, WitnessVariable = FriProofVariable<CC, SC>>,
    PcsProverData<SC>: Send + Sync,
    BaseProof<SC>: Witnessable<CC, WitnessVariable = BaseProofVariable<CC, SC>>,
    BaseVerifyingKey<SC>: Witnessable<CC, WitnessVariable = BaseVerifyingKeyVariable<CC, SC>>,
    OnchainStdin<
        SC,
        RecursionChipType<
            Val<SC>,
            EMBED_DEGREE,
            W,
            NUM_EXTERNAL_ROUNDS,
            NUM_INTERNAL_ROUNDS,
            NUM_INTERNAL_ROUNDS_MINUS_ONE,
        >,
    >: Witnessable<CC, WitnessVariable = OnchainStdinVariable<CC, SC>>,

    RecursionChipType<
        Val<SC>,
        EMBED_DEGREE,
        W,
        NUM_EXTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS_MINUS_ONE,
    >: ChipBehavior<Val<SC>> + for<'b> Air<RecursiveVerifierConstraintFolder<'b, CC>>,
{
    pub fn build(
        input: &OnchainStdin<
            SC,
            RecursionChipType<
                Val<SC>,
                EMBED_DEGREE,
                W,
                NUM_EXTERNAL_ROUNDS,
                NUM_INTERNAL_ROUNDS,
                NUM_INTERNAL_ROUNDS_MINUS_ONE,
            >,
        >,
    ) -> (Vec<Constraint>, Witness<CC>) {
        tracing::info!("building gnark constraints");
        let constraints = {
            let mut builder = Builder::<CC>::default();

            let input_var = input.read(&mut builder);

            Self::build_verifier(&mut builder, &input.machine, &input_var);

            let mut backend = ConstraintCompiler::<CC>::default();
            backend.emit(builder.into_operations())
        };

        tracing::info!("building gnark witness");

        let witness = {
            // TODO, better method?// let pv: &RecursionPublicValues<BabyBear> = template_proof.public_values.as_slice().borrow();
            let binding = input.proof.public_values.to_vec();
            let pv: &RecursionPublicValues<CC::F> = binding.as_slice().borrow();
            let vkey_hash = fields_to_bn254(&pv.riscv_vk_digest);
            let committed_values_digest_bytes: [CC::F; 32] =
                words_to_bytes(&pv.committed_value_digest)
                    .try_into()
                    .unwrap();
            let committed_values_digest = field_bytes_to_bn254(&committed_values_digest_bytes);

            tracing::info!("building template witness");
            let mut witness = Witness::default();
            input.write(&mut witness);
            witness.write_committed_values_digest(committed_values_digest);
            witness.write_vkey_hash(vkey_hash);
            witness
        };

        (constraints, witness)
    }

    pub fn build_verifier(
        builder: &mut Builder<CC>,
        machine: &BaseMachine<
            SC,
            RecursionChipType<
                Val<SC>,
                EMBED_DEGREE,
                W,
                NUM_EXTERNAL_ROUNDS,
                NUM_INTERNAL_ROUNDS,
                NUM_INTERNAL_ROUNDS_MINUS_ONE,
            >,
        >,
        input: &OnchainStdinVariable<CC, SC>,
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

        assert_embed_public_values_valid::<CC, SC>(builder, embed_public_values);

        // Reflect the public values to the next level.
        SC::commit_recursion_public_values(builder, *embed_public_values);
    }
}
