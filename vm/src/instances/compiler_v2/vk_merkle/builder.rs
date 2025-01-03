use crate::{
    compiler::recursion_v2::{
        circuit::{
            config::{BabyBearFriConfigVariable, CircuitConfig},
            constraints::RecursiveVerifierConstraintFolder,
            merkle_tree::merkle_verify,
            witness::Witnessable,
        },
        ir::{compiler::DslIrCompiler, Builder, Felt},
        program::RecursionProgram,
    },
    configs::config::{FieldGenericConfig, StarkGenericConfig, Val},
    instances::{
        chiptype::recursion_chiptype_v2::RecursionChipType,
        compiler_v2::{
            recursion_circuit::{
                combine::builder::CombineVerifierCircuit,
                compress::builder::CompressVerifierCircuit, embed::builder::EmbedVerifierCircuit,
            },
            vk_merkle::{
                stdin::{MerkleProofStdinVariable, RecursionVkStdin, RecursionVkStdinVariable},
                VkMerkleManager,
            },
        },
        configs::{
            recur_bb_poseidon2::{FieldConfig, StarkConfig},
            recur_config::{FieldConfig as RecursionFC, StarkConfig as RecursionSC},
        },
    },
    machine::{
        chip::ChipBehavior,
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        machine::BaseMachine,
    },
    primitives::consts::{COMBINE_DEGREE, COMPRESS_DEGREE},
    recursion_v2::runtime::RecursionRecord,
};
use p3_air::Air;
use p3_baby_bear::BabyBear;
use std::marker::PhantomData;

#[derive(Debug, Clone, Copy)]
pub struct CombineVkVerifierCircuit<FC: FieldGenericConfig, SC: StarkGenericConfig, C>(
    PhantomData<(FC, SC, C)>,
);

impl<C> CombineVkVerifierCircuit<FieldConfig, StarkConfig, C>
where
    C: ChipBehavior<
            Val<RecursionSC>,
            Program = RecursionProgram<Val<RecursionSC>>,
            Record = RecursionRecord<Val<RecursionSC>>,
        > + for<'a> Air<ProverConstraintFolder<'a, RecursionSC>>
        + for<'a> Air<VerifierConstraintFolder<'a, RecursionSC>>
        + for<'a> Air<RecursiveVerifierConstraintFolder<'a, RecursionFC>>,
{
    pub fn build(
        machine: &BaseMachine<RecursionSC, C>,
        input: &RecursionVkStdin<RecursionSC, C>,
    ) -> RecursionProgram<Val<RecursionSC>> {
        // Construct the builder.
        let mut builder = Builder::<RecursionFC>::new();
        let input = input.read(&mut builder);
        let RecursionVkStdinVariable {
            resursion_stdin_var,
            merkle_proof_var,
        } = input;

        let vk_root: [Felt<BabyBear>; 8] = merkle_proof_var.merkle_root.map(|x| builder.eval(x));

        // Constraint that the vk_root of the merkle tree aligns with the vk_root of the recursion_stdin
        for (expected, actual) in vk_root.iter().zip(resursion_stdin_var.vk_root.iter()) {
            builder.assert_felt_eq(*expected, *actual);
        }

        // Constraint that ensures all the vk of the recursion program are included in the vk Merkle tree.
        let vk_digests = resursion_stdin_var
            .vks
            .iter()
            .map(|vk| vk.hash_babybear(&mut builder))
            .collect::<Vec<_>>();

        MerkleProofVerifier::verify(&mut builder, vk_digests, merkle_proof_var);
        CombineVerifierCircuit::build_verifier(&mut builder, machine, resursion_stdin_var);
        let operations = builder.into_operations();

        // Compile the program.
        let mut compiler = DslIrCompiler::<FieldConfig>::default();
        compiler.compile(operations)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MerkleProofVerifier<C, SC> {
    _phantom: PhantomData<(C, SC)>,
}

impl<CC, SC> MerkleProofVerifier<CC, SC>
where
    SC: BabyBearFriConfigVariable<CC>,
    CC: CircuitConfig<F = SC::Val, EF = SC::Challenge>,
{
    /// Verify (via Merkle tree) that the vkey digests of a proof belong to a specified set (encoded
    /// the Merkle tree proofs in input).
    pub fn verify(
        builder: &mut Builder<CC>,
        digests: Vec<SC::DigestVariable>,
        input: MerkleProofStdinVariable<CC, SC>,
    ) {
        let MerkleProofStdinVariable {
            vk_merkle_proofs,
            vk_values,
            merkle_root,
        } = input;
        for ((proof, value), expected_value) in
            vk_merkle_proofs.into_iter().zip(vk_values).zip(digests)
        {
            merkle_verify(builder, proof, value, merkle_root);
            SC::assert_digest_eq(builder, expected_value, value);
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct CompressVkVerifierCircuit<FC: FieldGenericConfig, SC: StarkGenericConfig>(
    PhantomData<(FC, SC)>,
);

impl CompressVkVerifierCircuit<FieldConfig, StarkConfig> {
    pub fn build(
        machine: &BaseMachine<StarkConfig, RecursionChipType<Val<StarkConfig>, COMBINE_DEGREE>>,
        input: &RecursionVkStdin<StarkConfig, RecursionChipType<Val<StarkConfig>, COMBINE_DEGREE>>,
    ) -> RecursionProgram<Val<StarkConfig>> {
        // Construct the builder.
        let mut builder = Builder::<FieldConfig>::new();
        let input = input.read(&mut builder);
        let RecursionVkStdinVariable {
            resursion_stdin_var,
            merkle_proof_var,
        } = input;

        let vk_root: [Felt<BabyBear>; 8] = merkle_proof_var.merkle_root.map(|x| builder.eval(x));

        // Constraint that the vk_root of the merkle tree aligns with the vk_root of the recursion_stdin
        for (expected, actual) in vk_root.iter().zip(resursion_stdin_var.vk_root.iter()) {
            builder.assert_felt_eq(*expected, *actual);
        }

        // Constraint that ensures all the vk of the recursion program are included in the vk Merkle tree.
        let vk_digests = resursion_stdin_var
            .vks
            .iter()
            .map(|vk| vk.hash_babybear(&mut builder))
            .collect::<Vec<_>>();

        MerkleProofVerifier::verify(&mut builder, vk_digests, merkle_proof_var);

        CompressVerifierCircuit::build_verifier(&mut builder, machine, resursion_stdin_var);

        let operations = builder.into_operations();

        // Compile the program.
        let mut compiler = DslIrCompiler::<FieldConfig>::default();
        compiler.compile(operations)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EmbedVkVerifierCircuit<FC: FieldGenericConfig, SC: StarkGenericConfig>(
    PhantomData<(FC, SC)>,
);

impl EmbedVkVerifierCircuit<FieldConfig, StarkConfig> {
    pub fn build(
        machine: &BaseMachine<StarkConfig, RecursionChipType<Val<StarkConfig>, COMPRESS_DEGREE>>,
        input: &RecursionVkStdin<StarkConfig, RecursionChipType<Val<StarkConfig>, COMPRESS_DEGREE>>,
        vk_manager: VkMerkleManager,
    ) -> RecursionProgram<Val<StarkConfig>> {
        // Construct the builder.
        let mut builder = Builder::<FieldConfig>::new();
        let input = input.read(&mut builder);

        // static vk_root in the embed circuit
        let static_vk_root: [Felt<BabyBear>; 8] = vk_manager.merkle_root.map(|x| builder.eval(x));

        let RecursionVkStdinVariable {
            resursion_stdin_var,
            merkle_proof_var,
        } = input;

        let vk_root: [Felt<BabyBear>; 8] = merkle_proof_var.merkle_root.map(|x| builder.eval(x));

        // Constraint that the vk_root of the merkle tree aligns with the hardcoded vk_root
        for (expected, actual) in vk_root.iter().zip(static_vk_root.iter()) {
            builder.assert_felt_eq(*expected, *actual);
        }

        // Constraint that the vk_root of the merkle tree aligns with the vk_root of the recursion_stdin
        for (expected, actual) in vk_root.iter().zip(resursion_stdin_var.vk_root.iter()) {
            builder.assert_felt_eq(*expected, *actual);
        }

        // Constraint that ensures all the vk of the recursion program are included in the vk Merkle tree.
        let vk_digests = resursion_stdin_var
            .vks
            .iter()
            .map(|vk| vk.hash_babybear(&mut builder))
            .collect::<Vec<_>>();

        MerkleProofVerifier::verify(&mut builder, vk_digests, merkle_proof_var);

        EmbedVerifierCircuit::build_verifier(&mut builder, machine, resursion_stdin_var);

        let operations = builder.into_operations();

        // Compile the program.
        let mut compiler = DslIrCompiler::<FieldConfig>::default();
        compiler.compile(operations)
    }
}
