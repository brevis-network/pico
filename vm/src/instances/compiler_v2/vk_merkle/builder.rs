use crate::{
    chips::chips::poseidon2_p3::{
        BabyBearPoseidon2Chip, KoalaBearPoseidon2Chip, Mersenne31Poseidon2Chip,
    },
    compiler::recursion_v2::{
        circuit::{
            config::{CircuitConfig, FieldFriConfigVariable},
            constraints::RecursiveVerifierConstraintFolder,
            hash::FieldHasher,
            merkle_tree::merkle_verify,
            types::FriProofVariable,
            witness::Witnessable,
        },
        ir::{compiler::DslIrCompiler, Builder, Ext, Felt},
        program::RecursionProgram,
    },
    configs::config::{Com, FieldGenericConfig, PcsProof, StarkGenericConfig, Val},
    emulator::recursion::emulator::RecursionRecord,
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
    },
    machine::{chip::ChipBehavior, field::FieldSpecificPoseidon2Config, machine::BaseMachine},
    primitives::consts::{COMBINE_DEGREE, COMPRESS_DEGREE, DIGEST_SIZE, EXTENSION_DEGREE},
};
use p3_air::Air;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::{extension::BinomiallyExtendable, PrimeField32, TwoAdicField};
use std::{fmt::Debug, marker::PhantomData};

#[derive(Debug, Clone, Copy)]
pub struct CombineVkVerifierCircuit<FC: FieldGenericConfig, SC: StarkGenericConfig, C>(
    PhantomData<(FC, SC, C)>,
);

impl<CC, SC, C> CombineVkVerifierCircuit<CC, SC, C>
where
    CC: CircuitConfig<N = Val<SC>, F = Val<SC>> + Debug,
    CC::F: TwoAdicField
        + PrimeField32
        + BinomiallyExtendable<EXTENSION_DEGREE>
        + Witnessable<CC, WitnessVariable = Felt<CC::F>>,
    CC::EF: Witnessable<CC, WitnessVariable = Ext<CC::F, CC::EF>>,
    SC: FieldFriConfigVariable<
            CC,
            Challenge = CC::EF,
            Domain = TwoAdicMultiplicativeCoset<CC::F>,
            DigestVariable = [Felt<Val<SC>>; DIGEST_SIZE],
        > + FieldHasher<Val<SC>>,
    <SC as FieldHasher<Val<SC>>>::Digest: Witnessable<CC, WitnessVariable = SC::DigestVariable>,
    Com<SC>: Witnessable<CC, WitnessVariable = SC::DigestVariable>,
    PcsProof<SC>: Witnessable<CC, WitnessVariable = FriProofVariable<CC, SC>>,
    C: ChipBehavior<
            Val<SC>,
            Program = RecursionProgram<Val<SC>>,
            Record = RecursionRecord<Val<SC>>,
        > + for<'a> Air<RecursiveVerifierConstraintFolder<'a, CC>>,
{
    pub fn build(
        machine: &BaseMachine<SC, C>,
        input: &RecursionVkStdin<SC, C>,
    ) -> RecursionProgram<Val<SC>> {
        // Construct the builder.
        let mut builder = Builder::<CC>::new();
        let input = input.read(&mut builder);
        let RecursionVkStdinVariable {
            resursion_stdin_var,
            merkle_proof_var,
        } = input;

        let vk_root: [Felt<Val<SC>>; 8] = merkle_proof_var.merkle_root.map(|x| builder.eval(x));

        // Constraint that the vk_root of the merkle tree aligns with the vk_root of the recursion_stdin
        for (expected, actual) in vk_root.iter().zip(resursion_stdin_var.vk_root.iter()) {
            builder.assert_felt_eq(*expected, *actual);
        }

        // Constraint that ensures all the vk of the recursion program are included in the vk Merkle tree.
        let vk_digests = resursion_stdin_var
            .vks
            .iter()
            .map(|vk| vk.hash_field(&mut builder))
            .collect::<Vec<_>>();

        MerkleProofVerifier::verify(&mut builder, vk_digests, merkle_proof_var);
        CombineVerifierCircuit::build_verifier(&mut builder, machine, resursion_stdin_var);
        let operations = builder.into_operations();

        // Compile the program.
        let mut compiler = DslIrCompiler::<CC>::default();
        compiler.compile(operations)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct MerkleProofVerifier<C, SC> {
    _phantom: PhantomData<(C, SC)>,
}

impl<CC, SC> MerkleProofVerifier<CC, SC>
where
    SC: FieldFriConfigVariable<CC>,
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

impl<CC, SC> CompressVkVerifierCircuit<CC, SC>
where
    CC: CircuitConfig<N = Val<SC>, F = Val<SC>> + Debug,
    CC::F: TwoAdicField
        + PrimeField32
        + Witnessable<CC, WitnessVariable = Felt<CC::F>>
        + BinomiallyExtendable<EXTENSION_DEGREE>
        + FieldSpecificPoseidon2Config,
    // TODO: why do we need this?
    Val<SC>: FieldSpecificPoseidon2Config,
    CC::EF: Witnessable<CC, WitnessVariable = Ext<CC::F, CC::EF>>,
    SC: FieldFriConfigVariable<
        CC,
        Challenge = CC::EF,
        Domain = TwoAdicMultiplicativeCoset<CC::F>,
        DigestVariable = [Felt<Val<SC>>; DIGEST_SIZE],
    >,
    Com<SC>: Witnessable<CC, WitnessVariable = SC::DigestVariable>,
    PcsProof<SC>: Witnessable<CC, WitnessVariable = FriProofVariable<CC, SC>>,
    for<'a> RecursionVkStdin<'a, SC, RecursionChipType<Val<SC>, COMPRESS_DEGREE>>:
        Witnessable<CC, WitnessVariable = RecursionVkStdinVariable<CC, SC>>,

    // for<'b> Poseidon2SkinnyChip<
    //     COMBINE_DEGREE,
    //     <CC::F as FieldSpecificPoseidon2Config>::Poseidon2Config,
    //     CC::F,
    // >: Air<RecursiveVerifierConstraintFolder<'b, CC>>,
    // Poseidon2SkinnyChip<
    //     COMBINE_DEGREE,
    //     <CC::F as FieldSpecificPoseidon2Config>::Poseidon2Config,
    //     CC::F,
    // >: ChipBehavior<CC::F, Record = RecursionRecord<CC::F>, Program = RecursionProgram<CC::F>>,
    for<'b> BabyBearPoseidon2Chip<CC::F>: Air<RecursiveVerifierConstraintFolder<'b, CC>>,
    BabyBearPoseidon2Chip<CC::F>:
        ChipBehavior<CC::F, Record = RecursionRecord<CC::F>, Program = RecursionProgram<CC::F>>,
    for<'b> KoalaBearPoseidon2Chip<CC::F>: Air<RecursiveVerifierConstraintFolder<'b, CC>>,
    KoalaBearPoseidon2Chip<CC::F>:
        ChipBehavior<CC::F, Record = RecursionRecord<CC::F>, Program = RecursionProgram<CC::F>>,
    for<'b> Mersenne31Poseidon2Chip<CC::F>: Air<RecursiveVerifierConstraintFolder<'b, CC>>,
    Mersenne31Poseidon2Chip<CC::F>:
        ChipBehavior<CC::F, Record = RecursionRecord<CC::F>, Program = RecursionProgram<CC::F>>,
{
    pub fn build(
        machine: &BaseMachine<SC, RecursionChipType<Val<SC>, COMBINE_DEGREE>>,
        input: &RecursionVkStdin<SC, RecursionChipType<Val<SC>, COMBINE_DEGREE>>,
    ) -> RecursionProgram<Val<SC>> {
        // Construct the builder.
        let mut builder = Builder::<CC>::new();
        let input = input.read(&mut builder);
        let RecursionVkStdinVariable {
            resursion_stdin_var,
            merkle_proof_var,
        } = input;

        let vk_root: [Felt<Val<SC>>; 8] = merkle_proof_var.merkle_root.map(|x| builder.eval(x));

        // Constraint that the vk_root of the merkle tree aligns with the vk_root of the recursion_stdin
        for (expected, actual) in vk_root.iter().zip(resursion_stdin_var.vk_root.iter()) {
            builder.assert_felt_eq(*expected, *actual);
        }

        // Constraint that ensures all the vk of the recursion program are included in the vk Merkle tree.
        let vk_digests = resursion_stdin_var
            .vks
            .iter()
            .map(|vk| vk.hash_field(&mut builder))
            .collect::<Vec<_>>();

        MerkleProofVerifier::verify(&mut builder, vk_digests, merkle_proof_var);

        CompressVerifierCircuit::build_verifier(&mut builder, machine, resursion_stdin_var);

        let operations = builder.into_operations();

        // Compile the program.
        let mut compiler = DslIrCompiler::<CC>::default();
        compiler.compile(operations)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct EmbedVkVerifierCircuit<FC: FieldGenericConfig, SC: StarkGenericConfig>(
    PhantomData<(FC, SC)>,
);

impl<CC, SC> EmbedVkVerifierCircuit<CC, SC>
where
    CC: CircuitConfig<N = Val<SC>, F = Val<SC>> + Debug,
    CC::F: TwoAdicField
        + PrimeField32
        + Witnessable<CC, WitnessVariable = Felt<CC::F>>
        + BinomiallyExtendable<EXTENSION_DEGREE>
        + FieldSpecificPoseidon2Config,
    // TODO: why do we need this?
    Val<SC>: FieldSpecificPoseidon2Config,
    CC::EF: Witnessable<CC, WitnessVariable = Ext<CC::F, CC::EF>>,
    SC: FieldFriConfigVariable<
        CC,
        Challenge = CC::EF,
        Domain = TwoAdicMultiplicativeCoset<CC::F>,
        DigestVariable = [Felt<Val<SC>>; DIGEST_SIZE],
    >,
    SC::DigestVariable: IntoIterator<Item = Felt<CC::F>>,
    Com<SC>: Witnessable<CC, WitnessVariable = SC::DigestVariable>,
    PcsProof<SC>: Witnessable<CC, WitnessVariable = FriProofVariable<CC, SC>>,
    for<'a> RecursionVkStdin<'a, SC, RecursionChipType<Val<SC>, COMPRESS_DEGREE>>:
        Witnessable<CC, WitnessVariable = RecursionVkStdinVariable<CC, SC>>,

    // for<'b> Poseidon2SkinnyChip<
    //     COMBINE_DEGREE,
    //     <CC::F as FieldSpecificPoseidon2Config>::Poseidon2Config,
    //     CC::F,
    // >: Air<RecursiveVerifierConstraintFolder<'b, CC>>,
    // Poseidon2SkinnyChip<
    //     COMBINE_DEGREE,
    //     <CC::F as FieldSpecificPoseidon2Config>::Poseidon2Config,
    //     CC::F,
    // >: ChipBehavior<CC::F, Record = RecursionRecord<CC::F>, Program = RecursionProgram<CC::F>>,
    for<'b> BabyBearPoseidon2Chip<CC::F>: Air<RecursiveVerifierConstraintFolder<'b, CC>>,
    BabyBearPoseidon2Chip<CC::F>:
        ChipBehavior<CC::F, Record = RecursionRecord<CC::F>, Program = RecursionProgram<CC::F>>,
    for<'b> KoalaBearPoseidon2Chip<CC::F>: Air<RecursiveVerifierConstraintFolder<'b, CC>>,
    KoalaBearPoseidon2Chip<CC::F>:
        ChipBehavior<CC::F, Record = RecursionRecord<CC::F>, Program = RecursionProgram<CC::F>>,
    for<'b> Mersenne31Poseidon2Chip<CC::F>: Air<RecursiveVerifierConstraintFolder<'b, CC>>,
    Mersenne31Poseidon2Chip<CC::F>:
        ChipBehavior<CC::F, Record = RecursionRecord<CC::F>, Program = RecursionProgram<CC::F>>,
{
    pub fn build(
        machine: &BaseMachine<SC, RecursionChipType<Val<SC>, COMPRESS_DEGREE>>,
        input: &RecursionVkStdin<SC, RecursionChipType<Val<SC>, COMPRESS_DEGREE>>,
        vk_manager: &VkMerkleManager<SC>,
    ) -> RecursionProgram<Val<SC>> {
        // Construct the builder.
        let mut builder = Builder::<CC>::new();
        let input = input.read(&mut builder);

        // static vk_root in the embed circuit
        let static_vk_root: [Felt<Val<SC>>; 8] = vk_manager.merkle_root.map(|x| builder.eval(x));

        let RecursionVkStdinVariable {
            resursion_stdin_var,
            merkle_proof_var,
        } = input;

        let vk_root: [Felt<Val<SC>>; 8] = merkle_proof_var.merkle_root.map(|x| builder.eval(x));

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
            .map(|vk| vk.hash_field(&mut builder))
            .collect::<Vec<_>>();

        MerkleProofVerifier::verify(&mut builder, vk_digests, merkle_proof_var);

        EmbedVerifierCircuit::build_verifier(&mut builder, machine, resursion_stdin_var);

        let operations = builder.into_operations();

        // Compile the program.
        let mut compiler = DslIrCompiler::<CC>::default();
        compiler.compile(operations)
    }
}
