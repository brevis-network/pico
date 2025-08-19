use crate::{
    compiler::recursion::{
        circuit::{
            challenger::{CanObserveVariable, DuplexChallengerVariable},
            config::{CircuitConfig, FieldFriConfig, FieldFriConfigVariable},
            constraints::RecursiveVerifierConstraintFolder,
            stark::StarkVerifier,
            witness::Witnessable,
        },
        ir::compiler::DslIrCompiler,
        prelude::*,
        program::RecursionProgram,
    },
    configs::config::Val,
    emulator::recursion::public_values::{
        assert_recursion_public_values_valid, recursion_public_values_digest, RecursionPublicValues,
    },
    instances::{
        chiptype::recursion_chiptype::RecursionChipType,
        compiler::{
            riscv_circuit::stdin::{DeferredStdin, DeferredStdinVariable},
            vk_merkle::builder::MerkleProofVerifier,
        },
    },
    machine::{
        chip::ChipBehavior,
        field::FieldSpecificPoseidon2Config,
        machine::BaseMachine,
        septic::{SepticCurve, SepticDigest},
    },
    primitives::consts::{DIGEST_SIZE, PV_DIGEST_NUM_WORDS, RECURSION_NUM_PVS, WORD_SIZE},
};
use p3_air::Air;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::{FieldAlgebra, PrimeField32, TwoAdicField};
use std::{array, borrow::BorrowMut, fmt::Debug, marker::PhantomData};
use tracing::instrument;

/// Circuit that verifies a single riscv proof and checks constraints
#[derive(Debug, Clone, Copy)]
pub struct DeferredVerifierCircuit<CC: CircuitConfig, SC: FieldFriConfig> {
    _phantom: PhantomData<(CC, SC)>,
}

impl<F, CC, SC> DeferredVerifierCircuit<CC, SC>
where
    F: TwoAdicField + PrimeField32 + FieldSpecificPoseidon2Config,
    CC: CircuitConfig<N = F, F = F, Bit = Felt<F>> + Debug,
    SC: FieldFriConfigVariable<
        CC,
        Val = F,
        Challenge = CC::EF,
        Domain = TwoAdicMultiplicativeCoset<F>,
        FriChallengerVariable = DuplexChallengerVariable<CC>,
        DigestVariable = [Felt<F>; DIGEST_SIZE],
    >,
    RecursionChipType<Val<SC>>:
        ChipBehavior<Val<SC>> + for<'a> Air<RecursiveVerifierConstraintFolder<'a, CC>>,
    DeferredStdin<SC, RecursionChipType<Val<SC>>>:
        Witnessable<CC, WitnessVariable = DeferredStdinVariable<CC, SC>>,
{
    #[instrument(name = "build deferred proofs program", level = "debug", skip_all)]
    pub fn build(
        machine: &BaseMachine<SC, RecursionChipType<Val<SC>>>,
        input: &DeferredStdin<SC, RecursionChipType<Val<SC>>>,
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

pub fn print_recursion_public_values<CC, SC>(
    builder: &mut Builder<CC>,
    pv: &RecursionPublicValues<Felt<CC::F>>,
) where
    CC: CircuitConfig,
    SC: FieldFriConfigVariable<
        CC,
        Val = CC::F,
        Challenge = CC::EF,
        Domain = TwoAdicMultiplicativeCoset<CC::F>,
        FriChallengerVariable = DuplexChallengerVariable<CC>,
        DigestVariable = [Felt<CC::F>; DIGEST_SIZE],
    >,
{
    // 1. committed_value_digest  (PV_DIGEST_NUM_WORDS * WORD_SIZE)
    for word in &pv.committed_value_digest {
        for elt in &word.0 {
            builder.print_f(*elt);
        }
    }

    // 2. deferred_proofs_digest  (DIGEST_SIZE)
    for elt in &pv.deferred_proofs_digest {
        builder.print_f(*elt);
    }

    // 3~8. start/next pc & chunk
    builder.print_f(pv.start_pc);
    builder.print_f(pv.next_pc);
    builder.print_f(pv.start_chunk);
    builder.print_f(pv.next_chunk);
    builder.print_f(pv.start_execution_chunk);
    builder.print_f(pv.next_execution_chunk);

    // 9~12. addr bits
    for bit in &pv.previous_initialize_addr_bits {
        builder.print_f(*bit);
    }
    for bit in &pv.last_initialize_addr_bits {
        builder.print_f(*bit);
    }
    for bit in &pv.previous_finalize_addr_bits {
        builder.print_f(*bit);
    }
    for bit in &pv.last_finalize_addr_bits {
        builder.print_f(*bit);
    }

    // 13. riscv_vk_digest
    for elt in &pv.riscv_vk_digest {
        builder.print_f(*elt);
    }

    // 14. vk_root
    for elt in &pv.vk_root {
        builder.print_f(*elt);
    }

    // 15. global_cumulative_sum  (SepticDigest = 2 × 16 felts)
    for elt in &pv.global_cumulative_sum.0.x.0 {
        builder.print_f(*elt);
    }
    for elt in &pv.global_cumulative_sum.0.y.0 {
        builder.print_f(*elt);
    }

    // 16~18. flags & digest
    builder.print_f(pv.flag_complete);
    builder.print_f(pv.contains_execution_chunk);
    for elt in &pv.digest {
        builder.print_f(*elt);
    }

    // 19. exit_code
    builder.print_f(pv.exit_code);
}

impl<CC, SC> DeferredVerifierCircuit<CC, SC>
where
    CC: CircuitConfig,
    CC::F: TwoAdicField + PrimeField32 + FieldSpecificPoseidon2Config,
    SC: FieldFriConfigVariable<
        CC,
        Val = CC::F,
        Challenge = CC::EF,
        Domain = TwoAdicMultiplicativeCoset<CC::F>,
        FriChallengerVariable = DuplexChallengerVariable<CC>,
        DigestVariable = [Felt<CC::F>; DIGEST_SIZE],
    >,
    RecursionChipType<Val<SC>>:
        ChipBehavior<Val<SC>> + for<'a> Air<RecursiveVerifierConstraintFolder<'a, CC>>,
{
    pub fn build_verifier(
        builder: &mut Builder<CC>,
        machine: &BaseMachine<SC, RecursionChipType<SC::Val>>,
        input: DeferredStdinVariable<CC, SC>,
    ) {
        // Read input.
        let DeferredStdinVariable {
            proof: chunk_proof,
            recursion_vk: vk,
            recursion_vk_merkle_data,
            start_reconstruct_deferred_digest,
            riscv_vk_digest,
            end_pc,
        } = input;

        let mut deferred_public_values_stream = chunk_proof.public_values.clone();
        let deferred_public_values: &mut RecursionPublicValues<_> =
            deferred_public_values_stream.as_mut_slice().borrow_mut();

        /*
        Completeness check
         */
        {
            let zero: Felt<_> = builder.eval(CC::F::ZERO);
            let one: Felt<_> = builder.eval(CC::F::ONE);

            // Flag must be complete.
            builder.assert_felt_eq(deferred_public_values.flag_complete, one);

            // Assert that `next_pc` is equal to zero (so program execution has completed)
            builder.assert_felt_eq(deferred_public_values.next_pc, zero);

            // Assert that start chunk is equal to 1.
            builder.assert_felt_eq(deferred_public_values.start_chunk, one);

            // Should contain execution chunk
            builder.assert_felt_eq(deferred_public_values.contains_execution_chunk, one);
            // Start execution chunk is one
            builder.assert_felt_eq(deferred_public_values.start_execution_chunk, one);
        }

        // Recursion_VK Merkle Verification
        let vk_root: [Felt<Val<SC>>; 8] = recursion_vk_merkle_data
            .merkle_root
            .map(|x| builder.eval(x));
        for (expected, actual) in vk_root.iter().zip(deferred_public_values.vk_root.iter()) {
            builder.assert_felt_eq(*expected, *actual);
        }

        // Constraint that ensures all the vk of the recursion program are included in the vk Merkle tree.
        let vk_digests = vec![vk.hash_field(builder)];
        MerkleProofVerifier::verify(builder, vk_digests, recursion_vk_merkle_data);

        /*
        Verify chunk proof(STARK Verification)
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

        // validate digest
        assert_recursion_public_values_valid::<CC, SC>(builder, deferred_public_values);

        // Handle public values
        {
            let zero: Felt<_> = builder.eval(CC::F::ZERO);
            let one: Felt<_> = builder.eval(CC::F::ONE);

            // Initialize the public values we will commit to.
            let mut recursion_public_values_stream = [zero; RECURSION_NUM_PVS];
            let recursion_public_values: &mut RecursionPublicValues<_> =
                recursion_public_values_stream.as_mut_slice().borrow_mut();
            recursion_public_values.start_pc = end_pc;
            recursion_public_values.next_pc = end_pc;
            recursion_public_values.start_chunk = one;
            recursion_public_values.next_chunk = one;
            recursion_public_values.start_execution_chunk = one;
            recursion_public_values.next_execution_chunk = one;
            recursion_public_values.riscv_vk_digest = riscv_vk_digest;
            recursion_public_values.vk_root = vk_root;

            {
                recursion_public_values.start_reconstruct_deferred_digest =
                    start_reconstruct_deferred_digest;

                // Initialize the consistency check variable.
                let mut reconstruct_deferred_digest: [Felt<CC::F>; DIGEST_SIZE] =
                    start_reconstruct_deferred_digest;

                let mut inputs: [Felt<CC::F>; 48] = array::from_fn(|_| builder.uninit());
                inputs[0..DIGEST_SIZE].copy_from_slice(&reconstruct_deferred_digest);

                inputs[DIGEST_SIZE..DIGEST_SIZE + DIGEST_SIZE]
                    .copy_from_slice(&deferred_public_values.riscv_vk_digest);

                for j in 0..PV_DIGEST_NUM_WORDS {
                    for k in 0..WORD_SIZE {
                        let element = deferred_public_values.committed_value_digest[j][k];
                        inputs[j * WORD_SIZE + k + 16] = element;
                    }
                }
                reconstruct_deferred_digest = SC::hash(builder, &inputs);

                recursion_public_values.end_reconstruct_deferred_digest =
                    reconstruct_deferred_digest;
            }

            recursion_public_values.flag_complete = builder.eval(CC::F::from_bool(false));
            recursion_public_values.contains_execution_chunk =
                builder.eval(CC::F::from_bool(false));

            recursion_public_values.global_cumulative_sum = SepticDigest(SepticCurve::convert(
                SepticDigest::<CC::F>::zero().0,
                |value| builder.eval(value),
            ));

            recursion_public_values.digest =
                recursion_public_values_digest::<CC, SC>(builder, recursion_public_values);

            SC::commit_recursion_public_values(builder, *recursion_public_values);
        }
    }
}
