use std::mem::transmute;

use itertools::Itertools;
use p3_air::Air;
use p3_commit::TwoAdicMultiplicativeCoset;
use p3_field::AbstractField;

use crate::{
    compiler::recursion::{
        ir::{Array, Builder, Config, Felt, Var},
        program_builder::{
            keys::BaseVerifyingKeyVariable,
            p3::{challenger::DuplexChallengerVariable, fri::TwoAdicMultiplicativeCosetVariable},
            utils::{assert_challenger_eq_pv, felt2var, get_preprocessed_data},
        },
    },
    configs::config::{Com, StarkGenericConfig},
    instances::machine::simple_machine::SimpleMachine,
    machine::{
        chip::ChipBehavior,
        folder::{ProverConstraintFolder, VerifierConstraintFolder},
        keys::BaseVerifyingKey,
        machine::MachineBehavior,
    },
    primitives::consts::{DIGEST_SIZE, RECURSION_NUM_PVS},
    recursion::air::{RecursionPublicValues, NUM_PV_ELMS_TO_HASH},
};

/// Assertions on the public values describing a complete recursive proof state.
///
/// See [SP1Prover::verify] for the verification algorithm of a complete SP1 proof.
pub(crate) fn assert_complete<CF: Config>(
    builder: &mut Builder<CF>,
    public_values: &RecursionPublicValues<Felt<CF::F>>,
    end_reconstruct_challenger: &DuplexChallengerVariable<CF>,
) {
    let RecursionPublicValues {
        next_pc,
        start_chunk,
        next_chunk,
        start_execution_chunk,
        next_execution_chunk,
        cumulative_sum,
        leaf_challenger,
        ..
    } = public_values;

    // Assert that `next_pc` is equal to zero (so program execution has completed)
    // builder.assert_felt_eq(*next_pc, CF::F::zero());

    // Assert that start chunk is equal to 1.
    // builder.assert_felt_eq(*start_chunk, CF::F::one());

    // Assert that the next chunk is not equal to one. This guarantees that there is at least one
    // chunk.
    // builder.assert_felt_ne(*next_chunk, CF::F::one());

    // Assert that the start execution chunk is equal to 1.
    // builder.assert_felt_eq(*start_execution_chunk, CF::F::one());

    // Assert that next chunk is not equal to one. This guarantees that there is at least one chunk
    // with CPU.
    // builder.assert_felt_ne(*next_execution_chunk, CF::F::one());

    // Assert that the end reconstruct challenger is equal to the leaf challenger.
    assert_challenger_eq_pv(builder, end_reconstruct_challenger, *leaf_challenger);

    // Assert that the cumulative sum is zero.
    for b in cumulative_sum.iter() {
        builder.assert_felt_eq(*b, CF::F::zero());
    }
}

pub(crate) fn proof_data_from_vk<CF: Config, SC, A>(
    builder: &mut Builder<CF>,
    vk: &BaseVerifyingKey<SC>,
    machine: &SimpleMachine<SC, A>,
) -> BaseVerifyingKeyVariable<CF>
where
    SC: StarkGenericConfig<
        Val = CF::F,
        Challenge = CF::EF,
        Domain = TwoAdicMultiplicativeCoset<CF::F>,
    >,
    A: ChipBehavior<SC::Val>
        + for<'a> Air<ProverConstraintFolder<'a, SC>>
        + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
    Com<SC>: Into<[SC::Val; DIGEST_SIZE]>,
{
    let mut commitment = builder.dyn_array(DIGEST_SIZE);
    for (i, value) in vk.commit.clone().into().iter().enumerate() {
        builder.set(&mut commitment, i, *value);
    }
    let pc_start: Felt<_> = builder.eval(vk.pc_start);

    let (prep_sorted_indices_val, prep_domains_val) =
        get_preprocessed_data(machine.chips(), &machine.preprocessed_chip_ids(), vk);

    let mut prep_sorted_indices = builder.dyn_array::<Var<_>>(prep_sorted_indices_val.len());
    let mut prep_domains =
        builder.dyn_array::<TwoAdicMultiplicativeCosetVariable<_>>(prep_domains_val.len());

    for (i, value) in prep_sorted_indices_val.iter().enumerate() {
        builder.set(
            &mut prep_sorted_indices,
            i,
            CF::N::from_canonical_usize(*value),
        );
    }

    for (i, value) in prep_domains_val.iter().enumerate() {
        let domain: TwoAdicMultiplicativeCosetVariable<_> = builder.constant(*value);
        builder.set(&mut prep_domains, i, domain);
    }

    BaseVerifyingKeyVariable {
        commitment,
        pc_start,
        preprocessed_sorted_idxs: prep_sorted_indices,
        preprocessed_domains: prep_domains,
    }
}

/// Calculates the digest of the recursion public values.
fn calculate_public_values_digest<CF: Config>(
    builder: &mut Builder<CF>,
    public_values: &RecursionPublicValues<Felt<CF::F>>,
) -> Array<CF, Felt<CF::F>> {
    let pv_elements: [Felt<_>; RECURSION_NUM_PVS] = unsafe { transmute(*public_values) };
    let mut poseidon_inputs = builder.array(NUM_PV_ELMS_TO_HASH);
    for (i, elm) in pv_elements[0..NUM_PV_ELMS_TO_HASH].iter().enumerate() {
        builder.set(&mut poseidon_inputs, i, *elm);
    }
    builder.poseidon2_hash(&poseidon_inputs)
}

/// Verifies the digest of a recursive public values struct.
pub(crate) fn verify_public_values_hash<CF: Config>(
    builder: &mut Builder<CF>,
    public_values: &RecursionPublicValues<Felt<CF::F>>,
) {
    let var_exit_code = felt2var(builder, public_values.exit_code);
    // Check that the public values digest is correct if the exit_code is 0.
    builder.if_eq(var_exit_code, CF::N::zero()).then(|builder| {
        let calculated_digest = calculate_public_values_digest(builder, public_values);

        let expected_digest = public_values.digest;
        for (i, expected_elm) in expected_digest.iter().enumerate() {
            let calculated_elm = builder.get(&calculated_digest, i);
            builder.assert_felt_eq(*expected_elm, calculated_elm);
        }
    });
}

/// Register and commits the recursion public values.
pub fn commit_public_values<CF: Config>(
    builder: &mut Builder<CF>,
    public_values: &RecursionPublicValues<Felt<CF::F>>,
) {
    let pv_elements: [Felt<_>; RECURSION_NUM_PVS] = unsafe { transmute(*public_values) };
    let pv_elms_no_digest = &pv_elements[0..NUM_PV_ELMS_TO_HASH];

    for value in pv_elms_no_digest.iter() {
        builder.register_public_value(*value);
    }

    // Hash the public values.
    let pv_digest = calculate_public_values_digest(builder, public_values);
    for i in 0..DIGEST_SIZE {
        let digest_element = builder.get(&pv_digest, i);
        builder.commit_public_value(digest_element);
    }
}
