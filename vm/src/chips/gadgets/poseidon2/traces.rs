use super::{
    columns::{FullRound, PartialRound, Poseidon2ValueCols, SBox},
    constants::RoundConstants,
};
use crate::primitives::{consts::PERMUTATION_WIDTH, FIELD_SBOX_DEGREE, FIELD_SBOX_REGISTERS};
use p3_field::PrimeField;
use p3_poseidon2::GenericPoseidon2LinearLayers;

pub(crate) fn populate_perm<
    F: PrimeField,
    LinearLayers: GenericPoseidon2LinearLayers<F, PERMUTATION_WIDTH>,
>(
    is_real: F,
    perm: &mut Poseidon2ValueCols<F>,
    mut state: [F; PERMUTATION_WIDTH],
    expected_output: Option<[F; PERMUTATION_WIDTH]>,
    constants: &RoundConstants<F>,
) {
    perm.is_real = is_real;

    for (inputs_i, state_i) in perm.inputs.iter_mut().zip(state) {
        *inputs_i += state_i;
    }

    LinearLayers::external_linear_layer(&mut state);

    for (full_round, constants) in perm
        .beginning_full_rounds
        .iter_mut()
        .zip(&constants.beginning_full_round_constants)
    {
        populate_full_round::<F, LinearLayers>(&mut state, full_round, constants);
    }

    for (partial_round, constant) in perm
        .partial_rounds
        .iter_mut()
        .zip(&constants.partial_round_constants)
    {
        populate_partial_round::<F, LinearLayers>(&mut state, partial_round, *constant);
    }

    for (full_round, constants) in perm
        .ending_full_rounds
        .iter_mut()
        .zip(&constants.ending_full_round_constants)
    {
        populate_full_round::<F, LinearLayers>(&mut state, full_round, constants);
    }

    if let Some(expected_output) = expected_output {
        for i in 0..PERMUTATION_WIDTH {
            assert_eq!(state[i], expected_output[i]);
        }
    }
}

#[inline]
pub(crate) fn populate_full_round<
    F: PrimeField,
    LinearLayers: GenericPoseidon2LinearLayers<F, PERMUTATION_WIDTH>,
>(
    state: &mut [F; PERMUTATION_WIDTH],
    full_round: &mut FullRound<F>,
    round_constants: &[F; PERMUTATION_WIDTH],
) {
    for (state_i, const_i) in state.iter_mut().zip(round_constants) {
        *state_i += *const_i;
    }
    for (state_i, sbox_i) in state.iter_mut().zip(full_round.sbox.iter_mut()) {
        populate_sbox(sbox_i, state_i);
    }
    LinearLayers::external_linear_layer(state);

    for (post_i, state_i) in full_round.post.iter_mut().zip(state) {
        *post_i = *state_i;
    }
}

#[inline]
pub(crate) fn populate_partial_round<
    F: PrimeField,
    LinearLayers: GenericPoseidon2LinearLayers<F, PERMUTATION_WIDTH>,
>(
    state: &mut [F; PERMUTATION_WIDTH],
    partial_round: &mut PartialRound<F>,
    round_constant: F,
) {
    state[0] += round_constant;
    populate_sbox(&mut partial_round.sbox, &mut state[0]);
    partial_round.post_sbox = state[0];
    LinearLayers::internal_linear_layer(state);
}

#[inline]
pub(crate) fn populate_sbox<F: PrimeField>(sbox: &mut SBox<F>, x: &mut F) {
    *x = match (FIELD_SBOX_DEGREE, FIELD_SBOX_REGISTERS) {
        (3, 0) => x.cube(), // case for koalabear
        (5, 1) => {
            // case for m31
            let x2 = x.square();
            let x3 = x2 * *x;
            sbox.0[0] = x3;
            x3 * x2
        }
        (7, 1) => {
            // case for babybear
            let x3 = x.cube();
            sbox.0[0] = x3;
            x3 * x3 * *x
        }
        _ => panic!(
            "Unexpected (SBOX_DEGREE, SBOX_REGISTERS) of ({}, {})",
            FIELD_SBOX_DEGREE, FIELD_SBOX_REGISTERS
        ),
    }
}
