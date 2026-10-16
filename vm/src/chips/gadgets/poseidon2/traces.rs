use super::{
    columns::{FullRound, PartialRound, Poseidon2ValueCols, SBox},
    constants::RoundConstants,
};
use crate::{
    configs::config::Poseidon2Config,
    primitives::{consts::PERMUTATION_WIDTH, poseidon2::FieldPoseidon2},
};
use hybrid_array::Array;
use p3_field::PrimeField;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use typenum::Unsigned;

pub(crate) fn populate_perm<
    F: PrimeField,
    LinearLayers: GenericPoseidon2LinearLayers<PERMUTATION_WIDTH>,
    Config: Poseidon2Config,
>(
    is_real: F,
    perm: &mut Poseidon2ValueCols<F, Config>,
    mut state: [F; PERMUTATION_WIDTH],
    expected_output: Option<[F; PERMUTATION_WIDTH]>,
    constants: &RoundConstants<F, Config>,
) {
    perm.is_real = is_real;

    for (inputs_i, state_i) in perm.inputs.iter_mut().zip(state) {
        *inputs_i += state_i;
    }

    populate_perm_rounds::<F, LinearLayers, Config>(
        &mut state,
        &mut perm.beginning_full_rounds,
        &mut perm.partial_rounds,
        &mut perm.ending_full_rounds,
        constants,
    );

    if let Some(expected_output) = expected_output {
        for i in 0..PERMUTATION_WIDTH {
            assert_eq!(state[i], expected_output[i]);
        }
    }
}

/// Runs the permutation on `state` in place (external linear layer, then the three round groups),
/// recording the per-round witnesses. Used by the full-width `Poseidon2ValueCols`
/// (`populate_perm`); the riscv rate-8 layout has its own driver
/// (`riscv_poseidon2::traces::populate_perm_rounds_riscv`, built from the per-round helpers below).
pub(crate) fn populate_perm_rounds<
    F: PrimeField,
    LinearLayers: GenericPoseidon2LinearLayers<PERMUTATION_WIDTH>,
    Config: Poseidon2Config,
>(
    state: &mut [F; PERMUTATION_WIDTH],
    beginning_full_rounds: &mut Array<FullRound<F, Config>, Config::HalfFullRounds>,
    partial_rounds: &mut Array<PartialRound<F, Config>, Config::PartialRounds>,
    ending_full_rounds: &mut Array<FullRound<F, Config>, Config::HalfFullRounds>,
    constants: &RoundConstants<F, Config>,
) {
    LinearLayers::external_linear_layer(state);

    for (full_round, constants) in beginning_full_rounds
        .iter_mut()
        .zip(&constants.beginning_full_round_constants)
    {
        populate_full_round::<F, LinearLayers, Config>(state, full_round, constants);
    }

    for (partial_round, constant) in partial_rounds
        .iter_mut()
        .zip(&constants.partial_round_constants)
    {
        populate_partial_round::<F, LinearLayers, Config>(state, partial_round, *constant);
    }

    for (full_round, constants) in ending_full_rounds
        .iter_mut()
        .zip(&constants.ending_full_round_constants)
    {
        populate_full_round::<F, LinearLayers, Config>(state, full_round, constants);
    }
}

#[inline]
pub(crate) fn populate_full_round<
    F: PrimeField,
    LinearLayers: GenericPoseidon2LinearLayers<PERMUTATION_WIDTH>,
    Config: Poseidon2Config,
>(
    state: &mut [F; PERMUTATION_WIDTH],
    full_round: &mut FullRound<F, Config>,
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
    LinearLayers: GenericPoseidon2LinearLayers<PERMUTATION_WIDTH>,
    Config: Poseidon2Config,
>(
    state: &mut [F; PERMUTATION_WIDTH],
    partial_round: &mut PartialRound<F, Config>,
    round_constant: F,
) {
    state[0] += round_constant;
    populate_sbox(&mut partial_round.sbox, &mut state[0]);
    partial_round.post_sbox = state[0];
    LinearLayers::internal_linear_layer(state);
}

/// `sbox` is unused for the same reason as in `constraints::eval_sbox`: KoalaBear's cube needs
/// no committed intermediate, and the zero-width `SBox` column stays in the layout.
#[inline]
pub(crate) fn populate_sbox<F: PrimeField, Config: Poseidon2Config>(
    _sbox: &mut SBox<F, Config>,
    x: &mut F,
) {
    *x = match (F::FIELD_SBOX_DEGREE, Config::SBoxRegisters::USIZE) {
        (3, 0) => x.cube(), // case for koalabear
        (deg, reg) => panic!(
            "Unexpected (SBOX_DEGREE, SBOX_REGISTERS) of ({}, {})",
            deg, reg,
        ),
    }
}
