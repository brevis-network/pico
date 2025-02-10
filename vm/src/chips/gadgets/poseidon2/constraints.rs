use super::{
    columns::{FullRound, PartialRound, Poseidon2ValueCols, SBox},
    constants::RoundConstants,
};
use crate::{
    configs::config::Poseidon2Config,
    machine::builder::ChipBuilder,
    primitives::{consts::PERMUTATION_WIDTH, poseidon2::FieldPoseidon2},
};
use p3_field::{Field, FieldAlgebra};
use p3_poseidon2::GenericPoseidon2LinearLayers;
use typenum::Unsigned;

pub(crate) fn eval_poseidon2<
    F: Field,
    CB: ChipBuilder<F>,
    LinearLayers: GenericPoseidon2LinearLayers<CB::Expr, PERMUTATION_WIDTH>,
    Config: Poseidon2Config,
>(
    builder: &mut CB,
    local: &Poseidon2ValueCols<CB::Var, Config>,
    round_constants: &RoundConstants<F, Config>,
) -> [CB::Expr; PERMUTATION_WIDTH] {
    let mut state: [CB::Expr; PERMUTATION_WIDTH] = local.inputs.map(|x| x.into());

    #[allow(non_snake_case)]
    let FIELD_HALF_FULL_ROUNDS = Config::HalfFullRounds::USIZE;
    #[allow(non_snake_case)]
    let FIELD_PARTIAL_ROUNDS = Config::PartialRounds::USIZE;

    LinearLayers::external_linear_layer(&mut state);

    for round in 0..FIELD_HALF_FULL_ROUNDS {
        eval_full_round::<F, CB, LinearLayers, Config>(
            &mut state,
            &local.beginning_full_rounds[round],
            &round_constants.beginning_full_round_constants[round],
            builder,
        );
    }

    for round in 0..FIELD_PARTIAL_ROUNDS {
        eval_partial_round::<F, CB, LinearLayers, Config>(
            &mut state,
            &local.partial_rounds[round],
            &round_constants.partial_round_constants[round],
            builder,
        );
    }

    for round in 0..FIELD_HALF_FULL_ROUNDS {
        eval_full_round::<F, CB, LinearLayers, Config>(
            &mut state,
            &local.ending_full_rounds[round],
            &round_constants.ending_full_round_constants[round],
            builder,
        );
    }

    state
}

#[inline]
pub(crate) fn eval_full_round<
    F: Field,
    CB: ChipBuilder<F>,
    LinearLayers: GenericPoseidon2LinearLayers<CB::Expr, PERMUTATION_WIDTH>,
    Config: Poseidon2Config,
>(
    state: &mut [CB::Expr; PERMUTATION_WIDTH],
    full_round: &FullRound<CB::Var, Config>,
    round_constants: &[F; PERMUTATION_WIDTH],
    builder: &mut CB,
) {
    for (i, (s, r)) in state.iter_mut().zip(round_constants.iter()).enumerate() {
        *s = s.clone() + *r;
        eval_sbox(&full_round.sbox[i], s, builder);
    }
    LinearLayers::external_linear_layer(state);
    for (state_i, post_i) in state.iter_mut().zip(full_round.post) {
        builder.assert_eq(state_i.clone(), post_i);
        *state_i = post_i.into();
    }
}

#[inline]
pub(crate) fn eval_partial_round<
    F: Field,
    CB: ChipBuilder<F>,
    LinearLayers: GenericPoseidon2LinearLayers<CB::Expr, PERMUTATION_WIDTH>,
    Config: Poseidon2Config,
>(
    state: &mut [CB::Expr; PERMUTATION_WIDTH],
    partial_round: &PartialRound<CB::Var, Config>,
    round_constant: &F,
    builder: &mut CB,
) {
    state[0] = state[0].clone() + *round_constant;
    eval_sbox(&partial_round.sbox, &mut state[0], builder);

    builder.assert_eq(state[0].clone(), partial_round.post_sbox);
    state[0] = partial_round.post_sbox.into();

    LinearLayers::internal_linear_layer(state);
}

/// Evaluates the S-box over a degree-1 expression `x`.
///
/// # Panics
///
/// This method panics if the number of `REGISTERS` is not chosen optimally for the given
/// `DEGREE` or if the `DEGREE` is not supported by the S-box. The supported degrees are
/// `3`, `5`, `7`, and `11`.
#[inline]
pub(crate) fn eval_sbox<F, CB, Config: Poseidon2Config>(
    sbox: &SBox<CB::Var, Config>,
    x: &mut CB::Expr,
    builder: &mut CB,
) where
    F: Field,
    CB: ChipBuilder<F>,
    CB::Expr: FieldAlgebra,
{
    *x = match (F::FIELD_SBOX_DEGREE, Config::SBoxRegisters::USIZE) {
        (3, 0) => x.cube(), // case for KoalaBear
        (5, 1) => {
            // case for m31
            let committed_x3 = sbox.0[0].into();
            let x2 = x.square();
            builder.assert_eq(committed_x3.clone(), x2.clone() * x.clone());
            committed_x3 * x2
        }
        (7, 1) => {
            // case for BabyBear
            let committed_x3 = sbox.0[0].into();
            builder.assert_eq(committed_x3.clone(), x.cube());
            committed_x3.square() * x.clone()
        }
        (deg, reg) => panic!("Unexpected (DEGREE, REGISTERS) of ({}, {})", deg, reg),
    }
}
