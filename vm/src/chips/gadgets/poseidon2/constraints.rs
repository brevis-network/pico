use super::{
    columns::{FullRound, PartialRound, Poseidon2ValueCols, SBox},
    constants::RoundConstants,
};
use crate::{
    configs::config::Poseidon2Config,
    machine::builder::ChipBuilder,
    primitives::{consts::PERMUTATION_WIDTH, poseidon2::FieldPoseidon2},
};
use hybrid_array::Array;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_poseidon2::GenericPoseidon2LinearLayers;
use typenum::Unsigned;

pub(crate) fn eval_poseidon2<
    F: Field,
    CB: ChipBuilder<F>,
    LinearLayers: GenericPoseidon2LinearLayers<PERMUTATION_WIDTH>,
    Config: Poseidon2Config,
>(
    builder: &mut CB,
    local: &Poseidon2ValueCols<CB::Var, Config>,
    round_constants: &RoundConstants<F, Config>,
) -> [CB::Expr; PERMUTATION_WIDTH] {
    eval_poseidon2_rounds::<F, CB, LinearLayers, Config>(
        builder,
        local.inputs.map(|x| x.into()),
        &local.beginning_full_rounds,
        &local.partial_rounds,
        &local.ending_full_rounds,
        round_constants,
    )
}

/// Evaluates the permutation rounds on an initial `state` (external linear layer, then the three
/// round groups), returning the output state. Used by the full-width `Poseidon2ValueCols`
/// (`eval_poseidon2`); the riscv rate-8 layout has its own round driver
/// (`riscv_poseidon2::constraints::eval_poseidon2_rounds_riscv`, built from the per-round helpers
/// below) because its last full round commits only the looked-up lanes.
pub(crate) fn eval_poseidon2_rounds<
    F: Field,
    CB: ChipBuilder<F>,
    LinearLayers: GenericPoseidon2LinearLayers<PERMUTATION_WIDTH>,
    Config: Poseidon2Config,
>(
    builder: &mut CB,
    mut state: [CB::Expr; PERMUTATION_WIDTH],
    beginning_full_rounds: &Array<FullRound<CB::Var, Config>, Config::HalfFullRounds>,
    partial_rounds: &Array<PartialRound<CB::Var, Config>, Config::PartialRounds>,
    ending_full_rounds: &Array<FullRound<CB::Var, Config>, Config::HalfFullRounds>,
    round_constants: &RoundConstants<F, Config>,
) -> [CB::Expr; PERMUTATION_WIDTH] {
    #[allow(non_snake_case)]
    let FIELD_HALF_FULL_ROUNDS = Config::HalfFullRounds::USIZE;
    #[allow(non_snake_case)]
    let FIELD_PARTIAL_ROUNDS = Config::PartialRounds::USIZE;

    LinearLayers::external_linear_layer(&mut state);

    for round in 0..FIELD_HALF_FULL_ROUNDS {
        eval_full_round::<F, CB, LinearLayers, Config>(
            &mut state,
            &beginning_full_rounds[round],
            &round_constants.beginning_full_round_constants[round],
            builder,
        );
    }

    for round in 0..FIELD_PARTIAL_ROUNDS {
        eval_partial_round::<F, CB, LinearLayers, Config>(
            &mut state,
            &partial_rounds[round],
            &round_constants.partial_round_constants[round],
            builder,
        );
    }

    for round in 0..FIELD_HALF_FULL_ROUNDS {
        eval_full_round::<F, CB, LinearLayers, Config>(
            &mut state,
            &ending_full_rounds[round],
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
    LinearLayers: GenericPoseidon2LinearLayers<PERMUTATION_WIDTH>,
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
    LinearLayers: GenericPoseidon2LinearLayers<PERMUTATION_WIDTH>,
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
/// A cube needs no committed intermediate, so `_sbox` and `_builder` go unused. They stay
/// because the `SBox` they index is `Array<T, Config::SBoxRegisters>`, zero-width under every
/// config here and so free; emptying it out means changing that associated type.
///
/// # Panics
///
/// Panics for any `(DEGREE, REGISTERS)` but KoalaBear's `(3, 0)`, the only shape a
/// `Poseidon2Config` here produces.
#[inline]
pub(crate) fn eval_sbox<F, CB, Config: Poseidon2Config>(
    _sbox: &SBox<CB::Var, Config>,
    x: &mut CB::Expr,
    _builder: &mut CB,
) where
    F: Field,
    CB: ChipBuilder<F>,
    CB::Expr: PrimeCharacteristicRing,
{
    *x = match (F::FIELD_SBOX_DEGREE, Config::SBoxRegisters::USIZE) {
        (3, 0) => x.cube(), // case for KoalaBear
        (deg, reg) => panic!("Unexpected (DEGREE, REGISTERS) of ({}, {})", deg, reg),
    }
}
