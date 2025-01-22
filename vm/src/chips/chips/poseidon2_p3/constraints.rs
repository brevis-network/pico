use crate::{
    chips::chips::poseidon2_p3::{
        columns::{
            FullRound, PartialRound, Poseidon2Cols, Poseidon2PreprocessedCols, Poseidon2ValueCols,
            SBox, NUM_POSEIDON2_COLS,
        },
        constants::RoundConstants,
        Poseidon2ChipP3,
    },
    machine::builder::{ChipBuilder, RecursionBuilder},
    primitives::{
        consts::PERMUTATION_WIDTH, FIELD_HALF_FULL_ROUNDS, FIELD_PARTIAL_ROUNDS, FIELD_SBOX_DEGREE,
        FIELD_SBOX_REGISTERS,
    },
};
use p3_air::{Air, BaseAir};
use p3_field::{Field, FieldAlgebra};
use p3_matrix::Matrix;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use std::borrow::Borrow;

impl<F: Field, LinearLayers: Sync> BaseAir<F> for Poseidon2ChipP3<F, LinearLayers> {
    fn width(&self) -> usize {
        NUM_POSEIDON2_COLS
    }
}

impl<
        F: Field,
        LinearLayers: GenericPoseidon2LinearLayers<CB::Expr, PERMUTATION_WIDTH>,
        CB: ChipBuilder<F>,
    > Air<CB> for Poseidon2ChipP3<F, LinearLayers>
where
    Self: BaseAir<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &Poseidon2Cols<CB::Var> = (*local).borrow();
        let prep = builder.preprocessed();
        let prep_local = prep.row_slice(0);
        let prep_local: &Poseidon2PreprocessedCols<CB::Var> = (*prep_local).borrow();

        for (local, prep_local) in local.values.iter().zip(prep_local.values.iter()) {
            // memory constraints
            (0..PERMUTATION_WIDTH).for_each(|i| {
                builder.looking_single(prep_local.input[i], local.inputs[i], prep_local.is_real_neg)
            });

            (0..PERMUTATION_WIDTH).for_each(|i| {
                builder.looking_single(
                    prep_local.output[i].addr,
                    local.ending_full_rounds[FIELD_HALF_FULL_ROUNDS - 1].post[i],
                    prep_local.output[i].mult,
                )
            });

            eval_poseidon2::<F, CB, LinearLayers>(builder, local, &self.constants);
        }
    }
}

pub(crate) fn eval_poseidon2<
    F: Field,
    CB: ChipBuilder<F>,
    LinearLayers: GenericPoseidon2LinearLayers<CB::Expr, PERMUTATION_WIDTH>,
>(
    builder: &mut CB,
    local: &Poseidon2ValueCols<CB::Var>,
    round_constants: &RoundConstants<F>,
) {
    let mut state: [CB::Expr; PERMUTATION_WIDTH] = local.inputs.map(|x| x.into());

    LinearLayers::external_linear_layer(&mut state);

    for round in 0..FIELD_HALF_FULL_ROUNDS {
        eval_full_round::<F, CB, LinearLayers>(
            &mut state,
            &local.beginning_full_rounds[round],
            &round_constants.beginning_full_round_constants[round],
            builder,
        );
    }

    for round in 0..FIELD_PARTIAL_ROUNDS {
        eval_partial_round::<F, CB, LinearLayers>(
            &mut state,
            &local.partial_rounds[round],
            &round_constants.partial_round_constants[round],
            builder,
        );
    }

    for round in 0..FIELD_HALF_FULL_ROUNDS {
        eval_full_round::<F, CB, LinearLayers>(
            &mut state,
            &local.ending_full_rounds[round],
            &round_constants.ending_full_round_constants[round],
            builder,
        );
    }
}

#[inline]
fn eval_full_round<
    F: Field,
    CB: ChipBuilder<F>,
    LinearLayers: GenericPoseidon2LinearLayers<CB::Expr, PERMUTATION_WIDTH>,
>(
    state: &mut [CB::Expr; PERMUTATION_WIDTH],
    full_round: &FullRound<CB::Var>,
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
fn eval_partial_round<
    F: Field,
    CB: ChipBuilder<F>,
    LinearLayers: GenericPoseidon2LinearLayers<CB::Expr, PERMUTATION_WIDTH>,
>(
    state: &mut [CB::Expr; PERMUTATION_WIDTH],
    partial_round: &PartialRound<CB::Var>,
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
fn eval_sbox<F, CB>(sbox: &SBox<CB::Var>, x: &mut CB::Expr, builder: &mut CB)
where
    F: Field,
    CB: ChipBuilder<F>,
    CB::Expr: FieldAlgebra,
{
    *x = match (FIELD_SBOX_DEGREE, FIELD_SBOX_REGISTERS) {
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
        _ => panic!(
            "Unexpected (DEGREE, REGISTERS) of ({}, {})",
            FIELD_SBOX_DEGREE, FIELD_SBOX_REGISTERS
        ),
    }
}
