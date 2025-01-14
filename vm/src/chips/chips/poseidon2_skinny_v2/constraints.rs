use super::{
    columns::{
        Poseidon2Cols, Poseidon2PreprocessedCols, BABYBEAR_NUM_POSEIDON2_COLS,
        KOALABEAR_NUM_POSEIDON2_COLS,
    },
    Poseidon2SkinnyChip,
};
use crate::{
    chips::chips::poseidon2::utils::{external_linear_layer, internal_linear_layer},
    machine::builder::{ChipBuilder, RecursionBuilder},
    primitives::consts::{
        BABYBEAR_NUM_EXTERNAL_ROUNDS, BABYBEAR_NUM_INTERNAL_ROUNDS, KOALABEAR_NUM_EXTERNAL_ROUNDS,
        KOALABEAR_NUM_INTERNAL_ROUNDS, PERMUTATION_WIDTH,
    },
};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, FieldAlgebra};
use p3_matrix::Matrix;
use std::{array, borrow::Borrow};

macro_rules! impl_poseidon2_skinny_chip {
    ($num_external_rounds:expr, $num_internal_rounds:expr, $num_col:expr) => {
        impl<const DEGREE: usize, F: Field> BaseAir<F>
            for Poseidon2SkinnyChip<DEGREE, $num_external_rounds, $num_internal_rounds, F>
        {
            fn width(&self) -> usize {
                $num_col
            }
        }

        impl<const DEGREE: usize, F: Field, CB: ChipBuilder<F>> Air<CB>
            for Poseidon2SkinnyChip<DEGREE, $num_external_rounds, $num_internal_rounds, F>
        where
            CB::Var: Sized,
        {
            fn eval(&self, builder: &mut CB) {
                // We only support machines with degree 9.
                assert!(DEGREE >= 9);

                let main = builder.main();
                let (local_row, next_row) = (main.row_slice(0), main.row_slice(1));
                let local_row: &Poseidon2Cols<_, { $num_internal_rounds - 1 }> =
                    (*local_row).borrow();
                let next_row: &Poseidon2Cols<_, { $num_internal_rounds - 1 }> =
                    (*next_row).borrow();
                let prepr = builder.preprocessed();
                let prep_local = prepr.row_slice(0);
                let prep_local: &Poseidon2PreprocessedCols<_> = (*prep_local).borrow();

                // Dummy constraints to normalize to DEGREE.
                let lhs = (0..DEGREE)
                    .map(|_| local_row.state_var[0].into())
                    .product::<CB::Expr>();
                let rhs = (0..DEGREE)
                    .map(|_| local_row.state_var[0].into())
                    .product::<CB::Expr>();
                builder.assert_eq(lhs, rhs);

                // For now, include only memory constraints.
                (0..PERMUTATION_WIDTH).for_each(|i| {
                    builder.looking_single(
                        prep_local.memory_preprocessed[i].addr,
                        local_row.state_var[i],
                        prep_local.memory_preprocessed[i].mult,
                    )
                });

                self.eval_input_round(builder, local_row, prep_local, next_row);

                self.eval_external_round(builder, local_row, prep_local, next_row);

                self.eval_internal_rounds(
                    builder,
                    local_row,
                    next_row,
                    prep_local.round_counters_preprocessed.round_constants,
                    prep_local.round_counters_preprocessed.is_internal_round,
                );
            }
        }

        impl<const DEGREE: usize, F: Field>
            Poseidon2SkinnyChip<DEGREE, $num_external_rounds, $num_internal_rounds, F>
        {
            fn eval_input_round<CB: ChipBuilder<F>>(
                &self,
                builder: &mut CB,
                local_row: &Poseidon2Cols<CB::Var, { $num_internal_rounds - 1 }>,
                prep_local: &Poseidon2PreprocessedCols<CB::Var>,
                next_row: &Poseidon2Cols<CB::Var, { $num_internal_rounds - 1 }>,
            ) {
                let mut state: [CB::Expr; PERMUTATION_WIDTH] =
                    array::from_fn(|i| local_row.state_var[i].into());

                // Apply the linear layer.
                external_linear_layer(&mut state);

                let next_state = next_row.state_var;
                for i in 0..PERMUTATION_WIDTH {
                    builder
                        .when_transition()
                        .when(prep_local.round_counters_preprocessed.is_input_round)
                        .assert_eq(next_state[i], state[i].clone());
                }
            }

            fn eval_external_round<CB: ChipBuilder<F>>(
                &self,
                builder: &mut CB,
                local_row: &Poseidon2Cols<CB::Var, { $num_internal_rounds - 1 }>,
                prep_local: &Poseidon2PreprocessedCols<CB::Var>,
                next_row: &Poseidon2Cols<CB::Var, { $num_internal_rounds - 1 }>,
            ) {
                let local_state = local_row.state_var;

                // Add the round constants.
                let add_rc: [CB::Expr; PERMUTATION_WIDTH] = core::array::from_fn(|i| {
                    local_state[i].into()
                        + prep_local.round_counters_preprocessed.round_constants[i]
                });

                // Apply the sboxes.
                // See `populate_external_round` for why we don't have columns for the sbox output here.
                let mut sbox_deg_7: [CB::Expr; PERMUTATION_WIDTH] =
                    core::array::from_fn(|_| CB::Expr::ZERO);
                for i in 0..PERMUTATION_WIDTH {
                    let sbox_deg_3 = add_rc[i].clone() * add_rc[i].clone() * add_rc[i].clone();
                    sbox_deg_7[i] = sbox_deg_3.clone() * sbox_deg_3.clone() * add_rc[i].clone();
                }

                // Apply the linear layer.
                let mut state = sbox_deg_7;
                external_linear_layer(&mut state);

                let next_state = next_row.state_var;
                for i in 0..PERMUTATION_WIDTH {
                    builder
                        .when_transition()
                        .when(prep_local.round_counters_preprocessed.is_external_round)
                        .assert_eq(next_state[i], state[i].clone());
                }
            }

            fn eval_internal_rounds<CB: ChipBuilder<F>>(
                &self,
                builder: &mut CB,
                local_row: &Poseidon2Cols<CB::Var, { $num_internal_rounds - 1 }>,
                next_row: &Poseidon2Cols<CB::Var, { $num_internal_rounds - 1 }>,
                round_constants: [CB::Var; PERMUTATION_WIDTH],
                is_internal_row: CB::Var,
            ) {
                let local_state = local_row.state_var;

                let s0 = local_row.internal_rounds_s0;
                let mut state: [CB::Expr; PERMUTATION_WIDTH] =
                    core::array::from_fn(|i| local_state[i].into());
                for r in 0..$num_internal_rounds {
                    // Add the round constant.
                    let add_rc = if r == 0 {
                        state[0].clone()
                    } else {
                        s0[r - 1].into()
                    } + round_constants[r];

                    let sbox_deg_3 = add_rc.clone() * add_rc.clone() * add_rc.clone();
                    // See `populate_internal_rounds` for why we don't have columns for the sbox output
                    // here.
                    let sbox_deg_7 = sbox_deg_3.clone() * sbox_deg_3.clone() * add_rc.clone();

                    // Apply the linear layer.
                    // See `populate_internal_rounds` for why we don't have columns for the new state here.
                    state[0] = sbox_deg_7.clone();
                    internal_linear_layer::<F, _>(&mut state);

                    if r < $num_internal_rounds - 1 {
                        builder
                            .when(is_internal_row)
                            .assert_eq(s0[r], state[0].clone());
                    }
                }

                let next_state = next_row.state_var;
                for i in 0..PERMUTATION_WIDTH {
                    builder
                        .when(is_internal_row)
                        .assert_eq(next_state[i], state[i].clone())
                }
            }
        }
    };
}

impl_poseidon2_skinny_chip!(
    BABYBEAR_NUM_EXTERNAL_ROUNDS,
    BABYBEAR_NUM_INTERNAL_ROUNDS,
    BABYBEAR_NUM_POSEIDON2_COLS
);
impl_poseidon2_skinny_chip!(
    KOALABEAR_NUM_EXTERNAL_ROUNDS,
    KOALABEAR_NUM_INTERNAL_ROUNDS,
    KOALABEAR_NUM_POSEIDON2_COLS
);
