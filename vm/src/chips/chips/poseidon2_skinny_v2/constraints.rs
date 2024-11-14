use super::{
    columns::{Poseidon2Cols, Poseidon2PreprocessedCols, NUM_POSEIDON2_COLS},
    utils::{external_linear_layer, internal_linear_layer, NUM_INTERNAL_ROUNDS, WIDTH},
    Poseidon2SkinnyChip,
};
use crate::machine::builder::{ChipBuilder, RecursionBuilder};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{AbstractField, Field};
use p3_matrix::Matrix;
use std::{array, borrow::Borrow};

impl<const DEGREE: usize, F: Field> BaseAir<F> for Poseidon2SkinnyChip<DEGREE, F> {
    fn width(&self) -> usize {
        NUM_POSEIDON2_COLS
    }
}

impl<const DEGREE: usize, F: Field, CB: ChipBuilder<F>> Air<CB> for Poseidon2SkinnyChip<DEGREE, F>
where
    CB::Var: Sized,
{
    fn eval(&self, builder: &mut CB) {
        // We only support machines with degree 9.
        assert!(DEGREE >= 9);

        let main = builder.main();
        let (local_row, next_row) = (main.row_slice(0), main.row_slice(1));
        let local_row: &Poseidon2Cols<_> = (*local_row).borrow();
        let next_row: &Poseidon2Cols<_> = (*next_row).borrow();
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
        (0..WIDTH).for_each(|i| {
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

impl<const DEGREE: usize, F: Field> Poseidon2SkinnyChip<DEGREE, F> {
    fn eval_input_round<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local_row: &Poseidon2Cols<CB::Var>,
        prep_local: &Poseidon2PreprocessedCols<CB::Var>,
        next_row: &Poseidon2Cols<CB::Var>,
    ) {
        let mut state: [CB::Expr; WIDTH] = array::from_fn(|i| local_row.state_var[i].into());

        // Apply the linear layer.
        external_linear_layer(&mut state);

        let next_state = next_row.state_var;
        for i in 0..WIDTH {
            builder
                .when_transition()
                .when(prep_local.round_counters_preprocessed.is_input_round)
                .assert_eq(next_state[i], state[i].clone());
        }
    }

    fn eval_external_round<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local_row: &Poseidon2Cols<CB::Var>,
        prep_local: &Poseidon2PreprocessedCols<CB::Var>,
        next_row: &Poseidon2Cols<CB::Var>,
    ) {
        let local_state = local_row.state_var;

        // Add the round constants.
        let add_rc: [CB::Expr; WIDTH] = core::array::from_fn(|i| {
            local_state[i].into() + prep_local.round_counters_preprocessed.round_constants[i]
        });

        // Apply the sboxes.
        // See `populate_external_round` for why we don't have columns for the sbox output here.
        let mut sbox_deg_7: [CB::Expr; WIDTH] = core::array::from_fn(|_| CB::Expr::zero());
        for i in 0..WIDTH {
            let sbox_deg_3 = add_rc[i].clone() * add_rc[i].clone() * add_rc[i].clone();
            sbox_deg_7[i] = sbox_deg_3.clone() * sbox_deg_3.clone() * add_rc[i].clone();
        }

        // Apply the linear layer.
        let mut state = sbox_deg_7;
        external_linear_layer(&mut state);

        let next_state = next_row.state_var;
        for i in 0..WIDTH {
            builder
                .when_transition()
                .when(prep_local.round_counters_preprocessed.is_external_round)
                .assert_eq(next_state[i], state[i].clone());
        }
    }

    fn eval_internal_rounds<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local_row: &Poseidon2Cols<CB::Var>,
        next_row: &Poseidon2Cols<CB::Var>,
        round_constants: [CB::Var; WIDTH],
        is_internal_row: CB::Var,
    ) {
        let local_state = local_row.state_var;

        let s0 = local_row.internal_rounds_s0;
        let mut state: [CB::Expr; WIDTH] = core::array::from_fn(|i| local_state[i].into());
        for r in 0..NUM_INTERNAL_ROUNDS {
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
            internal_linear_layer(&mut state);

            if r < NUM_INTERNAL_ROUNDS - 1 {
                builder
                    .when(is_internal_row)
                    .assert_eq(s0[r], state[0].clone());
            }
        }

        let next_state = next_row.state_var;
        for i in 0..WIDTH {
            builder
                .when(is_internal_row)
                .assert_eq(next_state[i], state[i].clone())
        }
    }
}
