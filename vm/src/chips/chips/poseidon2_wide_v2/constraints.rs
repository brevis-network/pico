use crate::{
    chips::chips::poseidon2_wide_v2::{
        columns::{
            permutation::Poseidon2, preprocessed::Poseidon2PreprocessedCols,
            NUM_POSEIDON2_DEGREE3_COLS, NUM_POSEIDON2_DEGREE9_COLS,
        },
        utils::{external_linear_layer, internal_linear_layer},
        Poseidon2WideChip, NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS, WIDTH,
    },
    machine::builder::{ChipBuilder, RecursionBuilder},
    primitives::RC_16_30_U32,
};
use p3_air::{Air, BaseAir};
use p3_field::{Field, FieldAlgebra};
use p3_matrix::Matrix;
use std::{array, borrow::Borrow};

impl<F, const DEGREE: usize> BaseAir<F> for Poseidon2WideChip<DEGREE, F> {
    fn width(&self) -> usize {
        if DEGREE == 3 {
            NUM_POSEIDON2_DEGREE3_COLS
        } else if DEGREE == 9 || DEGREE == 17 {
            NUM_POSEIDON2_DEGREE9_COLS
        } else {
            panic!("Unsupported degree: {}", DEGREE);
        }
    }
}

impl<F: Field, CB: ChipBuilder<F>, const DEGREE: usize> Air<CB> for Poseidon2WideChip<DEGREE, F>
where
    CB::Var: 'static,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let preprocessed = builder.preprocessed();
        let local_row = Self::convert::<CB::Var>(main.row_slice(0));
        let preprocessed_local = preprocessed.row_slice(0);
        let preprocessed_local: &Poseidon2PreprocessedCols<_> = (*preprocessed_local).borrow();

        // Dummy constraints to normalize to DEGREE.
        let lhs = (0..DEGREE)
            .map(|_| local_row.external_rounds_state()[0][0].into())
            .product::<CB::Expr>();
        let rhs = (0..DEGREE)
            .map(|_| local_row.external_rounds_state()[0][0].into())
            .product::<CB::Expr>();
        builder.assert_eq(lhs, rhs);

        // For now, include only memory constraints.
        (0..WIDTH).for_each(|i| {
            builder.looking_single(
                preprocessed_local.input[i],
                local_row.external_rounds_state()[0][i],
                preprocessed_local.is_real_neg,
            )
        });

        (0..WIDTH).for_each(|i| {
            builder.looking_single(
                preprocessed_local.output[i].addr,
                local_row.perm_output()[i],
                preprocessed_local.output[i].mult,
            )
        });

        // Apply the external rounds.
        for r in 0..NUM_EXTERNAL_ROUNDS {
            self.eval_external_round(builder, local_row.as_ref(), r);
        }

        // Apply the internal rounds.
        self.eval_internal_rounds(builder, local_row.as_ref());
    }
}

impl<const DEGREE: usize, F: Field> Poseidon2WideChip<DEGREE, F> {
    /// Eval the constraints for the external rounds.
    fn eval_external_round<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local_row: &dyn Poseidon2<CB::Var>,
        r: usize,
    ) {
        let mut local_state: [CB::Expr; WIDTH] =
            array::from_fn(|i| local_row.external_rounds_state()[r][i].into());

        // For the first round, apply the linear layer.
        if r == 0 {
            external_linear_layer(&mut local_state);
        }

        // Add the round constants.
        let round = if r < NUM_EXTERNAL_ROUNDS / 2 {
            r
        } else {
            r + NUM_INTERNAL_ROUNDS
        };
        let add_rc: [CB::Expr; WIDTH] = array::from_fn(|i| {
            local_state[i].clone() + CB::F::from_wrapped_u32(RC_16_30_U32[round][i])
        });

        // Apply the sboxes.
        // See `populate_external_round` for why we don't have columns for the sbox output here.
        let mut sbox_deg_7: [CB::Expr; WIDTH] = array::from_fn(|_| CB::Expr::ZERO);
        let mut sbox_deg_3: [CB::Expr; WIDTH] = array::from_fn(|_| CB::Expr::ZERO);
        for i in 0..WIDTH {
            let calculated_sbox_deg_3 = add_rc[i].clone() * add_rc[i].clone() * add_rc[i].clone();

            if let Some(external_sbox) = local_row.external_rounds_sbox() {
                builder.assert_eq(external_sbox[r][i].into(), calculated_sbox_deg_3);
                sbox_deg_3[i] = external_sbox[r][i].into();
            } else {
                sbox_deg_3[i] = calculated_sbox_deg_3;
            }

            sbox_deg_7[i] = sbox_deg_3[i].clone() * sbox_deg_3[i].clone() * add_rc[i].clone();
        }

        // Apply the linear layer.
        let mut state = sbox_deg_7;
        external_linear_layer(&mut state);

        let next_state = if r == (NUM_EXTERNAL_ROUNDS / 2) - 1 {
            local_row.internal_rounds_state()
        } else if r == NUM_EXTERNAL_ROUNDS - 1 {
            local_row.perm_output()
        } else {
            &local_row.external_rounds_state()[r + 1]
        };

        for i in 0..WIDTH {
            builder.assert_eq(next_state[i], state[i].clone());
        }
    }

    /// Eval the constraints for the internal rounds.
    fn eval_internal_rounds<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local_row: &dyn Poseidon2<CB::Var>,
    ) {
        let state = &local_row.internal_rounds_state();
        let s0 = local_row.internal_rounds_s0();
        let mut state: [CB::Expr; WIDTH] = array::from_fn(|i| state[i].into());
        for r in 0..NUM_INTERNAL_ROUNDS {
            // Add the round constant.
            let round = r + NUM_EXTERNAL_ROUNDS / 2;
            let add_rc = if r == 0 {
                state[0].clone()
            } else {
                s0[r - 1].into()
            } + CB::Expr::from_wrapped_u32(RC_16_30_U32[round][0]);

            let mut sbox_deg_3 = add_rc.clone() * add_rc.clone() * add_rc.clone();
            if let Some(internal_sbox) = local_row.internal_rounds_sbox() {
                builder.assert_eq(internal_sbox[r], sbox_deg_3);
                sbox_deg_3 = internal_sbox[r].into();
            }

            // See `populate_internal_rounds` for why we don't have columns for the sbox output
            // here.
            let sbox_deg_7 = sbox_deg_3.clone() * sbox_deg_3.clone() * add_rc.clone();

            // Apply the linear layer.
            // See `populate_internal_rounds` for why we don't have columns for the new state here.
            state[0] = sbox_deg_7.clone();
            internal_linear_layer(&mut state);

            if r < NUM_INTERNAL_ROUNDS - 1 {
                builder.assert_eq(s0[r], state[0].clone());
            }
        }

        let external_state = local_row.external_rounds_state()[NUM_EXTERNAL_ROUNDS / 2];
        for i in 0..WIDTH {
            builder.assert_eq(external_state[i], state[i].clone())
        }
    }
}
