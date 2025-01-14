use super::columns::{
    BABYBEAR_NUM_POSEIDON2_HD_COLS, BABYBEAR_NUM_POSEIDON2_LD_COLS, KOALABEAR_NUM_POSEIDON2_COLS,
};
use crate::{
    chips::chips::poseidon2::{
        columns::{permutation::Poseidon2, preprocessed::Poseidon2PreprocessedCols},
        utils::{external_linear_layer, internal_linear_layer},
        Poseidon2Chip,
    },
    machine::{
        builder::{ChipBuilder, RecursionBuilder},
        field::{FieldBehavior, FieldType},
    },
    primitives::{
        consts::{
            BABYBEAR_NUM_EXTERNAL_ROUNDS, BABYBEAR_NUM_INTERNAL_ROUNDS,
            KOALABEAR_NUM_EXTERNAL_ROUNDS, KOALABEAR_NUM_INTERNAL_ROUNDS, PERMUTATION_WIDTH,
        },
        RC_16_30_U32,
    },
};
use p3_air::{Air, BaseAir};
use p3_field::{Field, FieldAlgebra};
use p3_matrix::Matrix;
use std::{array, borrow::Borrow};

macro_rules! impl_poseidon2_chip {
    ($num_external_rounds:expr, $num_internal_rounds:expr, $num_col_ld:expr, $num_col_hd:expr) => {
        impl<F, const DEGREE: usize> BaseAir<F>
            for Poseidon2Chip<
                DEGREE,
                $num_external_rounds,
                $num_internal_rounds,
                { $num_internal_rounds - 1 },
                F,
            >
        {
            fn width(&self) -> usize {
                if DEGREE == 3 {
                    $num_col_ld
                } else if DEGREE == 9 {
                    $num_col_hd
                } else {
                    panic!("Unsupported degree: {}", DEGREE);
                }
            }
        }

        impl<F: Field, CB: ChipBuilder<F>, const DEGREE: usize> Air<CB>
            for Poseidon2Chip<
                DEGREE,
                $num_external_rounds,
                $num_internal_rounds,
                { $num_internal_rounds - 1 },
                F,
            >
        where
            CB::Var: 'static,
        {
            fn eval(&self, builder: &mut CB) {
                let main = builder.main();
                let preprocessed = builder.preprocessed();
                let local_row = Self::convert::<CB::Var>(main.row_slice(0));
                let preprocessed_local = preprocessed.row_slice(0);
                let preprocessed_local: &Poseidon2PreprocessedCols<_> =
                    (*preprocessed_local).borrow();

                // Dummy constraints to normalize to DEGREE.
                let lhs = (0..DEGREE)
                    .map(|_| local_row.external_rounds_state()[0][0].into())
                    .product::<CB::Expr>();
                let rhs = (0..DEGREE)
                    .map(|_| local_row.external_rounds_state()[0][0].into())
                    .product::<CB::Expr>();
                builder.assert_eq(lhs, rhs);

                // For now, include only memory constraints.
                (0..PERMUTATION_WIDTH).for_each(|i| {
                    builder.looking_single(
                        preprocessed_local.input[i],
                        local_row.external_rounds_state()[0][i],
                        preprocessed_local.is_real_neg,
                    )
                });

                (0..PERMUTATION_WIDTH).for_each(|i| {
                    builder.looking_single(
                        preprocessed_local.output[i].addr,
                        local_row.perm_output()[i],
                        preprocessed_local.output[i].mult,
                    )
                });

                // Apply the external rounds.
                for r in 0..$num_external_rounds {
                    self.eval_external_round(builder, local_row.as_ref(), r);
                }

                // Apply the internal rounds.
                self.eval_internal_rounds(builder, local_row.as_ref());
            }
        }
    };
}

impl_poseidon2_chip!(
    BABYBEAR_NUM_EXTERNAL_ROUNDS,
    BABYBEAR_NUM_INTERNAL_ROUNDS,
    BABYBEAR_NUM_POSEIDON2_LD_COLS,
    BABYBEAR_NUM_POSEIDON2_HD_COLS
);

impl_poseidon2_chip!(
    KOALABEAR_NUM_EXTERNAL_ROUNDS,
    KOALABEAR_NUM_INTERNAL_ROUNDS,
    KOALABEAR_NUM_POSEIDON2_COLS,
    KOALABEAR_NUM_POSEIDON2_COLS
);

impl<
        const DEGREE: usize,
        const NUM_EXTERNAL_ROUNDS: usize,
        const NUM_INTERNAL_ROUNDS: usize,
        const NUM_INTERNAL_ROUNDS_MINUS_ONE: usize,
        F: Field,
    >
    Poseidon2Chip<
        DEGREE,
        NUM_EXTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS,
        NUM_INTERNAL_ROUNDS_MINUS_ONE,
        F,
    >
{
    /// Eval the constraints for the external rounds.
    fn eval_external_round<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local_row: &dyn Poseidon2<
            CB::Var,
            NUM_EXTERNAL_ROUNDS,
            NUM_INTERNAL_ROUNDS,
            NUM_INTERNAL_ROUNDS_MINUS_ONE,
        >,
        r: usize,
    ) {
        let mut local_state: [CB::Expr; PERMUTATION_WIDTH] =
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
        let add_rc: [CB::Expr; PERMUTATION_WIDTH] = array::from_fn(|i| {
            local_state[i].clone() + CB::F::from_wrapped_u32(RC_16_30_U32[round][i])
        });

        // Apply the sboxes.
        let mut state;
        if F::field_type() == FieldType::TypeBabyBear {
            let mut sbox_deg_7: [CB::Expr; PERMUTATION_WIDTH] = array::from_fn(|_| CB::Expr::ZERO);
            let mut sbox_deg_3: [CB::Expr; PERMUTATION_WIDTH] = array::from_fn(|_| CB::Expr::ZERO);
            for i in 0..PERMUTATION_WIDTH {
                let calculated_sbox_deg_3 =
                    add_rc[i].clone() * add_rc[i].clone() * add_rc[i].clone();

                if let Some(external_sbox) = local_row.external_rounds_sbox() {
                    builder.assert_eq(external_sbox[r][i].into(), calculated_sbox_deg_3);
                    sbox_deg_3[i] = external_sbox[r][i].into();
                } else {
                    sbox_deg_3[i] = calculated_sbox_deg_3;
                }

                sbox_deg_7[i] = sbox_deg_3[i].clone() * sbox_deg_3[i].clone() * add_rc[i].clone();
            }
            state = sbox_deg_7;
        } else if F::field_type() == FieldType::TypeKoalaBear {
            let mut sbox_deg_3: [CB::Expr; PERMUTATION_WIDTH] = array::from_fn(|_| CB::Expr::ZERO);
            for i in 0..PERMUTATION_WIDTH {
                sbox_deg_3[i] = add_rc[i].clone() * add_rc[i].clone() * add_rc[i].clone();

                assert!(local_row.external_rounds_sbox().is_none());
            }
            state = sbox_deg_3;
        } else {
            panic!("Unsupported field type: {:?}", F::field_type());
        }

        // Apply the linear layer.
        external_linear_layer(&mut state);

        let next_state = if r == (NUM_EXTERNAL_ROUNDS / 2) - 1 {
            local_row.internal_rounds_state()
        } else if r == NUM_EXTERNAL_ROUNDS - 1 {
            local_row.perm_output()
        } else {
            &local_row.external_rounds_state()[r + 1]
        };

        for i in 0..PERMUTATION_WIDTH {
            builder.assert_eq(next_state[i], state[i].clone());
        }
    }

    /// Eval the constraints for the internal rounds.
    fn eval_internal_rounds<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local_row: &dyn Poseidon2<
            CB::Var,
            NUM_EXTERNAL_ROUNDS,
            NUM_INTERNAL_ROUNDS,
            NUM_INTERNAL_ROUNDS_MINUS_ONE,
        >,
    ) {
        let state = &local_row.internal_rounds_state();
        let s0 = local_row.internal_rounds_s0();
        let mut state: [CB::Expr; PERMUTATION_WIDTH] = array::from_fn(|i| state[i].into());
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

            // Apply the sboxes.
            if F::field_type() == FieldType::TypeBabyBear {
                let sbox_deg_7 = sbox_deg_3.clone() * sbox_deg_3.clone() * add_rc.clone();
                state[0] = sbox_deg_7.clone();
            } else if F::field_type() == FieldType::TypeKoalaBear {
                state[0] = sbox_deg_3.clone();
            } else {
                panic!("Unsupported field type: {:?}", F::field_type());
            }

            internal_linear_layer::<F, _>(&mut state);

            if r < NUM_INTERNAL_ROUNDS - 1 {
                builder.assert_eq(s0[r], state[0].clone());
            }
        }

        let external_state = local_row.external_rounds_state()[NUM_EXTERNAL_ROUNDS / 2];
        for i in 0..PERMUTATION_WIDTH {
            builder.assert_eq(external_state[i], state[i].clone())
        }
    }
}
