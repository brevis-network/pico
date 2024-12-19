use crate::machine::builder::{ChipBaseBuilder, ChipBuilder, RecursionBuilder};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, FieldAlgebra};
use p3_matrix::Matrix;
use std::borrow::Borrow;

use super::{
    ExpReverseBitsLenChip, ExpReverseBitsLenCols, ExpReverseBitsLenPreprocessedCols,
    NUM_EXP_REVERSE_BITS_LEN_COLS,
};

impl<F, const DEGREE: usize> BaseAir<F> for ExpReverseBitsLenChip<DEGREE, F> {
    fn width(&self) -> usize {
        NUM_EXP_REVERSE_BITS_LEN_COLS
    }
}

impl<const DEGREE: usize, F: Field> ExpReverseBitsLenChip<DEGREE, F> {
    pub fn eval_exp_reverse_bits_len<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &ExpReverseBitsLenCols<CB::Var>,
        local_preprocess: &ExpReverseBitsLenPreprocessedCols<CB::Var>,
        next: &ExpReverseBitsLenCols<CB::Var>,
        next_preprocess: &ExpReverseBitsLenPreprocessedCols<CB::Var>,
    ) {
        // Dummy constraints to normalize to DEGREE when DEGREE > 3.
        if DEGREE > 3 {
            let lhs = (0..DEGREE)
                .map(|_| local_preprocess.is_real.into())
                .product::<CB::Expr>();
            let rhs = (0..DEGREE)
                .map(|_| local_preprocess.is_real.into())
                .product::<CB::Expr>();
            builder.assert_eq(lhs, rhs);
        }

        // Constrain mem read for x.  The read mult is one for only the first row, and zero for all
        // others.
        builder.looking_single(
            local_preprocess.x_mem.addr,
            local.x,
            local_preprocess.x_mem.mult,
        );

        // Ensure that the value at the x memory access is unchanged when not `is_last`.
        builder
            .when_transition()
            .when(next_preprocess.is_real)
            .when_not(local_preprocess.is_last)
            .assert_eq(local.x, next.x);

        // Constrain mem read for exponent's bits.  The read mult is one for all real rows.
        builder.looking_single(
            local_preprocess.exponent_mem.addr,
            local.current_bit,
            local_preprocess.exponent_mem.mult,
        );

        // The accumulator needs to start with the multiplier for every `is_first` row.
        builder
            .when(local_preprocess.is_first)
            .assert_eq(local.accum, local.multiplier);

        // `multiplier` is x if the current bit is 1, and 1 if the current bit is 0.
        builder
            .when(local_preprocess.is_real)
            .when(local.current_bit)
            .assert_eq(local.multiplier, local.x);
        builder
            .when(local_preprocess.is_real)
            .when_not(local.current_bit)
            .assert_eq(local.multiplier, CB::Expr::ONE);

        // To get `next.accum`, we multiply `local.prev_accum_squared` by `local.multiplier` when
        // not `is_last`.
        builder.when(local_preprocess.is_real).assert_eq(
            local.prev_accum_squared_times_multiplier,
            local.prev_accum_squared * local.multiplier,
        );

        builder
            .when(local_preprocess.is_real)
            .when_not(local_preprocess.is_first)
            .assert_eq(local.accum, local.prev_accum_squared_times_multiplier);

        // Constrain the accum_squared column.
        builder
            .when(local_preprocess.is_real)
            .assert_eq(local.accum_squared, local.accum * local.accum);

        builder
            .when_transition()
            .when(next_preprocess.is_real)
            .when_not(local_preprocess.is_last)
            .assert_eq(next.prev_accum_squared, local.accum_squared);

        // Constrain mem write for the result.
        builder.looking_single(
            local_preprocess.result_mem.addr,
            local.accum,
            local_preprocess.result_mem.mult,
        );
    }

    #[allow(dead_code)]
    pub const fn do_exp_bit_memory_access<T: Copy>(
        local: &ExpReverseBitsLenPreprocessedCols<T>,
    ) -> T {
        local.is_real
    }
}

impl<F: Field, CB, const DEGREE: usize> Air<CB> for ExpReverseBitsLenChip<DEGREE, F>
where
    CB: ChipBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &ExpReverseBitsLenCols<CB::Var> = (*local).borrow();
        let next: &ExpReverseBitsLenCols<CB::Var> = (*next).borrow();
        let prepocess = builder.preprocessed();
        let (prepocess_local, prepocess_next) = (prepocess.row_slice(0), prepocess.row_slice(1));
        let prepocess_local: &ExpReverseBitsLenPreprocessedCols<_> = (*prepocess_local).borrow();
        let prepocess_next: &ExpReverseBitsLenPreprocessedCols<_> = (*prepocess_next).borrow();
        self.eval_exp_reverse_bits_len::<CB>(builder, local, prepocess_local, next, prepocess_next);
    }
}
