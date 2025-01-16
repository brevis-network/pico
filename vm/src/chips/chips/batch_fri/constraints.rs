use crate::{
    chips::chips::batch_fri::{
        columns::{BatchFRICols, BatchFRIPreprocessedCols},
        BatchFRIChip,
    },
    machine::{
        builder::{ChipBaseBuilder, ChipBuilder, RecursionBuilder},
        extension::BinomialExtension,
    },
    primitives::consts::EXTENSION_DEGREE,
};
use p3_air::{Air, AirBuilder};
use p3_field::{extension::BinomiallyExtendable, Field};
use p3_matrix::Matrix;
use std::borrow::Borrow;

impl<F: Field + BinomiallyExtendable<EXTENSION_DEGREE>, CB> Air<CB> for BatchFRIChip<F>
where
    CB: ChipBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &BatchFRICols<CB::Var> = (*local).borrow();
        let next: &BatchFRICols<CB::Var> = (*next).borrow();
        let prepr = builder.preprocessed();
        let (prepr_local, _prepr_next) = (prepr.row_slice(0), prepr.row_slice(1));
        let prepr_local: &BatchFRIPreprocessedCols<CB::Var> = (*prepr_local).borrow();

        // Constrain memory read for alpha_pow, p_at_z, and p_at_x.
        builder.looked_block(
            prepr_local.alpha_pow_addr,
            local.alpha_pow,
            prepr_local.is_real,
        );
        builder.looked_block(prepr_local.p_at_z_addr, local.p_at_z, prepr_local.is_real);
        builder.looked_single(prepr_local.p_at_x_addr, local.p_at_x, prepr_local.is_real);

        // Constrain memory write for the accumulator.
        // Note that we write with multiplicity 1, when `is_end` is true.
        builder.looking_block(prepr_local.acc_addr, local.acc, prepr_local.is_end);

        // Constrain the accumulator value of the first row.
        builder.when_first_row().assert_ext_eq(
            local.acc.as_extension::<F, CB>(),
            local.alpha_pow.as_extension::<F, CB>()
                * (local.p_at_z.as_extension::<F, CB>()
                    - BinomialExtension::from_base(local.p_at_x.into())),
        );

        // Constrain the accumulator of the next row when the current row is the end of loop.
        builder
            .when_transition()
            .when(prepr_local.is_end)
            .assert_ext_eq(
                next.acc.as_extension::<F, CB>(),
                next.alpha_pow.as_extension::<F, CB>()
                    * (next.p_at_z.as_extension::<F, CB>()
                        - BinomialExtension::from_base(next.p_at_x.into())),
            );

        // Constrain the accumulator of the next row when the current row is not the end of loop.
        builder
            .when_transition()
            .when_not(prepr_local.is_end)
            .assert_ext_eq(
                next.acc.as_extension::<F, CB>(),
                local.acc.as_extension::<F, CB>()
                    + next.alpha_pow.as_extension::<F, CB>()
                        * (next.p_at_z.as_extension::<F, CB>()
                            - BinomialExtension::from_base(next.p_at_x.into())),
            );
    }
}
