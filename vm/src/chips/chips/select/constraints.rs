use crate::{
    chips::chips::select::{
        columns::{
            SelectCols, SelectPreprocessedCols, SelectPreprocessedValueCols, SelectValueCols,
            NUM_SELECT_COLS,
        },
        SelectChip,
    },
    compiler::recursion::types::SelectIo,
    machine::builder::{ChipBuilder, RecursionBuilder},
};
use p3_air::{Air, BaseAir};
use p3_field::{Field, FieldAlgebra};
use p3_matrix::Matrix;
use std::{borrow::Borrow, iter::zip};

impl<F> BaseAir<F> for SelectChip<F> {
    fn width(&self) -> usize {
        NUM_SELECT_COLS
    }
}

impl<F: Field, CB> Air<CB> for SelectChip<F>
where
    CB: ChipBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &SelectCols<CB::Var> = (*local).borrow();
        let prep = builder.preprocessed();
        let prep_local = prep.row_slice(0);
        let prep_local: &SelectPreprocessedCols<CB::Var> = (*prep_local).borrow();

        for (
            SelectValueCols {
                vals:
                    SelectIo {
                        bit,
                        in1,
                        in2,
                        out1,
                        out2,
                    },
            },
            SelectPreprocessedValueCols {
                is_real,
                addrs,
                mult1,
                mult2,
            },
        ) in zip(local.values, prep_local.values)
        {
            builder.looked_single(addrs.bit, bit, is_real);
            builder.looked_single(addrs.in1, in1, is_real);
            builder.looked_single(addrs.in2, in2, is_real);
            builder.looking_single(addrs.out1, out1, mult1);
            builder.looking_single(addrs.out2, out2, mult2);
            builder.assert_eq(out1, bit * in2 + (CB::Expr::ONE - bit) * in1);
            builder.assert_eq(out2, bit * in1 + (CB::Expr::ONE - bit) * in2);
        }
    }
}
