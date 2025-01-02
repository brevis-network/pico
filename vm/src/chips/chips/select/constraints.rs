use crate::{
    chips::chips::select::{
        columns::{SelectCols, SelectPreprocessedCols},
        SelectChip,
    },
    machine::builder::{ChipBuilder, RecursionBuilder},
};
use p3_air::Air;
use p3_field::{Field, FieldAlgebra};
use p3_matrix::Matrix;
use std::borrow::Borrow;

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

        builder.looked_single(prep_local.addrs.bit, local.vals.bit, prep_local.is_real);
        builder.looked_single(prep_local.addrs.in1, local.vals.in1, prep_local.is_real);
        builder.looked_single(prep_local.addrs.in2, local.vals.in2, prep_local.is_real);
        builder.looking_single(prep_local.addrs.out1, local.vals.out1, prep_local.mult1);
        builder.looking_single(prep_local.addrs.out2, local.vals.out2, prep_local.mult2);
        builder.assert_eq(
            local.vals.out1,
            local.vals.bit * local.vals.in2 + (CB::Expr::ONE - local.vals.bit) * local.vals.in1,
        );
        builder.assert_eq(
            local.vals.out2,
            local.vals.bit * local.vals.in1 + (CB::Expr::ONE - local.vals.bit) * local.vals.in2,
        );
    }
}
