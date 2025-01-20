use crate::{
    chips::chips::alu_base::{
        columns::{
            BaseAluAccessCols, BaseAluCols, BaseAluPreprocessedCols, BaseAluValueCols,
            NUM_BASE_ALU_COLS,
        },
        BaseAluChip,
    },
    compiler::recursion_v2::types::BaseAluIo,
    machine::builder::{ChipBuilder, RecursionBuilder},
};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::Field;
use p3_matrix::Matrix;
use std::{borrow::Borrow, iter::zip};

impl<F> BaseAir<F> for BaseAluChip<F> {
    fn width(&self) -> usize {
        NUM_BASE_ALU_COLS
    }
}

impl<F: Field, CB> Air<CB> for BaseAluChip<F>
where
    CB: ChipBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &BaseAluCols<CB::Var> = (*local).borrow();
        let prep = builder.preprocessed();
        let prep_local = prep.row_slice(0);
        let prep_local: &BaseAluPreprocessedCols<CB::Var> = (*prep_local).borrow();

        for (
            BaseAluValueCols {
                vals: BaseAluIo { out, in1, in2 },
            },
            BaseAluAccessCols {
                addrs,
                is_add,
                is_sub,
                is_mul,
                is_div,
                mult,
            },
        ) in zip(local.values, prep_local.accesses)
        {
            // Check exactly one flag is enabled.
            let is_real = is_add + is_sub + is_mul + is_div;
            builder.assert_bool(is_real.clone());

            builder.when(is_add).assert_eq(in1 + in2, out);
            builder.when(is_sub).assert_eq(in1, in2 + out);
            builder.when(is_mul).assert_eq(out, in1 * in2);
            builder.when(is_div).assert_eq(in2 * out, in1);

            builder.looked_single(addrs.in1, in1, is_real.clone());

            builder.looked_single(addrs.in2, in2, is_real);

            builder.looking_single(addrs.out, out, mult);
        }
    }
}
