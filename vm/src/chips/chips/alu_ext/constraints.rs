use crate::{
    chips::chips::alu_ext::{
        columns::{
            ExtAluAccessCols, ExtAluCols, ExtAluPreprocessedCols, ExtAluValueCols, NUM_EXT_ALU_COLS,
        },
        ExtAluChip,
    },
    machine::builder::{ChipBuilder, ExtensionBuilder, RecursionBuilder},
    primitives::consts::EXTENSION_DEGREE,
};
use p3_air::{Air, BaseAir};
use p3_field::{extension::BinomiallyExtendable, Field};
use p3_matrix::Matrix;
use std::{borrow::Borrow, iter::zip};

impl<F: Field> BaseAir<F> for ExtAluChip<F> {
    fn width(&self) -> usize {
        NUM_EXT_ALU_COLS
    }
}

impl<F: Field + BinomiallyExtendable<EXTENSION_DEGREE>, CB> Air<CB> for ExtAluChip<F>
where
    CB: ChipBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &ExtAluCols<CB::Var> = (*local).borrow();
        let prep = builder.preprocessed();
        let prep_local = prep.row_slice(0);
        let prep_local: &ExtAluPreprocessedCols<CB::Var> = (*prep_local).borrow();

        for (
            ExtAluValueCols { vals },
            ExtAluAccessCols {
                addrs,
                is_add,
                is_sub,
                is_mul,
                is_div,
                mult,
            },
        ) in zip(local.values, prep_local.accesses)
        {
            let in1 = vals.in1.as_extension::<F, CB>();
            let in2 = vals.in2.as_extension::<F, CB>();
            let out = vals.out.as_extension::<F, CB>();

            // Check exactly one flag is enabled.
            let is_real = is_add + is_sub + is_mul + is_div;
            builder.assert_bool(is_real.clone());

            builder
                .when(is_add)
                .assert_ext_eq(in1.clone() + in2.clone(), out.clone());
            builder
                .when(is_sub)
                .assert_ext_eq(in1.clone(), in2.clone() + out.clone());
            builder
                .when(is_mul)
                .assert_ext_eq(in1.clone() * in2.clone(), out.clone());
            builder.when(is_div).assert_ext_eq(in1, in2 * out);

            // Read the inputs from memory.
            builder.looked_block(addrs.in1, vals.in1, is_real.clone());

            builder.looked_block(addrs.in2, vals.in2, is_real);

            // Write the output to memory.
            builder.looking_block(addrs.out, vals.out, mult);
        }
    }
}
