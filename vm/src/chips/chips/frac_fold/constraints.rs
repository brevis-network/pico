use crate::{
    chips::chips::frac_fold::{
        columns::{FracFoldCols, FracFoldPreprocessedCols},
        FracFoldChip,
    },
    machine::builder::{ChipBaseBuilder, ChipBuilder, RecursionBuilder},
    primitives::consts::EXTENSION_DEGREE,
};
use p3_air::{Air, WindowAccess};
use p3_field::{extension::BinomiallyExtendable, Field};
use std::borrow::Borrow;

impl<F: Field + BinomiallyExtendable<EXTENSION_DEGREE>, CB> Air<CB> for FracFoldChip<F>
where
    CB: ChipBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &FracFoldCols<CB::Var> = (*local).borrow();

        let prepr = builder.preprocessed().clone();
        let prepr_local = prepr.current_slice();
        let prepr_local: &FracFoldPreprocessedCols<CB::Var> = (*prepr_local).borrow();

        let is_real = prepr_local.is_real;

        // Memory reads: load the four input fractions.
        builder.looked_block(prepr_local.in_p1_addr, local.p1, is_real);
        builder.looked_block(prepr_local.in_q1_addr, local.q1, is_real);
        builder.looked_block(prepr_local.in_p2_addr, local.p2, is_real);
        builder.looked_block(prepr_local.in_q2_addr, local.q2, is_real);

        // Memory writes: store the two output fractions.
        builder.looking_block(prepr_local.out_p_addr, local.out_p, prepr_local.mult);
        builder.looking_block(prepr_local.out_q_addr, local.out_q, prepr_local.mult);

        // Algebraic constraint: out_p = p1 * q2 + p2 * q1  (EF multiplication)
        let p1 = local.p1.as_extension::<F, CB>();
        let q1 = local.q1.as_extension::<F, CB>();
        let p2 = local.p2.as_extension::<F, CB>();
        let q2 = local.q2.as_extension::<F, CB>();
        let out_p = local.out_p.as_extension::<F, CB>();
        let out_q = local.out_q.as_extension::<F, CB>();

        builder
            .when(is_real)
            .assert_ext_eq(p1.clone() * q2.clone() + p2.clone() * q1.clone(), out_p);

        // Algebraic constraint: out_q = q1 * q2
        builder.when(is_real).assert_ext_eq(q1 * q2, out_q);
    }
}
