use crate::{
    chips::chips::horner_eval::{
        columns::{HornerEvalCols, HornerEvalPreprocessedCols},
        HornerEvalChip,
    },
    machine::{
        builder::{ChipBaseBuilder, ChipBuilder, RecursionBuilder},
        extension::BinomialExtension,
    },
    primitives::consts::EXTENSION_DEGREE,
};
use p3_air::{Air, AirBuilder, WindowAccess};
use p3_field::{extension::BinomiallyExtendable, Field};
use std::borrow::Borrow;

/// Row contribution: c0*x^3 + c1*x^2 + c2*x + c3 (coefficients in evaluation order).
fn row_fold<F, CB>(
    cols: &HornerEvalCols<CB::Var>,
) -> BinomialExtension<F, CB::Expr, EXTENSION_DEGREE>
where
    F: Field + BinomiallyExtendable<EXTENSION_DEGREE>,
    CB: ChipBuilder<F>,
{
    let x = cols.x.as_extension::<F, CB>();
    let x2 = cols.x2.as_extension::<F, CB>();
    let x3 = cols.x3.as_extension::<F, CB>();
    cols.coeffs[0].as_extension::<F, CB>() * x3
        + cols.coeffs[1].as_extension::<F, CB>() * x2
        + cols.coeffs[2].as_extension::<F, CB>() * x
        + cols.coeffs[3].as_extension::<F, CB>()
}

impl<F: Field + BinomiallyExtendable<EXTENSION_DEGREE>, CB> Air<CB> for HornerEvalChip<F>
where
    CB: ChipBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let (local, next) = (main.current_slice(), main.next_slice());
        let local: &HornerEvalCols<CB::Var> = (*local).borrow();
        let next: &HornerEvalCols<CB::Var> = (*next).borrow();

        let prepr = builder.preprocessed().clone();
        let prepr_local = prepr.current_slice();
        let prepr_local: &HornerEvalPreprocessedCols<CB::Var> = (*prepr_local).borrow();

        // Memory reads: the coefficients on every real row, x only on segment start.
        for j in 0..4 {
            builder.looked_block(
                prepr_local.coeff_addrs[j],
                local.coeffs[j],
                prepr_local.is_real,
            );
        }
        builder.looked_block(prepr_local.x_addr, local.x, prepr_local.is_start);

        // Memory write for the final accumulator (mult is zero on non-end rows).
        builder.looking_block(prepr_local.out_addr, local.acc, prepr_local.mult);

        let x = local.x.as_extension::<F, CB>();
        let x2 = local.x2.as_extension::<F, CB>();
        let x3 = local.x3.as_extension::<F, CB>();
        let x4 = local.x4.as_extension::<F, CB>();
        let acc = local.acc.as_extension::<F, CB>();
        let next_x = next.x.as_extension::<F, CB>();
        let next_x4 = next.x4.as_extension::<F, CB>();
        let next_acc = next.acc.as_extension::<F, CB>();

        // Power helpers (bind x2/x3/x4 to x).
        builder
            .when(prepr_local.is_real)
            .assert_ext_eq(x2.clone(), x.clone() * x.clone());
        builder
            .when(prepr_local.is_real)
            .assert_ext_eq(x3.clone(), x2.clone() * x.clone());
        builder
            .when(prepr_local.is_real)
            .assert_ext_eq(x4, x2.clone() * x2);

        // Segment start: acc = row_fold (Horner over the first 4 coefficients,
        // starting from acc = 0).
        builder
            .when(prepr_local.is_start)
            .assert_ext_eq(acc.clone(), row_fold::<F, CB>(local));

        // Within a segment: x is copied down and the accumulator chains
        //   next_acc = acc * x^4 + next_row_fold.
        let in_segment = prepr_local.is_real - prepr_local.is_end;
        builder
            .when_transition()
            .when(in_segment.clone())
            .assert_ext_eq(next_x, x);
        builder
            .when_transition()
            .when(in_segment)
            .assert_ext_eq(next_acc, acc * next_x4 + row_fold::<F, CB>(next));
    }
}
