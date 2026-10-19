use crate::{
    chips::chips::ext_dot_product::{
        columns::{ExtDotProductCols, ExtDotProductPreprocessedCols},
        ExtDotProductChip,
    },
    machine::{
        builder::{ChipBaseBuilder, ChipBuilder, RecursionBuilder},
        extension::BinomialExtension,
    },
    primitives::consts::{EXTENSION_DEGREE, EXT_DOT_PRODUCT_DATAPAR, EXT_DOT_PRODUCT_GROUPS},
};
use p3_air::{Air, AirBuilder, WindowAccess};
use p3_field::{extension::BinomiallyExtendable, Field};
use std::borrow::Borrow;

/// Row-local dot contribution: sum over groups g and lanes k of
/// val[g].lane_k (base) * mu[g*EXTENSION_DEGREE + k] (ext).
fn row_sum<F, CB>(
    cols: &ExtDotProductCols<CB::Var>,
) -> BinomialExtension<F, CB::Expr, EXTENSION_DEGREE>
where
    F: Field + BinomiallyExtendable<EXTENSION_DEGREE>,
    CB: ChipBuilder<F>,
{
    let mut acc: Option<BinomialExtension<F, CB::Expr, EXTENSION_DEGREE>> = None;
    for g in 0..EXT_DOT_PRODUCT_GROUPS {
        for k in 0..EXTENSION_DEGREE {
            let mu = cols.mus[g * EXTENSION_DEGREE + k].as_extension::<F, CB>();
            let val: CB::Expr = cols.vals[g].0[k].into();
            let term = mu * BinomialExtension::from_base(val);
            acc = Some(match acc {
                None => term,
                Some(a) => a + term,
            });
        }
    }
    acc.unwrap()
}

impl<F: Field + BinomiallyExtendable<EXTENSION_DEGREE>, CB> Air<CB> for ExtDotProductChip<F>
where
    CB: ChipBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let (local, next) = (main.current_slice(), main.next_slice());
        let local: &ExtDotProductCols<CB::Var> = (*local).borrow();
        let next: &ExtDotProductCols<CB::Var> = (*next).borrow();

        let prepr = builder.preprocessed().clone();
        let prepr_local = prepr.current_slice();
        let prepr_local: &ExtDotProductPreprocessedCols<CB::Var> = (*prepr_local).borrow();

        // Memory reads: one packed value block per group and one mu per lane
        // (zero-padded lanes/groups read addr 0, whose value is the zero block;
        // the lowering accounts those reads).
        for j in 0..EXT_DOT_PRODUCT_DATAPAR {
            builder.looked_block(prepr_local.mu_addrs[j], local.mus[j], prepr_local.is_real);
        }
        for g in 0..EXT_DOT_PRODUCT_GROUPS {
            builder.looked_block(prepr_local.val_addrs[g], local.vals[g], prepr_local.is_real);
        }

        // Memory write for the final accumulator (mult is zero on non-end rows).
        builder.looking_block(prepr_local.acc_addr, local.acc, prepr_local.mult);

        let acc = local.acc.as_extension::<F, CB>();
        let next_acc = next.acc.as_extension::<F, CB>();
        let local_sum = row_sum::<F, CB>(local);
        let next_sum = row_sum::<F, CB>(next);

        // First trace row starts a segment: acc = row_sum.
        builder
            .when_first_row()
            .when(prepr_local.is_real)
            .assert_ext_eq(acc.clone(), local_sum);

        // A row after a segment end starts a new segment (padding rows satisfy
        // this trivially: 0 == 0).
        builder
            .when_transition()
            .when(prepr_local.is_end)
            .assert_ext_eq(next_acc.clone(), next_sum.clone());

        // Within a segment the accumulator chains: next_acc = acc + next_row_sum.
        builder
            .when_transition()
            .when(prepr_local.is_real - prepr_local.is_end)
            .assert_ext_eq(next_acc, acc + next_sum);
    }
}
