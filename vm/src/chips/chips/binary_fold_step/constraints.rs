use crate::{
    chips::chips::binary_fold_step::{
        columns::{BinaryFoldStepCols, BinaryFoldStepPreprocessedCols},
        BinaryFoldStepChip,
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

impl<F: Field + BinomiallyExtendable<EXTENSION_DEGREE>, CB> Air<CB> for BinaryFoldStepChip<F>
where
    CB: ChipBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &BinaryFoldStepCols<CB::Var> = (*local).borrow();

        let prepr = builder.preprocessed().clone();
        let prepr_local = prepr.current_slice();
        let prepr_local: &BinaryFoldStepPreprocessedCols<CB::Var> = (*prepr_local).borrow();

        let is_real = prepr_local.is_real;

        // Memory reads.
        builder.looked_single(prepr_local.tw_addr, local.tw, is_real);
        builder.looked_single(prepr_local.xi_addr, local.xi, is_real);
        builder.looked_single(prepr_local.inv_tw_addr, local.inv_tw, is_real);
        builder.looked_single(prepr_local.xi_inv_addr, local.xi_inv, is_real);
        builder.looked_block(prepr_local.alpha_addr, local.alpha, is_real);
        builder.looked_block(prepr_local.v_lo_addr, local.v_lo, is_real);
        builder.looked_block(prepr_local.v_hi_addr, local.v_hi, is_real);

        // Memory write.
        builder.looking_block(prepr_local.out_addr, local.out, prepr_local.mult);

        let alpha = local.alpha.as_extension::<F, CB>();
        let v_lo = local.v_lo.as_extension::<F, CB>();
        let v_hi = local.v_hi.as_extension::<F, CB>();
        let amt = local.amt.as_extension::<F, CB>();
        let out = local.out.as_extension::<F, CB>();

        let embed = |e: CB::Expr| BinomialExtension::<F, CB::Expr, EXTENSION_DEGREE>::from_base(e);

        // (1) amt = alpha - tw * xi.
        builder
            .when(is_real)
            .assert_ext_eq(amt.clone(), alpha - embed(local.tw * local.xi));

        // (2) tih = inv_tw * xi_inv * (1/2).
        // NOTE: xi_inv is consumed as the caller-supplied inverse of xi; this chip does not
        // constrain xi * xi_inv == 1 locally. That relation IS now enforced upstream in the WHIR
        // query lowering (which asserts `zi_root * zi_root_inv == 1`, with zi_root itself bound
        // to the Fiat-Shamir sample), so the hinted xi_inv this chip reads is pinned.
        let inv2 = F::TWO.inverse();
        builder.when(is_real).assert_eq(
            local.tih,
            local.inv_tw * local.xi_inv * CB::Expr::from(inv2),
        );

        // (3) out = v_lo + amt * (v_lo - v_hi) * tih.
        builder.when(is_real).assert_ext_eq(
            out,
            v_lo.clone() + amt * (v_lo - v_hi) * embed(local.tih.into()),
        );
    }
}
