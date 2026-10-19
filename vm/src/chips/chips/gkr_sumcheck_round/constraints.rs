use crate::{
    chips::chips::gkr_sumcheck_round::{
        columns::{GkrSumcheckRoundCols, GkrSumcheckRoundPreprocessedCols},
        GkrSumcheckRoundChip,
    },
    machine::{
        builder::{ChipBaseBuilder, ChipBuilder, RecursionBuilder},
        extension::BinomialExtension,
    },
    primitives::consts::EXTENSION_DEGREE,
};
use p3_air::{Air, WindowAccess};
use p3_field::{extension::BinomiallyExtendable, Field, PrimeCharacteristicRing};
use std::borrow::Borrow;

impl<F: Field + BinomiallyExtendable<EXTENSION_DEGREE>, CB> Air<CB> for GkrSumcheckRoundChip<F>
where
    CB: ChipBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &GkrSumcheckRoundCols<CB::Var> = (*local).borrow();

        let prepr = builder.preprocessed().clone();
        let prepr_local = prepr.current_slice();
        let prepr_local: &GkrSumcheckRoundPreprocessedCols<CB::Var> = (*prepr_local).borrow();

        let is_real = prepr_local.is_real;

        // Memory reads.
        builder.looked_block(prepr_local.claim_addr, local.claim, is_real);
        builder.looked_block(prepr_local.s1_addr, local.s1, is_real);
        builder.looked_block(prepr_local.s2_addr, local.s2, is_real);
        builder.looked_block(prepr_local.s3_addr, local.s3, is_real);
        builder.looked_block(prepr_local.r_addr, local.r, is_real);
        builder.looked_block(prepr_local.xi_addr, local.xi, is_real);
        builder.looked_block(prepr_local.eq_in_addr, local.eq_in, is_real);

        // Memory writes.
        builder.looking_block(
            prepr_local.next_claim_addr,
            local.next_claim,
            prepr_local.mult_next,
        );
        builder.looking_block(prepr_local.eq_out_addr, local.eq_out, prepr_local.mult_eq);

        let claim = local.claim.as_extension::<F, CB>();
        let s1 = local.s1.as_extension::<F, CB>();
        let s2 = local.s2.as_extension::<F, CB>();
        let s3 = local.s3.as_extension::<F, CB>();
        let r = local.r.as_extension::<F, CB>();
        let xi = local.xi.as_extension::<F, CB>();
        let eq_in = local.eq_in.as_extension::<F, CB>();
        let r_sq = local.r_sq.as_extension::<F, CB>();
        let next_claim = local.next_claim.as_extension::<F, CB>();
        let eq_out = local.eq_out.as_extension::<F, CB>();

        let ext_c = |c: u32| {
            BinomialExtension::<F, CB::Expr, EXTENSION_DEGREE>::from_base(CB::Expr::from(
                F::from_u32(c),
            ))
        };

        // (1) r_sq == r * r.
        builder
            .when(is_real)
            .assert_ext_eq(r_sq.clone(), r.clone() * r.clone());

        // (2) Cubic interpolation through (0, s0), (1, s1), (2, s2), (3, s3) at r,
        // with s0 = claim - s1 inline (the round sum check holds by construction):
        //   6*next_claim == -s0*A + 3*s1*B - 3*s2*C + s3*D
        // where, rewriting r^3 as r*r_sq to stay within degree 4 (gated):
        //   A = (r-1)(r-2)(r-3) = r*r_sq - 6*r_sq + 11*r - 6
        //   B = r(r-2)(r-3)    = r*r_sq - 5*r_sq + 6*r
        //   C = r(r-1)(r-3)    = r*r_sq - 4*r_sq + 3*r
        //   D = r(r-1)(r-2)    = r*r_sq - 3*r_sq + 2*r
        let r_cu = r.clone() * r_sq.clone();
        let a = r_cu.clone() - r_sq.clone() * ext_c(6) + r.clone() * ext_c(11) - ext_c(6);
        let b = r_cu.clone() - r_sq.clone() * ext_c(5) + r.clone() * ext_c(6);
        let c = r_cu.clone() - r_sq.clone() * ext_c(4) + r.clone() * ext_c(3);
        let d = r_cu - r_sq * ext_c(3) + r.clone() * ext_c(2);
        let s0 = claim - s1.clone();
        let rhs = s1 * b * ext_c(3) + s3 * d - s0 * a - s2 * c * ext_c(3);
        builder
            .when(is_real)
            .assert_ext_eq(next_claim * ext_c(6), rhs);

        // (3) eq_out == eq_in * eq_factor(xi, r),
        //     eq_factor(x, y) = x*y + (1-x)*(1-y) = 2xy - x - y + 1.
        let two_xir = xi.clone() * r.clone() * ext_c(2);
        let eq_factor = two_xir - xi - r
            + BinomialExtension::<F, CB::Expr, EXTENSION_DEGREE>::from_base(CB::Expr::ONE);
        builder
            .when(is_real)
            .assert_ext_eq(eq_out, eq_in * eq_factor);
    }
}
