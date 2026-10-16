use crate::{
    chips::chips::lagrange_eval_d2::{
        columns::{LagrangeEvalD2Cols, LagrangeEvalD2PreprocessedCols},
        LagrangeEvalD2Chip,
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

impl<F: Field + BinomiallyExtendable<EXTENSION_DEGREE>, CB> Air<CB> for LagrangeEvalD2Chip<F>
where
    CB: ChipBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &LagrangeEvalD2Cols<CB::Var> = (*local).borrow();

        let prepr = builder.preprocessed().clone();
        let prepr_local = prepr.current_slice();
        let prepr_local: &LagrangeEvalD2PreprocessedCols<CB::Var> = (*prepr_local).borrow();

        let is_real = prepr_local.is_real;

        // Memory reads: the running claim, the two prover evaluations, the challenge.
        builder.looked_block(prepr_local.claim_addr, local.claim, is_real);
        builder.looked_block(prepr_local.s1_addr, local.s1, is_real);
        builder.looked_block(prepr_local.s2_addr, local.s2, is_real);
        builder.looked_block(prepr_local.r_addr, local.r, is_real);

        // Memory write: the next claim.
        builder.looking_block(
            prepr_local.next_claim_addr,
            local.next_claim,
            prepr_local.mult,
        );

        let claim = local.claim.as_extension::<F, CB>();
        let s1 = local.s1.as_extension::<F, CB>();
        let s2 = local.s2.as_extension::<F, CB>();
        let r = local.r.as_extension::<F, CB>();
        let next_claim = local.next_claim.as_extension::<F, CB>();

        let one = BinomialExtension::<F, CB::Expr, EXTENSION_DEGREE>::from_base(CB::Expr::ONE);
        let two = BinomialExtension::<F, CB::Expr, EXTENSION_DEGREE>::from_base(CB::Expr::TWO);

        // s0 = claim - s1 (inline: enforces the round's sum check s(0) + s(1) == claim
        // by construction). Bind next_claim to the quadratic interpolation at r:
        //   2 * next_claim == s0*(r-1)*(r-2) - 2*s1*r*(r-2) + s2*r*(r-1)
        // Degree 3 in the committed columns, 4 with the is_real gate (== max degree).
        let s0 = claim - s1.clone();
        let r1 = r.clone() - one; // r - 1
        let r2 = r.clone() - two.clone(); // r - 2
        let l0 = s0 * r1.clone() * r2.clone();
        let l1 = s1 * r.clone() * r2;
        let l2 = s2 * r * r1;
        builder
            .when(is_real)
            .assert_ext_eq(next_claim * two.clone(), l0 - l1.clone() * two + l2);
    }
}
