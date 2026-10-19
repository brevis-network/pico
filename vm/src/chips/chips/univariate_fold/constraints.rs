use crate::{
    chips::chips::univariate_fold::{
        columns::{UnivariateFoldCols, UnivariateFoldPreprocessedCols},
        UnivariateFoldChip, MAX_COEFFS,
    },
    machine::{
        builder::{ChipBaseBuilder, ChipBuilder, RecursionBuilder},
        extension::BinomialExtension,
    },
    primitives::consts::EXTENSION_DEGREE,
};
use p3_air::{Air, WindowAccess};
use p3_field::{extension::BinomiallyExtendable, Field};
use std::borrow::Borrow;

impl<F: Field + BinomiallyExtendable<EXTENSION_DEGREE>, CB> Air<CB> for UnivariateFoldChip<F>
where
    CB: ChipBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &UnivariateFoldCols<CB::Var> = (*local).borrow();

        let prepr = builder.preprocessed().clone();
        let prepr_local = prepr.current_slice();
        let prepr_local: &UnivariateFoldPreprocessedCols<CB::Var> = (*prepr_local).borrow();

        let is_real = prepr_local.is_real;

        // Memory reads for each coefficient.
        for (addr, coeff) in prepr_local.coeffs_addrs.iter().zip(local.coeffs.iter()) {
            builder.looked_block(*addr, *coeff, is_real);
        }
        builder.looked_block(prepr_local.claimed_sum_addr, local.claimed_sum, is_real);
        builder.looked_block(prepr_local.r_addr, local.r, is_real);

        // Memory write for next_sum.
        builder.looking_block(prepr_local.next_sum_addr, local.next_sum, prepr_local.mult);

        let claimed_sum = local.claimed_sum.as_extension::<F, CB>();
        let eval_at_0 = local.eval_at_0.as_extension::<F, CB>();
        let eval_at_1 = local.eval_at_1.as_extension::<F, CB>();

        // Stacking round-0 uses a multiplicative domain of order omega_order = 2^l_skip.
        // Domain sum = (coeffs[0] + coeffs[omega_order]) * omega_order == claimed_sum.
        // MAX_COEFFS = 2*omega_order - 1, so omega_order = (MAX_COEFFS+1)/2.
        let omega_order = MAX_COEFFS.div_ceil(2); // = 16 for l_skip = 4
        let omega_f = F::from_usize(omega_order);
        let omega_ext =
            BinomialExtension::<F, CB::Expr, EXTENSION_DEGREE>::from_base(CB::Expr::from(omega_f));

        // eval_at_0 = coeffs[0].
        builder
            .when(is_real)
            .assert_ext_eq(eval_at_0.clone(), local.coeffs[0].as_extension::<F, CB>());

        // eval_at_1 = coeffs[omega_order].
        builder.when(is_real).assert_ext_eq(
            eval_at_1.clone(),
            local.coeffs[omega_order].as_extension::<F, CB>(),
        );

        // (coeffs[0] + coeffs[omega_order]) * omega_order == claimed_sum.
        builder
            .when(is_real)
            .assert_ext_eq((eval_at_0 + eval_at_1) * omega_ext, claimed_sum);

        // Bind next_sum to p(r) so a prover cannot write an arbitrary folded value.
        // Horner over all MAX_COEFFS slots; unused high slots are zero-padded by
        // trace-gen, so the full-length evaluation equals the true p(r).
        //   acc[0] = coeffs[MAX_COEFFS-1]
        //   acc[i] = acc[i-1] * r + coeffs[MAX_COEFFS-1-i]   for i in 1..(MAX_COEFFS-1)
        //   next_sum = acc[MAX_COEFFS-2] * r + coeffs[0]
        let r = local.r.as_extension::<F, CB>();

        // acc[0] == coeffs[MAX_COEFFS-1]
        builder.when(is_real).assert_ext_eq(
            local.acc[0].as_extension::<F, CB>(),
            local.coeffs[MAX_COEFFS - 1].as_extension::<F, CB>(),
        );

        // acc[i] == acc[i-1] * r + coeffs[MAX_COEFFS-1-i]
        for i in 1..(MAX_COEFFS - 1) {
            let prev = local.acc[i - 1].as_extension::<F, CB>();
            let coeff = local.coeffs[MAX_COEFFS - 1 - i].as_extension::<F, CB>();
            builder.when(is_real).assert_ext_eq(
                local.acc[i].as_extension::<F, CB>(),
                prev * r.clone() + coeff,
            );
        }

        // next_sum == acc[MAX_COEFFS-2] * r + coeffs[0]
        let acc_last = local.acc[MAX_COEFFS - 2].as_extension::<F, CB>();
        let next_sum = local.next_sum.as_extension::<F, CB>();
        builder.when(is_real).assert_ext_eq(
            next_sum,
            acc_last * r + local.coeffs[0].as_extension::<F, CB>(),
        );
    }
}
