use super::{
    columns::{FriFoldMainCols, FriFoldPreprocessedCols, NUM_FRI_FOLD_MAIN_COLS},
    FriFoldChip,
};
use crate::machine::{
    builder::{ChipBaseBuilder, ChipBuilder, RecursionBuilder},
    extension::BinomialExtension,
};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::PrimeField32;
use p3_matrix::Matrix;
use std::borrow::Borrow;

impl<const DEGREE: usize, F: PrimeField32> BaseAir<F> for FriFoldChip<DEGREE, F> {
    fn width(&self) -> usize {
        NUM_FRI_FOLD_MAIN_COLS
    }
}

impl<const DEGREE: usize, F: PrimeField32, CB: ChipBuilder<F>> Air<CB> for FriFoldChip<DEGREE, F>
where
    CB::Var: Sized,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let (local, next) = (main.row_slice(0), main.row_slice(1));
        let local: &FriFoldMainCols<CB::Var> = (*local).borrow();
        let next: &FriFoldMainCols<CB::Var> = (*next).borrow();
        let prepr = builder.preprocessed();
        let (prepr_local, prepr_next) = (prepr.row_slice(0), prepr.row_slice(1));
        let prepr_local: &FriFoldPreprocessedCols<CB::Var> = (*prepr_local).borrow();
        let prepr_next: &FriFoldPreprocessedCols<CB::Var> = (*prepr_next).borrow();

        // Dummy constraints to normalize to DEGREE.
        let lhs = (0..DEGREE)
            .map(|_| prepr_local.is_real.into())
            .product::<CB::Expr>();
        let rhs = (0..DEGREE)
            .map(|_| prepr_local.is_real.into())
            .product::<CB::Expr>();
        builder.assert_eq(lhs, rhs);

        self.eval_fri_fold::<CB>(builder, local, next, prepr_local, prepr_next);
    }
}

impl<const DEGREE: usize, F: PrimeField32> FriFoldChip<DEGREE, F> {
    pub fn eval_fri_fold<CB: ChipBuilder<F>>(
        &self,
        builder: &mut CB,
        local: &FriFoldMainCols<CB::Var>,
        next: &FriFoldMainCols<CB::Var>,
        local_prepr: &FriFoldPreprocessedCols<CB::Var>,
        next_prepr: &FriFoldPreprocessedCols<CB::Var>,
    ) {
        // Constrain mem read for x.  Read at the first fri fold row.
        builder.looking_single(local_prepr.x_mem.addr, local.x, local_prepr.x_mem.mult);

        // Ensure that the x value is the same for all rows within a fri fold invocation.
        builder
            .when_transition()
            .when(next_prepr.is_real)
            .when_not(next_prepr.is_first)
            .assert_eq(local.x, next.x);

        // Constrain mem read for z.  Read at the first fri fold row.
        builder.looking_block(local_prepr.z_mem.addr, local.z, local_prepr.z_mem.mult);

        // Ensure that the z value is the same for all rows within a fri fold invocation.
        builder
            .when_transition()
            .when(next_prepr.is_real)
            .when_not(next_prepr.is_first)
            .assert_ext_eq(
                local.z.as_extension::<F, CB>(),
                next.z.as_extension::<F, CB>(),
            );

        // Constrain mem read for alpha.  Read at the first fri fold row.
        builder.looking_block(
            local_prepr.alpha_mem.addr,
            local.alpha,
            local_prepr.alpha_mem.mult,
        );

        // Ensure that the alpha value is the same for all rows within a fri fold invocation.
        builder
            .when_transition()
            .when(next_prepr.is_real)
            .when_not(next_prepr.is_first)
            .assert_ext_eq(
                local.alpha.as_extension::<F, CB>(),
                next.alpha.as_extension::<F, CB>(),
            );

        // Constrain read for alpha_pow_input.
        builder.looking_block(
            local_prepr.alpha_pow_input_mem.addr,
            local.alpha_pow_input,
            local_prepr.alpha_pow_input_mem.mult,
        );

        // Constrain read for ro_input.
        builder.looking_block(
            local_prepr.ro_input_mem.addr,
            local.ro_input,
            local_prepr.ro_input_mem.mult,
        );

        // Constrain read for p_at_z.
        builder.looking_block(
            local_prepr.p_at_z_mem.addr,
            local.p_at_z,
            local_prepr.p_at_z_mem.mult,
        );

        // Constrain read for p_at_x.
        builder.looking_block(
            local_prepr.p_at_x_mem.addr,
            local.p_at_x,
            local_prepr.p_at_x_mem.mult,
        );

        // Constrain write for alpha_pow_output.
        builder.looking_block(
            local_prepr.alpha_pow_output_mem.addr,
            local.alpha_pow_output,
            local_prepr.alpha_pow_output_mem.mult,
        );

        // Constrain write for ro_output.
        builder.looking_block(
            local_prepr.ro_output_mem.addr,
            local.ro_output,
            local_prepr.ro_output_mem.mult,
        );

        // 1. Constrain new_value = old_value * alpha.
        let alpha = local.alpha.as_extension::<F, CB>();
        let old_alpha_pow = local.alpha_pow_input.as_extension::<F, CB>();
        let new_alpha_pow = local.alpha_pow_output.as_extension::<F, CB>();
        builder.assert_ext_eq(old_alpha_pow.clone() * alpha, new_alpha_pow.clone());

        // 2. Constrain new_value = old_alpha_pow * quotient + old_ro,
        // where quotient = (p_at_x - p_at_z) / (x - z)
        // <=> (new_ro - old_ro) * (z - x) = old_alpha_pow * (p_at_x - p_at_z)
        let p_at_z = local.p_at_z.as_extension::<F, CB>();
        let p_at_x = local.p_at_x.as_extension::<F, CB>();
        let z = local.z.as_extension::<F, CB>();
        let x = local.x.into();
        let old_ro = local.ro_input.as_extension::<F, CB>();
        let new_ro = local.ro_output.as_extension::<F, CB>();
        builder.assert_ext_eq(
            (new_ro.clone() - old_ro) * (BinomialExtension::from_base(x) - z),
            (p_at_x - p_at_z) * old_alpha_pow,
        );
    }

    pub const fn do_memory_access<T: Copy>(local: &FriFoldPreprocessedCols<T>) -> T {
        local.is_real
    }
}
