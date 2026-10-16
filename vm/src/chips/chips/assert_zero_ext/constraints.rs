use crate::{
    chips::chips::assert_zero_ext::{
        columns::{AssertZeroExtCols, AssertZeroExtPreprocessedCols},
        AssertZeroExtChip,
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

impl<F: Field + BinomiallyExtendable<EXTENSION_DEGREE>, CB> Air<CB> for AssertZeroExtChip<F>
where
    CB: ChipBuilder<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &AssertZeroExtCols<CB::Var> = (*local).borrow();

        let prepr = builder.preprocessed().clone();
        let prepr_local = prepr.current_slice();
        let prepr_local: &AssertZeroExtPreprocessedCols<CB::Var> = (*prepr_local).borrow();

        let is_real = prepr_local.is_real;

        // Memory read: load the EF value at addr.
        builder.looked_block(prepr_local.addr, local.val, is_real);

        // Assert val == 0 (as extension-field element).
        let val = local.val.as_extension::<F, CB>();
        let zero = BinomialExtension::<F, CB::Expr, EXTENSION_DEGREE>::from_base(CB::Expr::ZERO);
        builder.when(is_real).assert_ext_eq(val, zero);
    }
}
