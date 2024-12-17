use super::columns::{PublicValuesCols, PublicValuesPreprocessedCols, NUM_PUBLIC_VALUES_COLS};
use crate::{
    chips::chips::public_values_v2::PublicValuesChip,
    machine::builder::{ChipBuilder, RecursionBuilder},
    primitives::consts::RECURSION_NUM_PVS_V2,
    recursion_v2::air::RecursionPublicValues,
};
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::Field;
use p3_matrix::Matrix;
use std::borrow::Borrow;

impl<F: Field> BaseAir<F> for PublicValuesChip<F> {
    fn width(&self) -> usize {
        NUM_PUBLIC_VALUES_COLS
    }
}

impl<F: Field, CB: ChipBuilder<F>> Air<CB> for PublicValuesChip<F> {
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &PublicValuesCols<CB::Var> = (*local).borrow();
        let preprocessed = builder.preprocessed();
        let local_preprocessed = preprocessed.row_slice(0);
        let local_preprocessed: &PublicValuesPreprocessedCols<CB::Var> =
            (*local_preprocessed).borrow();
        let pv = builder.public_values();
        let pv_elements: [CB::Expr; RECURSION_NUM_PVS_V2] = core::array::from_fn(|i| pv[i].into());
        let public_values: &RecursionPublicValues<CB::Expr> = pv_elements.as_slice().borrow();

        // Constrain mem read for the public value element.
        builder.looking_single(
            local_preprocessed.pv_mem.addr,
            local.pv_element,
            local_preprocessed.pv_mem.mult,
        );

        for (i, pv_elm) in public_values.digest.iter().enumerate() {
            // Ensure that the public value element is the same for all rows within a fri fold
            // invocation.
            builder
                .when(local_preprocessed.pv_idx[i])
                .assert_eq(pv_elm.clone(), local.pv_element);
        }
    }
}
