use super::Poseidon2ChipP3;
use crate::{
    chips::gadgets::poseidon2::{
        columns::{Poseidon2Cols, NUM_POSEIDON2_COLS},
        constraints::eval_poseidon2,
    },
    machine::{
        builder::ChipBuilder,
        lookup::{LookupScope, LookupType, SymbolicLookup},
    },
    primitives::consts::PERMUTATION_WIDTH,
};
use p3_air::{Air, BaseAir};
use p3_field::Field;
use p3_matrix::Matrix;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use std::borrow::Borrow;

impl<F: Field, LinearLayers> BaseAir<F> for Poseidon2ChipP3<F, LinearLayers> {
    fn width(&self) -> usize {
        NUM_POSEIDON2_COLS
    }
}

impl<
        F: Field,
        LinearLayers: GenericPoseidon2LinearLayers<CB::Expr, PERMUTATION_WIDTH>,
        CB: ChipBuilder<F>,
    > Air<CB> for Poseidon2ChipP3<F, LinearLayers>
where
    Self: BaseAir<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &Poseidon2Cols<CB::Var> = (*local).borrow();

        for local in local.values.iter() {
            let outputs = eval_poseidon2::<F, CB, LinearLayers>(builder, local, &self.constants);

            let lookup_values = local
                .inputs
                .iter()
                .cloned()
                .map(Into::into)
                .chain(outputs)
                .collect();
            builder.looked(SymbolicLookup::new(
                lookup_values,
                local.is_real.into(),
                LookupType::Poseidon2,
                LookupScope::Regional,
            ));
        }
    }
}
