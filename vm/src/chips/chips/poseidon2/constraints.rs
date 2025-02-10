use crate::{
    chips::{
        chips::poseidon2::Poseidon2Chip,
        gadgets::poseidon2::{
            columns::{Poseidon2Cols, Poseidon2PreprocessedCols, NUM_POSEIDON2_COLS},
            constraints::eval_poseidon2,
        },
    },
    configs::config::Poseidon2Config,
    machine::builder::{ChipBuilder, RecursionBuilder},
    primitives::consts::PERMUTATION_WIDTH,
};
use p3_air::{Air, BaseAir};
use p3_field::Field;
use p3_matrix::Matrix;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use std::borrow::Borrow;

impl<F, LinearLayers, Config> BaseAir<F> for Poseidon2Chip<F, LinearLayers, Config>
where
    F: Sync,
    Config: Poseidon2Config,
{
    fn width(&self) -> usize {
        NUM_POSEIDON2_COLS::<Config>
    }
}

impl<F, LinearLayers, CB, Config> Air<CB> for Poseidon2Chip<F, LinearLayers, Config>
where
    F: Field,
    LinearLayers: GenericPoseidon2LinearLayers<CB::Expr, PERMUTATION_WIDTH>,
    CB: ChipBuilder<F>,
    Config: Poseidon2Config,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &Poseidon2Cols<CB::Var, Config> = (*local).borrow();
        let prep = builder.preprocessed();
        let prep_local = prep.row_slice(0);
        let prep_local: &Poseidon2PreprocessedCols<CB::Var> = (*prep_local).borrow();

        for (local, prep_local) in local.values.iter().zip(prep_local.values.iter()) {
            // memory constraints
            (0..PERMUTATION_WIDTH).for_each(|i| {
                builder.looking_single(prep_local.input[i], local.inputs[i], prep_local.is_real_neg)
            });

            (0..PERMUTATION_WIDTH).for_each(|i| {
                builder.looking_single(
                    prep_local.output[i].addr,
                    local.ending_full_rounds[Self::HALF_FULL_ROUNDS - 1].post[i],
                    prep_local.output[i].mult,
                )
            });

            eval_poseidon2::<F, CB, LinearLayers, Config>(builder, local, &self.constants);
        }
    }
}
