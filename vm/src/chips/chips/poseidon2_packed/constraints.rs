use crate::{
    chips::{
        chips::poseidon2_packed::{columns::Poseidon2PackedPreprocessedCols, Poseidon2PackedChip},
        gadgets::poseidon2::{
            columns::{Poseidon2ValueCols, NUM_POSEIDON2_VALUE_COLS},
            constraints::eval_poseidon2,
        },
    },
    configs::config::Poseidon2Config,
    machine::builder::{ChipBuilder, RecursionBuilder},
    primitives::consts::{PACK_LANES, PERMUTATION_WIDTH, PERM_BLOCKS},
};
use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::Field;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use std::borrow::Borrow;

impl<F, LinearLayers, Config> BaseAir<F> for Poseidon2PackedChip<F, LinearLayers, Config>
where
    F: Sync,
    Config: Poseidon2Config,
{
    fn width(&self) -> usize {
        NUM_POSEIDON2_VALUE_COLS::<Config>
    }
}

impl<F, LinearLayers, CB, Config> Air<CB> for Poseidon2PackedChip<F, LinearLayers, Config>
where
    F: Field,
    LinearLayers: GenericPoseidon2LinearLayers<PERMUTATION_WIDTH>,
    CB: ChipBuilder<F>,
    Config: Poseidon2Config,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.current_slice();
        let local: &Poseidon2ValueCols<CB::Var, Config> = (*local).borrow();
        let prep = builder.preprocessed().clone();
        let prep_local = prep.current_slice();
        let prep_local: &Poseidon2PackedPreprocessedCols<CB::Var> = (*prep_local).borrow();

        let post = &local.ending_full_rounds[Self::HALF_FULL_ROUNDS - 1].post;
        for j in 0..PERM_BLOCKS {
            // Packed memory read of input Block j (lanes PACK_LANES·j.. of the state).
            builder.looked_packed(
                prep_local.input[j],
                std::array::from_fn(|k| local.inputs[PACK_LANES * j + k]),
                prep_local.is_real,
            );
            // Packed memory write of output Block j.
            builder.looking_packed(
                prep_local.output[j].addr,
                std::array::from_fn(|k| post[PACK_LANES * j + k]),
                prep_local.output[j].mult,
            );
        }

        eval_poseidon2::<F, CB, LinearLayers, Config>(builder, local, &self.constants);
    }
}
