use crate::{
    chips::{
        chips::poseidon2_packed::{columns::Poseidon2PackedPreprocessedCols, Poseidon2PackedChip},
        gadgets::poseidon2::{
            columns::{Poseidon2ValueCols, NUM_POSEIDON2_VALUE_COLS},
            constraints::eval_poseidon2,
        },
    },
    compiler::recursion::ir::Block,
    configs::config::Poseidon2Config,
    machine::builder::{ChipBuilder, RecursionBuilder},
    primitives::consts::PERMUTATION_WIDTH,
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
        for j in 0..4 {
            // Packed memory read of input Block j (lanes 4j..4j+4 of the state).
            builder.looked_block(
                prep_local.input[j],
                Block([
                    local.inputs[4 * j],
                    local.inputs[4 * j + 1],
                    local.inputs[4 * j + 2],
                    local.inputs[4 * j + 3],
                ]),
                prep_local.is_real,
            );
            // Packed memory write of output Block j.
            builder.looking_block(
                prep_local.output[j].addr,
                Block([
                    post[4 * j],
                    post[4 * j + 1],
                    post[4 * j + 2],
                    post[4 * j + 3],
                ]),
                prep_local.output[j].mult,
            );
        }

        eval_poseidon2::<F, CB, LinearLayers, Config>(builder, local, &self.constants);
    }
}
