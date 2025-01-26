use crate::{
    chips::{
        chips::poseidon2_p3::Poseidon2ChipP3,
        gadgets::poseidon2::{
            columns::{Poseidon2Cols, Poseidon2PreprocessedCols, NUM_POSEIDON2_COLS},
            constraints::eval_poseidon2,
        },
    },
    machine::builder::{ChipBuilder, RecursionBuilder},
    primitives::consts::PERMUTATION_WIDTH,
};
use p3_air::{Air, BaseAir};
use p3_field::Field;
use p3_matrix::Matrix;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use std::borrow::Borrow;

impl<
        F: Field,
        LinearLayers: Sync,
        const FIELD_HALF_FULL_ROUNDS: usize,
        const FIELD_PARTIAL_ROUNDS: usize,
        const FIELD_SBOX_REGISTERS: usize,
    > BaseAir<F>
    for Poseidon2ChipP3<
        F,
        LinearLayers,
        FIELD_HALF_FULL_ROUNDS,
        FIELD_PARTIAL_ROUNDS,
        FIELD_SBOX_REGISTERS,
    >
{
    fn width(&self) -> usize {
        NUM_POSEIDON2_COLS::<FIELD_HALF_FULL_ROUNDS, FIELD_PARTIAL_ROUNDS, FIELD_SBOX_REGISTERS>
    }
}

impl<
        F: Field,
        LinearLayers: GenericPoseidon2LinearLayers<CB::Expr, PERMUTATION_WIDTH>,
        CB: ChipBuilder<F>,
        const FIELD_HALF_FULL_ROUNDS: usize,
        const FIELD_PARTIAL_ROUNDS: usize,
        const FIELD_SBOX_REGISTERS: usize,
    > Air<CB>
    for Poseidon2ChipP3<
        F,
        LinearLayers,
        FIELD_HALF_FULL_ROUNDS,
        FIELD_PARTIAL_ROUNDS,
        FIELD_SBOX_REGISTERS,
    >
where
    Self: BaseAir<F>,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &Poseidon2Cols<
            CB::Var,
            FIELD_HALF_FULL_ROUNDS,
            FIELD_PARTIAL_ROUNDS,
            FIELD_SBOX_REGISTERS,
        > = (*local).borrow();
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
                    local.ending_full_rounds[FIELD_HALF_FULL_ROUNDS - 1].post[i],
                    prep_local.output[i].mult,
                )
            });

            eval_poseidon2::<
                F,
                CB,
                LinearLayers,
                FIELD_HALF_FULL_ROUNDS,
                FIELD_PARTIAL_ROUNDS,
                FIELD_SBOX_REGISTERS,
            >(builder, local, &self.constants);
        }
    }
}
