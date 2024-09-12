use super::{
    columns::{ProgramMultiplicityCols, ProgramPreprocessedCols, NUM_PROGRAM_MULT_COLS},
    ProgramChip,
};
use core::borrow::Borrow;
use p3_air::{Air, BaseAir};
use p3_field::Field;
use p3_matrix::Matrix;
use pico_machine::chip::ChipBuilder;

impl<F: Field> BaseAir<F> for ProgramChip<F> {
    fn width(&self) -> usize {
        NUM_PROGRAM_MULT_COLS
    }
}

impl<F: Field, CB: ChipBuilder<F>> Air<CB> for ProgramChip<F>
where
    CB::Var: Sized,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();

        /* TODO: May wait for lookup to avoid conflict.
        let preprocessed = builder.preprocessed();

        let prep_local = preprocessed.row_slice(0);
        let prep_local: &ProgramPreprocessedCols<CB::Var> = (*prep_local).borrow();
        let mult_local = main.row_slice(0);
        let mult_local: &ProgramMultiplicityCols<CB::Var> = (*mult_local).borrow();

                // Contrain the interaction with CPU table
                builder.receive_program(
                    prep_local.pc,
                    prep_local.instruction,
                    prep_local.selectors,
                    mult_local.shard,
                    mult_local.multiplicity,
                );
        */
    }
}
