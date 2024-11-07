use super::{
    columns::{MemoryPreprocessedCols, NUM_MEM_INIT_COLS},
    MemoryConstChip,
};
use crate::machine::builder::{ChipBuilder, RecursionBuilder};
use p3_air::{Air, BaseAir};
use p3_field::PrimeField32;
use p3_matrix::Matrix;
use std::borrow::Borrow;

impl<F: PrimeField32> BaseAir<F> for MemoryConstChip<F> {
    fn width(&self) -> usize {
        NUM_MEM_INIT_COLS
    }
}

impl<F: PrimeField32, CB: ChipBuilder<F>> Air<CB> for MemoryConstChip<F>
where
    CB::Var: Sized,
{
    fn eval(&self, builder: &mut CB) {
        let prep = builder.preprocessed();
        let prep_local = prep.row_slice(0);
        let prep_local: &MemoryPreprocessedCols<CB::Var> = (*prep_local).borrow();

        for (value, access) in prep_local.values_and_accesses {
            builder.looking_block(access.addr, value, access.mult);
        }
    }
}
