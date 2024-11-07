use super::{
    columns::{MemoryCols, MemoryPreprocessedCols, NUM_MEM_INIT_COLS},
    MemoryVarChip,
};
use crate::machine::builder::{ChipBuilder, RecursionBuilder};
use p3_air::{Air, BaseAir};
use p3_field::PrimeField32;
use p3_matrix::Matrix;
use std::{borrow::Borrow, iter::zip};

impl<F: PrimeField32> BaseAir<F> for MemoryVarChip<F> {
    fn width(&self) -> usize {
        NUM_MEM_INIT_COLS
    }
}

impl<F: PrimeField32, CB: ChipBuilder<F>> Air<CB> for MemoryVarChip<F>
where
    CB::Var: Sized,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local = main.row_slice(0);
        let local: &MemoryCols<CB::Var> = (*local).borrow();
        let prep = builder.preprocessed();
        let prep_local = prep.row_slice(0);
        let prep_local: &MemoryPreprocessedCols<CB::Var> = (*prep_local).borrow();

        for (value, access) in zip(local.values, prep_local.accesses) {
            builder.looking_block(access.addr, value, access.mult);
        }
    }
}
