use super::{
    columns::{MemoryPreprocessedCols, MemoryValueAccess, NUM_MEM_INIT_COLS},
    MemoryConstChip,
};
use crate::machine::builder::{ChipBuilder, RecursionBuilder};
use p3_air::{Air, BaseAir, WindowAccess};
use p3_field::PrimeField32;
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
        let prep = builder.preprocessed().clone();
        let prep_local = prep.current_slice();
        let prep_local: &MemoryPreprocessedCols<CB::Var> = (*prep_local).borrow();

        for MemoryValueAccess { value, access } in prep_local.values_and_accesses {
            builder.looking_block(access.addr, value, access.mult);
        }
    }
}
