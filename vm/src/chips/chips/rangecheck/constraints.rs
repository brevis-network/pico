use super::{
    columns::{RangeCheckMultCols, RangeCheckPreprocessedCols, NUM_RANGECHECK_MULT_COLS},
    RangeCheckChip,
};
use crate::{
    compiler::riscv::opcode::RangeCheckOpcode,
    machine::builder::{ChipBuilder, ChipLookupBuilder},
};
use core::borrow::Borrow;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::Field;
use p3_matrix::Matrix;

impl<R: Sync, P: Sync, F: Field> BaseAir<F> for RangeCheckChip<R, P, F> {
    fn width(&self) -> usize {
        NUM_RANGECHECK_MULT_COLS
    }
}

impl<R, P, F, CB> Air<CB> for RangeCheckChip<R, P, F>
where
    R: Sync,
    P: Sync,
    F: Field,
    CB: ChipBuilder<F>,
    CB::Var: Sized,
{
    fn eval(&self, builder: &mut CB) {
        let main = builder.main();
        let local_mult = main.row_slice(0);
        let local_mult: &RangeCheckMultCols<CB::Var> = (*local_mult).borrow();

        let prep = builder.preprocessed();
        let prep = prep.row_slice(0);
        let local: &RangeCheckPreprocessedCols<CB::Var> = (*prep).borrow();

        for (i, opcode) in RangeCheckOpcode::all().into_iter().enumerate() {
            let mult = local_mult.multiplicities[i];
            // let chunk = local_mult.chunk;

            // check that no lookups happened out of the range
            match opcode {
                RangeCheckOpcode::U8 => {
                    builder.when_not(local.is_u8).assert_zero(mult);
                }
                RangeCheckOpcode::U12 => {
                    builder.when_not(local.is_u12).assert_zero(mult);
                }
                RangeCheckOpcode::U16 => {
                    // the table is implicitly in the u16 range
                    // builder.when_not(local.is_u16).assert_zero(mult);
                }
            }

            // record the receive
            builder.looked_rangecheck(opcode, local.value, mult);
            // builder.looked_rangecheck(opcode, local.value, chunk, mult);
        }
    }
}
