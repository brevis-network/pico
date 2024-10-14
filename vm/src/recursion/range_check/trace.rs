use std::borrow::BorrowMut;

use crate::machine::chip::ChipBehavior;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;

use super::{
    columns::{RangeCheckMultCols, NUM_RANGE_CHECK_MULT_COLS, NUM_RANGE_CHECK_PREPROCESSED_COLS},
    RangeCheckChip,
};
use crate::{compiler::recursion::program::RecursionProgram, recursion::runtime::RecursionRecord};

pub const NUM_ROWS: usize = 1 << 16;

impl<F: PrimeField32> ChipBehavior<F> for RangeCheckChip<F> {
    type Record = RecursionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "RangeCheck".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_RANGE_CHECK_PREPROCESSED_COLS
    }

    fn generate_preprocessed(&self, _program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let (trace, _) = Self::trace_and_map();

        Some(trace)
    }

    fn generate_main(
        &self,
        input: &RecursionRecord<F>,
        _: &mut RecursionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let (_, event_map) = Self::trace_and_map();

        let mut trace = RowMajorMatrix::new(
            vec![F::zero(); NUM_RANGE_CHECK_MULT_COLS * NUM_ROWS],
            NUM_RANGE_CHECK_MULT_COLS,
        );

        for (lookup, mult) in input.range_check_events.iter() {
            let (row, index) = event_map[lookup];
            let cols: &mut RangeCheckMultCols<F> = trace.row_mut(row).borrow_mut();

            // Update the trace multiplicity
            cols.multiplicities[index] += F::from_canonical_usize(*mult);
        }

        trace
    }

    fn is_active(&self, _: &Self::Record) -> bool {
        true
    }
}
