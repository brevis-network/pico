use super::{
    columns::{
        RangeCheckMultCols, RangeCheckPreprocessedCols, NUM_RANGE_CHECK_MULT_COLS,
        NUM_RANGE_CHECK_PREPROCESSED_COLS,
    },
    RangeCheckChip, RangeCheckEvent, RangeCheckOpcode,
};
use crate::{
    compiler::recursion::program::RecursionProgram, machine::chip::ChipBehavior,
    recursion::runtime::RecursionRecord,
};
use p3_field::{Field, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use std::{borrow::BorrowMut, collections::BTreeMap};

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

impl<F: Field> RangeCheckChip<F> {
    /// Creates the preprocessed range check trace and event map.
    ///
    /// This function returns a pair `(trace, map)`, where:
    /// - `trace` is a matrix containing all possible range check values.
    /// - `map` is a map from a range check lookup to the value's corresponding row it appears in
    ///   the table and
    /// the index of the result in the array of multiplicities.
    pub fn trace_and_map() -> (RowMajorMatrix<F>, BTreeMap<RangeCheckEvent, (usize, usize)>) {
        // A map from a byte lookup to its corresponding row in the table and index in the array of
        // multiplicities.
        let mut event_map = BTreeMap::new();

        // The trace containing all values, with all multiplicities set to zero.
        let mut initial_trace = RowMajorMatrix::new(
            vec![F::zero(); NUM_ROWS * NUM_RANGE_CHECK_PREPROCESSED_COLS],
            NUM_RANGE_CHECK_PREPROCESSED_COLS,
        );

        // Record all the necessary operations for each range check lookup.
        let opcodes = RangeCheckOpcode::all();

        // Iterate over all U16 values.
        for (row_index, val) in (0..=u16::MAX).enumerate() {
            let col: &mut RangeCheckPreprocessedCols<F> =
                initial_trace.row_mut(row_index).borrow_mut();

            // Set the u16 value.
            col.value_u16 = F::from_canonical_u16(val);

            // Iterate over all range check operations to update col values and the table map.
            for (i, opcode) in opcodes.iter().enumerate() {
                if *opcode == RangeCheckOpcode::U12 {
                    col.u12_out_range = F::from_bool(val > 0xFFF);
                }

                let event = RangeCheckEvent::new(*opcode, val);
                event_map.insert(event, (row_index, i));
            }
        }

        (initial_trace, event_map)
    }
}
