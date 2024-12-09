use super::{
    columns::{
        RangeCheckMultCols, RangeCheckPreprocessedCols, NUM_RANGECHECK_MULT_COLS,
        NUM_RANGECHECK_PREPROCESSED_COLS,
    },
    event::RangeRecordBehavior,
    RangeCheckChip,
};
use crate::{
    compiler::program::ProgramBehavior, emulator::record::RecordBehavior,
    machine::chip::ChipBehavior,
};
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::BorrowMut;

pub const NUM_ROWS: usize = 1 << 16;

impl<R, P, F> ChipBehavior<F> for RangeCheckChip<R, P, F>
where
    R: RangeRecordBehavior + RecordBehavior,
    P: ProgramBehavior<F>,
    F: Field,
{
    type Record = R;
    type Program = P;

    fn name(&self) -> String {
        "RangeCheck".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_RANGECHECK_PREPROCESSED_COLS
    }

    fn generate_preprocessed(&self, _program: &P) -> Option<RowMajorMatrix<F>> {
        Some(Self::preprocess())
    }

    fn generate_main(&self, input: &R, _: &mut R) -> RowMajorMatrix<F> {
        let mut trace = RowMajorMatrix::new(
            vec![F::ZERO; NUM_RANGECHECK_MULT_COLS * NUM_ROWS],
            NUM_RANGECHECK_MULT_COLS,
        );

        let mut chunk = input.chunk_index() as u32;
        if input.name() == "RecursionRecord" {
            chunk = 0;
        }
        input
            .range_lookup_events(Some(chunk))
            .for_each(|(event, multi)| {
                let row = event.value as usize;
                let index = event.opcode as usize;

                let cols: &mut RangeCheckMultCols<F> = trace.row_mut(row).borrow_mut();
                cols.multiplicities[index] += F::from_canonical_usize(multi);
                cols.chunk = F::from_canonical_u32(chunk);
            });

        trace
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }
}

impl<R, P, F: Field> RangeCheckChip<R, P, F> {
    /// Creates the preprocessed range check trace.
    ///
    /// This function returns a `trace` which is a matrix containing all possible range check results.
    pub fn preprocess() -> RowMajorMatrix<F> {
        // The trace containing all values, with all multiplicities set to zero.
        let mut initial_trace = RowMajorMatrix::new(
            vec![F::ZERO; NUM_ROWS * NUM_RANGECHECK_PREPROCESSED_COLS],
            NUM_RANGECHECK_PREPROCESSED_COLS,
        );

        // Iterate over all options for pairs of bytes `a` and `b`.
        for row_index in 0..(1u32 << 16) {
            let row: &mut RangeCheckPreprocessedCols<F> =
                initial_trace.row_mut(row_index as usize).borrow_mut();

            let nbits = row_index.checked_ilog2().unwrap_or_default();
            let zero = F::ZERO;
            let one = F::ONE;

            // Set the column values
            row.value = F::from_canonical_u32(row_index);
            row.is_u8 = if nbits <= 8 { one } else { zero };
            row.is_u12 = if nbits <= 12 { one } else { zero };
            // row.is_u16 = if nbits <= 16 { one } else { zero };
        }

        initial_trace
    }
}
