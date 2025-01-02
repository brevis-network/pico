use crate::{
    chips::chips::select::{
        columns::{SelectCols, SelectPreprocessedCols, SELECT_COLS, SELECT_PREPROCESSED_COLS},
        SelectChip,
    },
    compiler::recursion_v2::{instruction::Instruction, program::RecursionProgram},
    machine::chip::ChipBehavior,
    recursion_v2::{runtime::RecursionRecord, stark::utils::next_power_of_two, types::SelectInstr},
};
use p3_air::BaseAir;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
use std::borrow::BorrowMut;

impl<F> BaseAir<F> for SelectChip<F> {
    fn width(&self) -> usize {
        SELECT_COLS
    }
}

impl<F: PrimeField32> ChipBehavior<F> for SelectChip<F> {
    type Record = RecursionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "Select".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        SELECT_PREPROCESSED_COLS
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let instrs = program
            .instructions
            .iter()
            .filter_map(|instruction| match instruction {
                Instruction::Select(x) => Some(x),
                _ => None,
            })
            .collect::<Vec<_>>();

        let nb_rows = instrs.len();
        let fixed_log2_rows = program.fixed_log2_rows(self);
        let padded_nb_rows = match fixed_log2_rows {
            Some(log2_rows) => 1 << log2_rows,
            None => next_power_of_two(nb_rows, None),
        };
        let mut values = vec![F::ZERO; padded_nb_rows * SELECT_PREPROCESSED_COLS];

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let populate_len = instrs.len() * SELECT_PREPROCESSED_COLS;
        values[..populate_len]
            .par_chunks_mut(SELECT_PREPROCESSED_COLS)
            .zip_eq(instrs)
            .for_each(|(row, instr)| {
                let SelectInstr {
                    addrs,
                    mult1,
                    mult2,
                } = instr;
                let access: &mut SelectPreprocessedCols<_> = row.borrow_mut();
                *access = SelectPreprocessedCols {
                    is_real: F::ONE,
                    addrs: addrs.to_owned(),
                    mult1: mult1.to_owned(),
                    mult2: mult2.to_owned(),
                };
            });

        // Convert the trace to a row major matrix.
        Some(RowMajorMatrix::new(values, SELECT_PREPROCESSED_COLS))
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let events = &input.select_events;
        let nb_rows = events.len();
        let fixed_log2_rows = input.fixed_log2_rows(self);
        let padded_nb_rows = match fixed_log2_rows {
            Some(log2_rows) => 1 << log2_rows,
            None => next_power_of_two(nb_rows, None),
        };
        let mut values = vec![F::ZERO; padded_nb_rows * SELECT_COLS];

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let populate_len = events.len() * SELECT_COLS;
        values[..populate_len]
            .par_chunks_mut(SELECT_COLS)
            .zip_eq(events)
            .for_each(|(row, &vals)| {
                let cols: &mut SelectCols<_> = row.borrow_mut();
                *cols = SelectCols { vals };
            });

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, SELECT_COLS)
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }
}
