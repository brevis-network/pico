use crate::{
    chips::{
        chips::select::{
            columns::{
                SelectPreprocessedValueCols, SelectValueCols, NUM_SELECT_COLS,
                NUM_SELECT_PREPROCESSED_COLS, NUM_SELECT_PREPROCESSED_VALUE_COLS,
                NUM_SELECT_VALUE_COLS,
            },
            SelectChip,
        },
        utils::next_power_of_two,
    },
    compiler::recursion::{
        instruction::Instruction, program::RecursionProgram, types::SelectInstr,
    },
    emulator::recursion::emulator::RecursionRecord,
    iter::{
        current_num_threads, IndexedPicoIterator, IntoPicoRefIterator, PicoIterator, PicoSliceMut,
    },
    machine::chip::ChipBehavior,
    primitives::consts::SELECT_DATAPAR,
};
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::BorrowMut;

impl<F: PrimeField32> ChipBehavior<F> for SelectChip<F> {
    type Record = RecursionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "Select".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_SELECT_PREPROCESSED_COLS
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let instructions: Vec<_> = program
            .instructions
            .pico_iter()
            .filter_map(|instruction| match instruction {
                Instruction::Select(x) => Some(x),
                _ => None,
            })
            .collect();

        let nrows = instructions.len().div_ceil(SELECT_DATAPAR);
        let fixed_log2_nrows = program.fixed_log2_rows(&self.name());
        let padded_nrows = match fixed_log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };

        let mut values: Vec<F> = vec![F::ZERO; padded_nrows * NUM_SELECT_PREPROCESSED_COLS];

        let chunk_size = (instructions.len() / current_num_threads()).max(1);
        let populate_len = instructions.len() * NUM_SELECT_PREPROCESSED_VALUE_COLS;

        values[..populate_len]
            .pico_chunks_mut(NUM_SELECT_PREPROCESSED_VALUE_COLS)
            .zip_eq(instructions)
            .with_min_len(chunk_size)
            .for_each(|(row, instr)| {
                let SelectInstr {
                    addrs,
                    mult1,
                    mult2,
                } = instr;
                let value_col: &mut SelectPreprocessedValueCols<_> = row.borrow_mut();
                *value_col = SelectPreprocessedValueCols {
                    is_real: F::ONE,
                    addrs: addrs.to_owned(),
                    mult1: mult1.to_owned(),
                    mult2: mult2.to_owned(),
                };
            });

        Some(RowMajorMatrix::new(values, NUM_SELECT_PREPROCESSED_COLS))
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let events = &input.select_events;
        let nrows = events.len().div_ceil(SELECT_DATAPAR);
        let fixed_log2_nrows = input.fixed_log2_rows(&self.name());
        let padded_nrows = match fixed_log2_nrows {
            Some(log2_nrows) => 1 << log2_nrows,
            None => next_power_of_two(nrows, None),
        };

        let mut values: Vec<F> = vec![F::ZERO; padded_nrows * NUM_SELECT_COLS];

        let chunk_size = (events.len() / current_num_threads()).max(1);
        let populate_len = events.len() * NUM_SELECT_VALUE_COLS;

        values[..populate_len]
            .pico_chunks_mut(NUM_SELECT_VALUE_COLS)
            .zip_eq(events)
            .with_min_len(chunk_size)
            .for_each(|(row, &vals)| {
                let cols: &mut SelectValueCols<_> = row.borrow_mut();
                *cols = SelectValueCols { vals };
            });

        RowMajorMatrix::new(values, NUM_SELECT_COLS)
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }
}
