use crate::{
    chips::chips::mle_open::{
        columns::{
            MleOpenCols, MleOpenPreprocessedCols, NUM_MLE_OPEN_COLS, NUM_MLE_OPEN_PREPROCESSED_COLS,
        },
        MleOpenChip,
    },
    compiler::recursion::{
        instruction::Instruction,
        program::RecursionProgram,
        types::{MleOpenEvent, MleOpenInstr},
    },
    emulator::recursion::emulator::RecursionRecord,
    machine::{
        chip::{ChipBehavior, PreprocessedRows},
        utils::pad_to_power_of_two,
    },
};
use p3_air::BaseAir;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::BorrowMut;

impl<F> BaseAir<F> for MleOpenChip<F> {
    fn width(&self) -> usize {
        NUM_MLE_OPEN_COLS
    }
}

impl<F: PrimeField32> ChipBehavior<F> for MleOpenChip<F> {
    type Record = RecursionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "MleOpen".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_MLE_OPEN_PREPROCESSED_COLS
    }

    fn preprocessed_rows(&self, program: &Self::Program) -> Option<PreprocessedRows> {
        Some(PreprocessedRows::Unpadded(
            program.prep_row_counts().mle_open,
        ))
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let mut rows: Vec<[F; NUM_MLE_OPEN_PREPROCESSED_COLS]> = Vec::new();

        program
            .instructions
            .iter()
            .filter_map(|instr| {
                if let Instruction::MleOpen(i) = instr {
                    Some(i)
                } else {
                    None
                }
            })
            .for_each(|instr: &MleOpenInstr<F>| {
                let mut row = [F::ZERO; NUM_MLE_OPEN_PREPROCESSED_COLS];
                let cols: &mut MleOpenPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                cols.is_real = F::ONE;
                cols.col_ref = F::from_u32(instr.col_ref);
                cols.opening_value_addr = instr.opening_value_addr;
                rows.push(row);
            });

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_MLE_OPEN_PREPROCESSED_COLS,
        );
        let log_size = program.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_MLE_OPEN_PREPROCESSED_COLS, F>(&mut trace.values, log_size);
        Some(trace)
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let rows = input
            .mle_open_events
            .iter()
            .map(|event: &MleOpenEvent<F>| {
                let mut row = [F::ZERO; NUM_MLE_OPEN_COLS];
                let cols: &mut MleOpenCols<F> = row.as_mut_slice().borrow_mut();
                cols.opening_value = event.opening_value;
                row
            })
            .collect::<Vec<_>>();

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_MLE_OPEN_COLS,
        );
        let log_rows = input.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_MLE_OPEN_COLS, F>(&mut trace.values, log_rows);
        trace
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }
}
