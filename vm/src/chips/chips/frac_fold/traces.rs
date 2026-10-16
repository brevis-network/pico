use crate::{
    chips::chips::frac_fold::{
        columns::{
            FracFoldCols, FracFoldPreprocessedCols, NUM_FRAC_FOLD_COLS,
            NUM_FRAC_FOLD_PREPROCESSED_COLS,
        },
        FracFoldChip,
    },
    compiler::recursion::{
        instruction::Instruction,
        program::RecursionProgram,
        types::{FracFoldEvent, FracFoldInstr},
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

impl<F> BaseAir<F> for FracFoldChip<F> {
    fn width(&self) -> usize {
        NUM_FRAC_FOLD_COLS
    }
}

impl<F: PrimeField32> ChipBehavior<F> for FracFoldChip<F> {
    type Record = RecursionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "FracFold".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_FRAC_FOLD_PREPROCESSED_COLS
    }

    fn preprocessed_rows(&self, program: &Self::Program) -> Option<PreprocessedRows> {
        Some(PreprocessedRows::Unpadded(
            program.prep_row_counts().frac_fold,
        ))
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let mut rows: Vec<[F; NUM_FRAC_FOLD_PREPROCESSED_COLS]> = Vec::new();

        program
            .instructions
            .iter()
            .filter_map(|instr| {
                if let Instruction::FracFold(i) = instr {
                    Some(i)
                } else {
                    None
                }
            })
            .for_each(|instr: &FracFoldInstr<F>| {
                let mut row = [F::ZERO; NUM_FRAC_FOLD_PREPROCESSED_COLS];
                let cols: &mut FracFoldPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                cols.is_real = F::ONE;
                cols.in_p1_addr = instr.in_p1_addr;
                cols.in_q1_addr = instr.in_q1_addr;
                cols.in_p2_addr = instr.in_p2_addr;
                cols.in_q2_addr = instr.in_q2_addr;
                cols.out_p_addr = instr.out_p_addr;
                cols.out_q_addr = instr.out_q_addr;
                cols.mult = instr.mult;
                rows.push(row);
            });

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_FRAC_FOLD_PREPROCESSED_COLS,
        );
        let log_size = program.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_FRAC_FOLD_PREPROCESSED_COLS, F>(&mut trace.values, log_size);
        Some(trace)
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let rows = input
            .frac_fold_events
            .iter()
            .map(|event: &FracFoldEvent<F>| {
                let mut row = [F::ZERO; NUM_FRAC_FOLD_COLS];
                let cols: &mut FracFoldCols<F> = row.as_mut_slice().borrow_mut();
                cols.p1 = event.p1;
                cols.q1 = event.q1;
                cols.p2 = event.p2;
                cols.q2 = event.q2;
                cols.out_p = event.out_p;
                cols.out_q = event.out_q;
                row
            })
            .collect::<Vec<_>>();

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_FRAC_FOLD_COLS,
        );
        let log_rows = input.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_FRAC_FOLD_COLS, F>(&mut trace.values, log_rows);
        trace
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }
}
