use crate::{
    chips::chips::lagrange_eval_d2::{
        columns::{
            LagrangeEvalD2Cols, LagrangeEvalD2PreprocessedCols, NUM_LAGRANGE_EVAL_D2_COLS,
            NUM_LAGRANGE_EVAL_D2_PREPROCESSED_COLS,
        },
        LagrangeEvalD2Chip,
    },
    compiler::recursion::{
        instruction::Instruction,
        program::RecursionProgram,
        types::{LagrangeEvalD2Event, LagrangeEvalD2Instr},
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

impl<F> BaseAir<F> for LagrangeEvalD2Chip<F> {
    fn width(&self) -> usize {
        NUM_LAGRANGE_EVAL_D2_COLS
    }
}

impl<F: PrimeField32> ChipBehavior<F> for LagrangeEvalD2Chip<F> {
    type Record = RecursionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "LagrangeEvalD2".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_LAGRANGE_EVAL_D2_PREPROCESSED_COLS
    }

    fn preprocessed_rows(&self, program: &Self::Program) -> Option<PreprocessedRows> {
        Some(PreprocessedRows::Unpadded(
            program.prep_row_counts().lagrange_eval_d2,
        ))
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let mut rows: Vec<[F; NUM_LAGRANGE_EVAL_D2_PREPROCESSED_COLS]> = Vec::new();

        program
            .instructions
            .iter()
            .filter_map(|instr| {
                if let Instruction::LagrangeEvalD2(i) = instr {
                    Some(i)
                } else {
                    None
                }
            })
            .for_each(|instr: &LagrangeEvalD2Instr<F>| {
                let mut row = [F::ZERO; NUM_LAGRANGE_EVAL_D2_PREPROCESSED_COLS];
                let cols: &mut LagrangeEvalD2PreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                cols.is_real = F::ONE;
                cols.claim_addr = instr.claim_addr;
                cols.s1_addr = instr.s1_addr;
                cols.s2_addr = instr.s2_addr;
                cols.r_addr = instr.r_addr;
                cols.next_claim_addr = instr.next_claim_addr;
                cols.mult = instr.mult;
                rows.push(row);
            });

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_LAGRANGE_EVAL_D2_PREPROCESSED_COLS,
        );
        let log_size = program.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_LAGRANGE_EVAL_D2_PREPROCESSED_COLS, F>(
            &mut trace.values,
            log_size,
        );
        Some(trace)
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let rows = input
            .lagrange_eval_d2_events
            .iter()
            .map(|event: &LagrangeEvalD2Event<F>| {
                let mut row = [F::ZERO; NUM_LAGRANGE_EVAL_D2_COLS];
                let cols: &mut LagrangeEvalD2Cols<F> = row.as_mut_slice().borrow_mut();
                cols.claim = event.claim;
                cols.s1 = event.s1;
                cols.s2 = event.s2;
                cols.r = event.r;
                cols.next_claim = event.next_claim;
                row
            })
            .collect::<Vec<_>>();

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_LAGRANGE_EVAL_D2_COLS,
        );
        let log_rows = input.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_LAGRANGE_EVAL_D2_COLS, F>(&mut trace.values, log_rows);
        trace
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }
}
