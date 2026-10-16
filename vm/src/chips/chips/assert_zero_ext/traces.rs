use crate::{
    chips::chips::assert_zero_ext::{
        columns::{
            AssertZeroExtCols, AssertZeroExtPreprocessedCols, NUM_ASSERT_ZERO_EXT_COLS,
            NUM_ASSERT_ZERO_EXT_PREPROCESSED_COLS,
        },
        AssertZeroExtChip,
    },
    compiler::recursion::{
        instruction::Instruction,
        program::RecursionProgram,
        types::{AssertZeroExtEvent, AssertZeroExtInstr},
    },
    emulator::recursion::emulator::RecursionRecord,
    machine::{
        chip::{ChipBehavior, PreprocessedRows},
        utils::pad_to_power_of_two,
    },
};
use p3_air::BaseAir;
use p3_field::{Field, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::BorrowMut;

impl<F> BaseAir<F> for AssertZeroExtChip<F> {
    fn width(&self) -> usize {
        NUM_ASSERT_ZERO_EXT_COLS
    }
}

impl<F: PrimeField32 + Field> ChipBehavior<F> for AssertZeroExtChip<F> {
    type Record = RecursionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "AssertZeroExt".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_ASSERT_ZERO_EXT_PREPROCESSED_COLS
    }

    fn preprocessed_rows(&self, program: &Self::Program) -> Option<PreprocessedRows> {
        Some(PreprocessedRows::Unpadded(
            program.prep_row_counts().assert_zero_ext,
        ))
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let mut rows: Vec<[F; NUM_ASSERT_ZERO_EXT_PREPROCESSED_COLS]> = Vec::new();

        program
            .instructions
            .iter()
            .filter_map(|instr| {
                if let Instruction::AssertZeroExt(i) = instr {
                    Some(i)
                } else {
                    None
                }
            })
            .for_each(|instr: &AssertZeroExtInstr<F>| {
                let mut row = [F::ZERO; NUM_ASSERT_ZERO_EXT_PREPROCESSED_COLS];
                let cols: &mut AssertZeroExtPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                cols.is_real = F::ONE;
                cols.addr = instr.addr;
                rows.push(row);
            });

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_ASSERT_ZERO_EXT_PREPROCESSED_COLS,
        );
        let log_size = program.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_ASSERT_ZERO_EXT_PREPROCESSED_COLS, F>(
            &mut trace.values,
            log_size,
        );
        Some(trace)
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let rows = input
            .assert_zero_ext_events
            .iter()
            .map(|event: &AssertZeroExtEvent<F>| {
                let mut row = [F::ZERO; NUM_ASSERT_ZERO_EXT_COLS];
                let cols: &mut AssertZeroExtCols<F> = row.as_mut_slice().borrow_mut();
                cols.val = event.val;
                row
            })
            .collect::<Vec<_>>();

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_ASSERT_ZERO_EXT_COLS,
        );
        let log_rows = input.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_ASSERT_ZERO_EXT_COLS, F>(&mut trace.values, log_rows);
        trace
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }
}
