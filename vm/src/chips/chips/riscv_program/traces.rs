use super::{
    columns::{
        ProgramMultiplicityCols, ProgramPreprocessedCols, NUM_PROGRAM_MULT_COLS,
        NUM_PROGRAM_PREPROCESSED_COLS,
    },
    ProgramChip,
};
use crate::{
    compiler::riscv::program::Program,
    emulator::riscv::record::EmulationRecord,
    machine::{chip::ChipBehavior, utils::pad_to_power_of_two},
};
use hashbrown::HashMap;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use rayon::prelude::*;
use std::borrow::BorrowMut;

impl<F: PrimeField32> ChipBehavior<F> for ProgramChip<F> {
    type Record = EmulationRecord;
    type Program = Program;

    fn name(&self) -> String {
        "Program".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_PROGRAM_PREPROCESSED_COLS
    }

    fn generate_preprocessed(&self, program: &Program) -> Option<RowMajorMatrix<F>> {
        debug_assert!(!program.instructions.is_empty(), "empty program");

        let rows = program
            .instructions
            .iter()
            .enumerate()
            .map(|(i, instruction)| {
                let pc = program.pc_base + (i as u32 * 4);
                let mut row = [F::ZERO; NUM_PROGRAM_PREPROCESSED_COLS];
                let cols: &mut ProgramPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                cols.pc = F::from_canonical_u32(pc);
                cols.instruction.populate(*instruction);
                cols.selectors.populate(*instruction);

                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_PROGRAM_PREPROCESSED_COLS,
        );

        let log_size = program.fixed_log2_rows(&self.name());
        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_PROGRAM_PREPROCESSED_COLS, F>(&mut trace.values, log_size);

        Some(trace)
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        // Collect instruction counts in parallel using a thread-safe HashMap
        let instruction_counts: HashMap<u32, usize> = input
            .cpu_events
            .par_iter()
            .fold(HashMap::new, |mut acc, event| {
                let pc = event.pc;
                *acc.entry(pc).or_insert(0) += 1;
                acc
            })
            .reduce(HashMap::new, |mut a, b| {
                b.into_iter().for_each(|(pc, count)| {
                    *a.entry(pc).or_insert(0) += count;
                });
                a
            });

        // Generate rows in parallel
        let rows: Vec<[F; NUM_PROGRAM_MULT_COLS]> = input
            .program
            .instructions
            .par_iter()
            .enumerate()
            .map(|(i, _)| {
                let pc = input.program.pc_base + (i as u32 * 4);
                let mut row = [F::ZERO; NUM_PROGRAM_MULT_COLS];
                let cols: &mut ProgramMultiplicityCols<F> = row.as_mut_slice().borrow_mut();
                cols.multiplicity =
                    F::from_canonical_usize(*instruction_counts.get(&pc).unwrap_or(&0));
                row
            })
            .collect();

        // Convert the trace to a row major matrix
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_PROGRAM_MULT_COLS,
        );

        // Pad the trace to a power of two
        let log_rows = input.shape_chip_size(&self.name());
        pad_to_power_of_two::<NUM_PROGRAM_MULT_COLS, F>(&mut trace.values, log_rows);

        trace
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }
}
