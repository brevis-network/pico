use super::{
    columns::{
        ProgramMultiplicityCols, ProgramPreprocessedCols, NUM_PROGRAM_MULT_COLS,
        NUM_PROGRAM_PREPROCESSED_COLS,
    },
    ProgramChip,
};
use hashbrown::HashMap;
use log::info;
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use pico_compiler::program::Program;
use pico_emulator::record::EmulationRecord;
use pico_machine::{chip::ChipBehavior, utils::pad_to_power_of_two};
use std::borrow::BorrowMut;

impl<F: Field> ChipBehavior<F> for ProgramChip<F> {
    fn name(&self) -> String {
        "Program".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_PROGRAM_PREPROCESSED_COLS
    }

    fn generate_preprocessed(&self, program: &Program) -> Option<RowMajorMatrix<F>> {
        info!("ProgramChip - generate_preprocessed: BEGIN");

        debug_assert!(!program.instructions.is_empty(), "empty program");

        let rows = program
            .instructions
            .clone()
            .into_iter()
            .enumerate()
            .map(|(i, instruction)| {
                let pc = program.pc_base + (i as u32 * 4);
                let mut row = [F::zero(); NUM_PROGRAM_PREPROCESSED_COLS];
                let cols: &mut ProgramPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                cols.pc = F::from_canonical_u32(pc);
                cols.instruction.populate(instruction);
                cols.selectors.populate(instruction);

                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_PROGRAM_PREPROCESSED_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_PROGRAM_PREPROCESSED_COLS, F>(&mut trace.values);

        info!("ProgramChip - generate_preprocessed: END");

        Some(trace)
    }

    fn generate_main(&self, input: &EmulationRecord) -> RowMajorMatrix<F> {
        info!("ProgramChip - generate_main: BEGIN");

        // Generate the trace rows for each event.

        // Collect the number of times each instruction is called from the cpu events.
        // Store it as a map of PC -> count.
        let mut instruction_counts = HashMap::new();
        input.cpu_events.iter().for_each(|event| {
            let pc = event.pc;
            instruction_counts
                .entry(pc)
                .and_modify(|count| *count += 1)
                .or_insert(1);
        });

        let rows = input
            .program
            .instructions
            .clone()
            .into_iter()
            .enumerate()
            .map(|(i, _)| {
                let pc = input.program.pc_base + (i as u32 * 4);
                let mut row = [F::zero(); NUM_PROGRAM_MULT_COLS];
                let cols: &mut ProgramMultiplicityCols<F> = row.as_mut_slice().borrow_mut();
                // TODO: Set shard if it's added in record.
                cols.shard = F::zero();
                // cols.shard = F::from_canonical_u32(input.public_values.execution_shard);
                cols.multiplicity =
                    F::from_canonical_usize(*instruction_counts.get(&pc).unwrap_or(&0));
                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_PROGRAM_MULT_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_PROGRAM_MULT_COLS, F>(&mut trace.values);

        info!("ProgramChip - generate_main: END");

        trace
    }
}
