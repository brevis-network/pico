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
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::BorrowMut;

impl<F: Field> ChipBehavior<F> for ProgramChip<F> {
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

        Some(trace)
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
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

        let pc_base = input.program.pc_base;
        let chunk = input.public_values.execution_chunk;
        let row_fn: fn(u32, u32, usize, &HashMap<u32, usize>) -> [F; NUM_PROGRAM_MULT_COLS] =
            if !input.unconstrained {
                |pc_base: u32, chunk: u32, i: usize, instruction_counts: &HashMap<u32, usize>| {
                    let pc = pc_base + (i as u32 * 4);
                    let mut row = [F::zero(); NUM_PROGRAM_MULT_COLS];
                    let cols: &mut ProgramMultiplicityCols<F> = row.as_mut_slice().borrow_mut();
                    cols.chunk = F::from_canonical_u32(chunk);
                    cols.multiplicity =
                        F::from_canonical_usize(*instruction_counts.get(&pc).unwrap_or(&0));
                    row
                }
                    as _
            } else {
                |_: u32, _: u32, _: usize, _: &HashMap<u32, usize>| {
                    [F::zero(); NUM_PROGRAM_MULT_COLS] as _
                }
            };

        let rows = input
            .program
            .instructions
            .clone()
            .into_iter()
            .enumerate()
            .map(|(i, _)| row_fn(pc_base, chunk, i, &instruction_counts))
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_PROGRAM_MULT_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_PROGRAM_MULT_COLS, F>(&mut trace.values);

        trace
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }
}
