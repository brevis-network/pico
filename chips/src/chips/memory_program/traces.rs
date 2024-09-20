use crate::chips::memory_program::{
    columns::{
        MemoryProgramMultCols, MemoryProgramPreprocessedCols, NUM_MEMORY_PROGRAM_MULT_COLS,
        NUM_MEMORY_PROGRAM_PREPROCESSED_COLS,
    },
    MemoryProgramChip,
};
use core::borrow::BorrowMut;
use log::info;
use p3_field::Field;
use p3_matrix::dense::RowMajorMatrix;
use pico_compiler::program::Program;
use pico_emulator::riscv::record::EmulationRecord;
use pico_machine::{chip::ChipBehavior, utils::pad_to_power_of_two};
use pico_compiler::word::Word;

impl<F: Field> ChipBehavior<F> for MemoryProgramChip<F> {
    type Record = EmulationRecord;

    fn name(&self) -> String {
        "MemoryProgram".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_MEMORY_PROGRAM_PREPROCESSED_COLS
    }

    fn generate_preprocessed(&self, program: &Program) -> Option<RowMajorMatrix<F>> {
        info!("MemoryProgramChip - generate_preprocessed: BEGIN");

        let program_memory = program.memory_image.clone();
        // Note that BTreeMap is guaranteed to be sorted by key. This makes the row order
        // deterministic.
        let rows = program_memory
            .into_iter()
            .map(|(addr, word)| {
                let mut row = [F::zero(); NUM_MEMORY_PROGRAM_PREPROCESSED_COLS];
                let cols: &mut MemoryProgramPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                cols.addr = F::from_canonical_u32(addr);
                cols.value = Word::from(word);
                cols.is_real = F::one();
                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_MEMORY_PROGRAM_PREPROCESSED_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_MEMORY_PROGRAM_PREPROCESSED_COLS, F>(&mut trace.values);

        info!("MemoryProgramChip - generate_preprocessed: END");

        Some(trace)
    }

    fn generate_main(&self, input: &EmulationRecord) -> RowMajorMatrix<F> {
        info!("MemoryProgramChip - generate_main: BEGIN");

        let program_memory_addrs = input
            .program
            .memory_image
            .keys()
            .copied()
            .collect::<Vec<_>>();

        /* TODO: Replace after we enable the public values.
                let mult = if input.public_values.shard == 1 {
                    F::one()
                } else {
                    F::zero()
                };
        */
        // We only have one shard for now.
        let mult = F::one();

        // Generate the trace rows for each event.
        let rows = program_memory_addrs
            .into_iter()
            .map(|_| {
                let mut row = [F::zero(); NUM_MEMORY_PROGRAM_MULT_COLS];
                let cols: &mut MemoryProgramMultCols<F> = row.as_mut_slice().borrow_mut();
                cols.multiplicity = mult;
                // We only have one shard for now.
                // cols.is_first_shard.populate(input.public_values.shard - 1);
                cols.is_first_shard.populate(0);
                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_MEMORY_PROGRAM_MULT_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_MEMORY_PROGRAM_MULT_COLS, F>(&mut trace.values);

        info!("MemoryProgramChip - generate_main: END");

        trace
    }
}
