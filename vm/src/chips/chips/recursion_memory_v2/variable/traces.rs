use super::{
    super::{MemoryAccessCols, NUM_MEM_ACCESS_COLS},
    columns::{
        MemoryCols, NUM_MEM_INIT_COLS, NUM_MEM_PREPROCESSED_INIT_COLS, NUM_VAR_MEM_ENTRIES_PER_ROW,
    },
    MemoryVarChip,
};
use crate::{
    compiler::recursion_v2::{
        instruction::{HintBitsInstr, HintExt2FeltsInstr, HintInstr, Instruction},
        program::RecursionProgram,
    },
    machine::{chip::ChipBehavior, utils::pad_to_power_of_two},
    recursion_v2::{runtime::RecursionRecord, stark::utils::next_power_of_two},
};
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::{
    IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator, ParallelSliceMut,
};
use std::{borrow::BorrowMut, iter::zip};

impl<F: PrimeField32> ChipBehavior<F> for MemoryVarChip<F> {
    type Record = RecursionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "MemoryVar".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_MEM_PREPROCESSED_INIT_COLS
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        // Allocating an intermediate `Vec` is faster.
        let accesses = program
            .instructions
            .par_iter() // Using `rayon` here provides a big speedup.
            .flat_map_iter(|instruction| match instruction {
                Instruction::Hint(HintInstr { output_addrs_mults })
                | Instruction::HintBits(HintBitsInstr {
                    output_addrs_mults,
                    input_addr: _, // No receive interaction for the hint operation
                }) => output_addrs_mults.iter().collect(),
                Instruction::HintExt2Felts(HintExt2FeltsInstr {
                    output_addrs_mults,
                    input_addr: _, // No receive interaction for the hint operation
                }) => output_addrs_mults.iter().collect(),
                _ => vec![],
            })
            .collect::<Vec<_>>();

        let nb_rows = accesses.len().div_ceil(NUM_VAR_MEM_ENTRIES_PER_ROW);
        let padded_nb_rows = match program.fixed_log2_rows(self) {
            Some(log2_rows) => 1 << log2_rows,
            None => next_power_of_two(nb_rows, None),
        };
        let mut values = vec![F::ZERO; padded_nb_rows * NUM_MEM_PREPROCESSED_INIT_COLS];

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let populate_len = accesses.len() * NUM_MEM_ACCESS_COLS;
        values[..populate_len]
            .par_chunks_mut(NUM_MEM_ACCESS_COLS)
            .zip_eq(accesses)
            .for_each(|(row, &(addr, mult))| *row.borrow_mut() = MemoryAccessCols { addr, mult });

        let mut trace = RowMajorMatrix::new(values, NUM_MEM_PREPROCESSED_INIT_COLS);

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_MEM_PREPROCESSED_INIT_COLS, F>(&mut trace.values);

        Some(trace)
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let rows = input
            .mem_var_events
            .chunks(NUM_VAR_MEM_ENTRIES_PER_ROW)
            .map(|row_events| {
                let mut row = [F::ZERO; NUM_MEM_INIT_COLS];
                let cols: &mut MemoryCols<_> = row.as_mut_slice().borrow_mut();
                for (cell, vals) in zip(&mut cols.values, row_events) {
                    *cell = vals.inner;
                }
                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_MEM_INIT_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_MEM_INIT_COLS, F>(&mut trace.values);

        trace
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }
}
