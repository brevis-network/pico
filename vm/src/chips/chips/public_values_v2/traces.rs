use super::columns::{
    PublicValuesCols, PublicValuesPreprocessedCols, NUM_PUBLIC_VALUES_COLS,
    NUM_PUBLIC_VALUES_PREPROCESSED_COLS,
};
use crate::{
    chips::chips::{
        public_values_v2::{PublicValuesChip, PUB_VALUES_LOG_HEIGHT},
        recursion_memory_v2::MemoryAccessCols,
    },
    compiler::recursion_v2::{instruction::Instruction, program::RecursionProgram},
    machine::chip::ChipBehavior,
    recursion_v2::{runtime::RecursionRecord, stark::utils::pad_rows_fixed},
};
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::BorrowMut;

impl<F: PrimeField32> ChipBehavior<F> for PublicValuesChip<F> {
    type Record = RecursionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "PublicValues".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_PUBLIC_VALUES_PREPROCESSED_COLS
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let mut rows: Vec<[F; NUM_PUBLIC_VALUES_PREPROCESSED_COLS]> = Vec::new();
        let commit_pv_hash_instructions = program
            .instructions
            .iter()
            .filter_map(|instruction| {
                if let Instruction::CommitPublicValues(instr) = instruction {
                    Some(instr)
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        if commit_pv_hash_instructions.len() != 1 {
            tracing::warn!("Expected exactly one CommitPVHash instruction.");
        }

        // We only take 1 commit pv hash instruction, since our air only checks for one public
        // values hash.
        for instruction in commit_pv_hash_instructions.iter().take(1) {
            for (i, addr) in instruction.pv_addrs.digest.iter().enumerate() {
                let mut row = [F::ZERO; NUM_PUBLIC_VALUES_PREPROCESSED_COLS];
                let cols: &mut PublicValuesPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                cols.pv_idx[i] = F::ONE;
                cols.pv_mem = MemoryAccessCols {
                    addr: *addr,
                    mult: F::NEG_ONE,
                };
                rows.push(row);
            }
        }

        // Pad the preprocessed rows to log size 4.
        pad_rows_fixed(
            &mut rows,
            || [F::ZERO; NUM_PUBLIC_VALUES_PREPROCESSED_COLS],
            Some(PUB_VALUES_LOG_HEIGHT),
        );

        let trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect(),
            NUM_PUBLIC_VALUES_PREPROCESSED_COLS,
        );
        Some(trace)
    }

    fn generate_main(
        &self,
        input: &RecursionRecord<F>,
        _: &mut RecursionRecord<F>,
    ) -> RowMajorMatrix<F> {
        if input.commit_pv_hash_events.len() != 1 {
            tracing::warn!("Expected exactly one CommitPVHash event.");
        }

        let mut rows: Vec<[F; NUM_PUBLIC_VALUES_COLS]> = Vec::new();

        // We only take 1 commit pv hash instruction, since our air only checks for one public
        // values hash.
        for event in input.commit_pv_hash_events.iter().take(1) {
            for element in event.public_values.digest.iter() {
                let mut row = [F::ZERO; NUM_PUBLIC_VALUES_COLS];
                let cols: &mut PublicValuesCols<F> = row.as_mut_slice().borrow_mut();

                cols.pv_element = *element;
                rows.push(row);
            }
        }

        // Pad the trace to log size 4
        pad_rows_fixed(
            &mut rows,
            || [F::ZERO; NUM_PUBLIC_VALUES_COLS],
            Some(PUB_VALUES_LOG_HEIGHT),
        );

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(rows.into_iter().flatten().collect(), NUM_PUBLIC_VALUES_COLS)
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }
}
