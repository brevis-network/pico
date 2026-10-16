use crate::{
    chips::chips::digest_select::{
        columns::{
            DigestSelectCols, DigestSelectPreprocessedCols, DigestSelectPreprocessedValueCols,
            DigestSelectValueCols, NUM_DIGEST_SELECT_COLS, NUM_DIGEST_SELECT_PREPROCESSED_COLS,
        },
        DigestSelectChip,
    },
    compiler::recursion::{
        instruction::Instruction,
        program::RecursionProgram,
        types::{DigestSelectEvent, DigestSelectInstr},
    },
    emulator::recursion::emulator::RecursionRecord,
    machine::{
        chip::{ChipBehavior, PreprocessedRows},
        utils::pad_to_power_of_two,
    },
    primitives::consts::DIGEST_SELECT_DATAPAR,
};
use p3_air::BaseAir;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::BorrowMut;

impl<F> BaseAir<F> for DigestSelectChip<F> {
    fn width(&self) -> usize {
        NUM_DIGEST_SELECT_COLS
    }
}

impl<F: PrimeField32> ChipBehavior<F> for DigestSelectChip<F> {
    type Record = RecursionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "DigestSelect".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_DIGEST_SELECT_PREPROCESSED_COLS
    }

    fn preprocessed_rows(&self, program: &Self::Program) -> Option<PreprocessedRows> {
        Some(PreprocessedRows::Unpadded(
            program.prep_row_counts().digest_select,
        ))
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let instrs: Vec<&DigestSelectInstr<F>> = program
            .instructions
            .iter()
            .filter_map(|instruction| {
                if let Instruction::DigestSelect(instr) = instruction {
                    Some(instr.as_ref())
                } else {
                    None
                }
            })
            .collect();

        let mut rows: Vec<[F; NUM_DIGEST_SELECT_PREPROCESSED_COLS]> = Vec::new();
        for chunk in instrs.chunks(DIGEST_SELECT_DATAPAR) {
            let mut row = [F::ZERO; NUM_DIGEST_SELECT_PREPROCESSED_COLS];
            let cols: &mut DigestSelectPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
            for (k, instr) in chunk.iter().enumerate() {
                cols.values[k] = DigestSelectPreprocessedValueCols {
                    is_real: F::ONE,
                    bit_addr: instr.bit_addr,
                    in1_addrs: instr.in1_addrs,
                    in2_addrs: instr.in2_addrs,
                    out_addrs: instr.out_addrs,
                    mults: instr.mults,
                };
            }
            rows.push(row);
        }

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_DIGEST_SELECT_PREPROCESSED_COLS,
        );
        let log_size = program.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_DIGEST_SELECT_PREPROCESSED_COLS, F>(&mut trace.values, log_size);
        Some(trace)
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let events = &input.digest_select_events;
        let mut rows: Vec<[F; NUM_DIGEST_SELECT_COLS]> = Vec::new();
        for chunk in events.chunks(DIGEST_SELECT_DATAPAR) {
            let mut row = [F::ZERO; NUM_DIGEST_SELECT_COLS];
            let cols: &mut DigestSelectCols<F> = row.as_mut_slice().borrow_mut();
            for (k, event) in chunk.iter().enumerate() {
                let e: &DigestSelectEvent<F> = event;
                cols.values[k] = DigestSelectValueCols {
                    bit: e.bit,
                    in1: e.in1,
                    in2: e.in2,
                    out: e.out,
                };
            }
            rows.push(row);
        }

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_DIGEST_SELECT_COLS,
        );
        let log_rows = input.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_DIGEST_SELECT_COLS, F>(&mut trace.values, log_rows);
        trace
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }
}
