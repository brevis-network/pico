use crate::{
    chips::chips::pack_block::{
        columns::{
            PackBlockCols, PackBlockPreprocessedCols, PackBlockPreprocessedValueCols,
            NUM_PACK_BLOCK_COLS, NUM_PACK_BLOCK_PREPROCESSED_COLS,
        },
        PackBlockChip,
    },
    compiler::recursion::{
        instruction::Instruction,
        program::RecursionProgram,
        types::{PackBlockEvent, PackBlockInstr},
    },
    emulator::recursion::emulator::RecursionRecord,
    machine::{
        chip::{ChipBehavior, PreprocessedRows},
        utils::pad_to_power_of_two,
    },
    primitives::consts::PACK_BLOCK_DATAPAR,
};
use p3_air::BaseAir;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::BorrowMut;

impl<F> BaseAir<F> for PackBlockChip<F> {
    fn width(&self) -> usize {
        NUM_PACK_BLOCK_COLS
    }
}

impl<F: PrimeField32> ChipBehavior<F> for PackBlockChip<F> {
    type Record = RecursionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "PackBlock".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_PACK_BLOCK_PREPROCESSED_COLS
    }

    fn preprocessed_rows(&self, program: &Self::Program) -> Option<PreprocessedRows> {
        Some(PreprocessedRows::Unpadded(
            program.prep_row_counts().pack_block,
        ))
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let instrs: Vec<&PackBlockInstr<F>> = program
            .instructions
            .iter()
            .filter_map(|instruction| {
                if let Instruction::PackBlock(instr) = instruction {
                    Some(instr.as_ref())
                } else {
                    None
                }
            })
            .collect();

        let mut rows: Vec<[F; NUM_PACK_BLOCK_PREPROCESSED_COLS]> = Vec::new();
        for chunk in instrs.chunks(PACK_BLOCK_DATAPAR) {
            let mut row = [F::ZERO; NUM_PACK_BLOCK_PREPROCESSED_COLS];
            let cols: &mut PackBlockPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
            for (k, instr) in chunk.iter().enumerate() {
                cols.values[k] = PackBlockPreprocessedValueCols {
                    is_real: F::ONE,
                    in_addrs: instr.in_addrs,
                    out_addr: instr.out_addr,
                    mult: instr.mult,
                };
            }
            rows.push(row);
        }

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_PACK_BLOCK_PREPROCESSED_COLS,
        );
        let log_size = program.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_PACK_BLOCK_PREPROCESSED_COLS, F>(&mut trace.values, log_size);
        Some(trace)
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let events = &input.pack_block_events;
        let mut rows: Vec<[F; NUM_PACK_BLOCK_COLS]> = Vec::new();
        for chunk in events.chunks(PACK_BLOCK_DATAPAR) {
            let mut row = [F::ZERO; NUM_PACK_BLOCK_COLS];
            let cols: &mut PackBlockCols<F> = row.as_mut_slice().borrow_mut();
            for (k, event) in chunk.iter().enumerate() {
                let e: &PackBlockEvent<F> = event;
                cols.values[k] = e.lanes;
            }
            rows.push(row);
        }

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_PACK_BLOCK_COLS,
        );
        let log_rows = input.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_PACK_BLOCK_COLS, F>(&mut trace.values, log_rows);
        trace
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }
}
