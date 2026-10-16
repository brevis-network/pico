use crate::{
    chips::chips::{
        recursion_memory::MemoryAccessCols,
        unpack_block::{
            columns::{
                UnpackBlockCols, UnpackBlockPreprocessedCols, NUM_UNPACK_BLOCK_COLS,
                NUM_UNPACK_BLOCK_PREPROCESSED_COLS,
            },
            UnpackBlockChip,
        },
    },
    compiler::recursion::{
        instruction::Instruction,
        program::RecursionProgram,
        types::{UnpackBlockEvent, UnpackBlockInstr},
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

impl<F> BaseAir<F> for UnpackBlockChip<F> {
    fn width(&self) -> usize {
        NUM_UNPACK_BLOCK_COLS
    }
}

impl<F: PrimeField32> ChipBehavior<F> for UnpackBlockChip<F> {
    type Record = RecursionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "UnpackBlock".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_UNPACK_BLOCK_PREPROCESSED_COLS
    }

    fn preprocessed_rows(&self, program: &Self::Program) -> Option<PreprocessedRows> {
        Some(PreprocessedRows::Unpadded(
            program.prep_row_counts().unpack_block,
        ))
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let mut rows: Vec<[F; NUM_UNPACK_BLOCK_PREPROCESSED_COLS]> = Vec::new();

        program
            .instructions
            .iter()
            .filter_map(|instruction| {
                if let Instruction::UnpackBlock(instr) = instruction {
                    Some(instr.as_ref())
                } else {
                    None
                }
            })
            .for_each(|instr: &UnpackBlockInstr<F>| {
                let mut row = [F::ZERO; NUM_UNPACK_BLOCK_PREPROCESSED_COLS];
                let cols: &mut UnpackBlockPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                cols.is_real = F::ONE;
                cols.in_addr = instr.in_addr;
                cols.out = std::array::from_fn(|i| MemoryAccessCols {
                    addr: instr.out_addrs[i],
                    mult: instr.mults[i],
                });
                rows.push(row);
            });

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_UNPACK_BLOCK_PREPROCESSED_COLS,
        );
        let log_size = program.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_UNPACK_BLOCK_PREPROCESSED_COLS, F>(&mut trace.values, log_size);
        Some(trace)
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let rows = input
            .unpack_block_events
            .iter()
            .map(|event: &UnpackBlockEvent<F>| {
                let mut row = [F::ZERO; NUM_UNPACK_BLOCK_COLS];
                let cols: &mut UnpackBlockCols<F> = row.as_mut_slice().borrow_mut();
                cols.val = event.val;
                row
            })
            .collect::<Vec<_>>();

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_UNPACK_BLOCK_COLS,
        );
        let log_rows = input.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_UNPACK_BLOCK_COLS, F>(&mut trace.values, log_rows);
        trace
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }
}
