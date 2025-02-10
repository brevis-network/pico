use crate::{
    chips::{
        chips::alu_base::{columns::*, BaseAluChip},
        utils::next_power_of_two,
    },
    compiler::recursion::{
        instruction::Instruction, program::RecursionProgram, types::BaseAluInstr,
    },
    emulator::recursion::emulator::{BaseAluOpcode, RecursionRecord},
    machine::chip::ChipBehavior,
    primitives::consts::BASE_ALU_DATAPAR,
};
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::ParallelIterator;
use rayon::prelude::{IndexedParallelIterator, ParallelSliceMut};
use std::borrow::BorrowMut;

impl<F: PrimeField32> ChipBehavior<F> for BaseAluChip<F> {
    type Record = RecursionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "BaseAlu".to_string()
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let instructions = program
            .instructions
            .iter()
            .filter_map(|instruction| match instruction {
                Instruction::BaseAlu(x) => Some(x),
                _ => None,
            })
            .collect::<Vec<_>>();

        let nb_rows = instructions.len().div_ceil(BASE_ALU_DATAPAR);
        let fixed_log2_rows = program.fixed_log2_rows(&self.name());
        let padded_nb_rows = match fixed_log2_rows {
            Some(log2_rows) => 1 << log2_rows,
            None => next_power_of_two(nb_rows, None),
        };
        let mut values = vec![F::ZERO; padded_nb_rows * NUM_BASE_ALU_PREPROCESSED_COLS];

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let populate_len = instructions.len() * NUM_BASE_ALU_ACCESS_COLS;
        values[..populate_len]
            .par_chunks_mut(NUM_BASE_ALU_ACCESS_COLS)
            .zip_eq(instructions)
            .for_each(|(row, instr)| {
                let BaseAluInstr {
                    opcode,
                    mult,
                    addrs,
                } = instr;
                let access: &mut BaseAluAccessCols<_> = row.borrow_mut();
                *access = BaseAluAccessCols {
                    addrs: addrs.to_owned(),
                    is_add: F::from_bool(false),
                    is_sub: F::from_bool(false),
                    is_mul: F::from_bool(false),
                    is_div: F::from_bool(false),
                    mult: mult.to_owned(),
                };
                let target_flag = match opcode {
                    BaseAluOpcode::AddF => &mut access.is_add,
                    BaseAluOpcode::SubF => &mut access.is_sub,
                    BaseAluOpcode::MulF => &mut access.is_mul,
                    BaseAluOpcode::DivF => &mut access.is_div,
                };
                *target_flag = F::from_bool(true);
            });

        // Convert the trace to a row major matrix.
        Some(RowMajorMatrix::new(values, NUM_BASE_ALU_PREPROCESSED_COLS))
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let events = &input.base_alu_events;
        let nb_rows = events.len().div_ceil(BASE_ALU_DATAPAR);
        let fixed_log2_rows = input.fixed_log2_rows(&self.name());
        let padded_nb_rows = match fixed_log2_rows {
            Some(log2_rows) => 1 << log2_rows,
            None => next_power_of_two(nb_rows, None),
        };
        let mut values = vec![F::ZERO; padded_nb_rows * NUM_BASE_ALU_COLS];

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let populate_len = events.len() * NUM_BASE_ALU_VALUE_COLS;
        values[..populate_len]
            .par_chunks_mut(NUM_BASE_ALU_VALUE_COLS)
            .zip_eq(events)
            .for_each(|(row, &vals)| {
                let cols: &mut BaseAluValueCols<_> = row.borrow_mut();
                *cols = BaseAluValueCols { vals };
            });

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_BASE_ALU_COLS)
    }

    fn preprocessed_width(&self) -> usize {
        NUM_BASE_ALU_PREPROCESSED_COLS
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }

    fn local_only(&self) -> bool {
        true
    }
}
