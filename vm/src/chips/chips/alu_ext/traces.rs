use crate::{
    chips::{
        chips::alu_ext::{
            columns::{
                ExtAluAccessCols, ExtAluValueCols, NUM_EXT_ALU_ACCESS_COLS, NUM_EXT_ALU_COLS,
                NUM_EXT_ALU_PREPROCESSED_COLS, NUM_EXT_ALU_VALUE_COLS,
            },
            ExtAluChip,
        },
        utils::next_power_of_two,
    },
    compiler::recursion::{
        instruction::Instruction, program::RecursionProgram, types::ExtAluInstr,
    },
    emulator::recursion::emulator::{ExtAluOpcode, RecursionRecord},
    iter::{IndexedPicoIterator, PicoIterator, PicoSliceMut},
    machine::chip::ChipBehavior,
    primitives::consts::{EXTENSION_DEGREE, EXT_ALU_DATAPAR},
};
use p3_field::{extension::BinomiallyExtendable, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::BorrowMut;

impl<F: PrimeField32 + BinomiallyExtendable<EXTENSION_DEGREE>> ChipBehavior<F> for ExtAluChip<F> {
    type Record = RecursionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "ExtAlu".to_string()
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let instructions = program
            .instructions
            .iter()
            .filter_map(|instruction| match instruction {
                Instruction::ExtAlu(x) => Some(x),
                _ => None,
            })
            .collect::<Vec<_>>();

        let nb_rows = instructions.len().div_ceil(EXT_ALU_DATAPAR);
        let fixed_log2_rows = program.fixed_log2_rows(&self.name());
        let padded_nb_rows = match fixed_log2_rows {
            Some(log2_rows) => 1 << log2_rows,
            None => next_power_of_two(nb_rows, None),
        };
        let mut values = vec![F::ZERO; padded_nb_rows * NUM_EXT_ALU_PREPROCESSED_COLS];

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let populate_len = instructions.len() * NUM_EXT_ALU_ACCESS_COLS;
        values[..populate_len]
            .pico_chunks_mut(NUM_EXT_ALU_ACCESS_COLS)
            .zip_eq(instructions)
            .for_each(|(row, instr)| {
                let ExtAluInstr {
                    opcode,
                    mult,
                    addrs,
                } = instr;
                let access: &mut ExtAluAccessCols<_> = row.borrow_mut();
                *access = ExtAluAccessCols {
                    addrs: addrs.to_owned(),
                    is_add: F::from_bool(false),
                    is_sub: F::from_bool(false),
                    is_mul: F::from_bool(false),
                    is_div: F::from_bool(false),
                    mult: mult.to_owned(),
                };
                let target_flag = match opcode {
                    ExtAluOpcode::AddE => &mut access.is_add,
                    ExtAluOpcode::SubE => &mut access.is_sub,
                    ExtAluOpcode::MulE => &mut access.is_mul,
                    ExtAluOpcode::DivE => &mut access.is_div,
                };
                *target_flag = F::from_bool(true);
            });

        // Convert the trace to a row major matrix.
        Some(RowMajorMatrix::new(values, NUM_EXT_ALU_PREPROCESSED_COLS))
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let events = &input.ext_alu_events;
        let nrows = events.len().div_ceil(EXT_ALU_DATAPAR);
        let fixed_log2_rows = input.fixed_log2_rows(&self.name());
        let padded_nb_rows = match fixed_log2_rows {
            Some(log2_rows) => 1 << log2_rows,
            None => next_power_of_two(nrows, None),
        };
        let mut values = vec![F::ZERO; padded_nb_rows * NUM_EXT_ALU_COLS];

        // Generate the trace rows & corresponding records for each chunk of events in parallel.
        let populate_len = events.len() * NUM_EXT_ALU_VALUE_COLS;
        values[..populate_len]
            .pico_chunks_mut(NUM_EXT_ALU_VALUE_COLS)
            .zip_eq(events)
            .for_each(|(row, &vals)| {
                let cols: &mut ExtAluValueCols<_> = row.borrow_mut();
                *cols = ExtAluValueCols { vals };
            });

        // Convert the trace to a row major matrix.
        RowMajorMatrix::new(values, NUM_EXT_ALU_COLS)
    }

    fn preprocessed_width(&self) -> usize {
        NUM_EXT_ALU_PREPROCESSED_COLS
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }

    fn local_only(&self) -> bool {
        true
    }
}
