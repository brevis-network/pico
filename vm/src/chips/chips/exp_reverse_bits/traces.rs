use crate::{
    chips::chips::{
        exp_reverse_bits::{
            columns::{
                ExpReverseBitsLenCols, ExpReverseBitsLenPreprocessedCols,
                NUM_EXP_REVERSE_BITS_LEN_COLS, NUM_EXP_REVERSE_BITS_LEN_PREPROCESSED_COLS,
            },
            ExpReverseBitsLenChip,
        },
        recursion_memory_v2::MemoryAccessCols,
    },
    compiler::recursion_v2::{instruction::Instruction, program::RecursionProgram},
    machine::chip::ChipBehavior,
    recursion_v2::{
        runtime::RecursionRecord, stark::utils::pad_rows_fixed, types::ExpReverseBitsInstr,
    },
};
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::BorrowMut;

#[cfg(debug_assertions)]
use p3_matrix::Matrix;

impl<F: PrimeField32> ChipBehavior<F> for ExpReverseBitsLenChip<F> {
    type Record = RecursionRecord<F>;

    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "ExpReverseBitsLen".to_string()
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let mut rows: Vec<[F; NUM_EXP_REVERSE_BITS_LEN_PREPROCESSED_COLS]> = Vec::new();
        program
            .instructions
            .iter()
            .filter_map(|instruction| {
                if let Instruction::ExpReverseBitsLen(instr) = instruction {
                    Some(instr)
                } else {
                    None
                }
            })
            .for_each(|instruction| {
                let ExpReverseBitsInstr { addrs, mult } = instruction;
                let mut row_add =
                    vec![[F::ZERO; NUM_EXP_REVERSE_BITS_LEN_PREPROCESSED_COLS]; addrs.exp.len()];
                row_add.iter_mut().enumerate().for_each(|(i, row)| {
                    let row: &mut ExpReverseBitsLenPreprocessedCols<F> =
                        row.as_mut_slice().borrow_mut();
                    row.iteration_num = F::from_canonical_u32(i as u32);
                    row.is_first = F::from_bool(i == 0);
                    row.is_last = F::from_bool(i == addrs.exp.len() - 1);
                    row.is_real = F::ONE;
                    row.x_mem = MemoryAccessCols {
                        addr: addrs.base,
                        mult: -F::from_bool(i == 0),
                    };
                    row.exponent_mem = MemoryAccessCols {
                        addr: addrs.exp[i],
                        mult: F::NEG_ONE,
                    };
                    row.result_mem = MemoryAccessCols {
                        addr: addrs.result,
                        mult: *mult * F::from_bool(i == addrs.exp.len() - 1),
                    };
                });
                rows.extend(row_add);
            });

        // Pad the trace to a power of two.
        pad_rows_fixed(
            &mut rows,
            || [F::ZERO; NUM_EXP_REVERSE_BITS_LEN_PREPROCESSED_COLS],
            program.fixed_log2_rows(&self.name()),
        );

        let trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect(),
            NUM_EXP_REVERSE_BITS_LEN_PREPROCESSED_COLS,
        );
        Some(trace)
    }

    fn generate_main(
        &self,
        input: &RecursionRecord<F>,
        _: &mut RecursionRecord<F>,
    ) -> RowMajorMatrix<F> {
        let mut overall_rows = Vec::new();
        input.exp_reverse_bits_len_events.iter().for_each(|event| {
            let mut rows = vec![vec![F::ZERO; NUM_EXP_REVERSE_BITS_LEN_COLS]; event.exp.len()];

            let mut accum = F::ONE;

            rows.iter_mut().enumerate().for_each(|(i, row)| {
                let cols: &mut ExpReverseBitsLenCols<F> = row.as_mut_slice().borrow_mut();

                let prev_accum = accum;
                accum = prev_accum
                    * prev_accum
                    * if event.exp[i] == F::ONE {
                        event.base
                    } else {
                        F::ONE
                    };

                cols.x = event.base;
                cols.current_bit = event.exp[i];
                cols.accum = accum;
                cols.accum_squared = accum * accum;
                cols.prev_accum_squared = prev_accum * prev_accum;
                cols.multiplier = if event.exp[i] == F::ONE {
                    event.base
                } else {
                    F::ONE
                };
                cols.prev_accum_squared_times_multiplier =
                    cols.prev_accum_squared * cols.multiplier;
                if i == event.exp.len() {
                    assert_eq!(event.result, accum);
                }
            });

            overall_rows.extend(rows);
        });

        // Pad the trace to a power of two.
        pad_rows_fixed(
            &mut overall_rows,
            || [F::ZERO; NUM_EXP_REVERSE_BITS_LEN_COLS].to_vec(),
            input.fixed_log2_rows(&self.name()),
        );

        // Convert the trace to a row major matrix.
        let trace = RowMajorMatrix::new(
            overall_rows.into_iter().flatten().collect(),
            NUM_EXP_REVERSE_BITS_LEN_COLS,
        );

        #[cfg(debug_assertions)]
        println!(
            "exp reverse bits len trace dims is width: {:?}, height: {:?}",
            trace.width(),
            trace.height()
        );

        trace
    }

    fn preprocessed_width(&self) -> usize {
        NUM_EXP_REVERSE_BITS_LEN_PREPROCESSED_COLS
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }
}
