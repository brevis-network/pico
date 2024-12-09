use super::{
    columns::{
        FriFoldMainCols, FriFoldPreprocessedCols, NUM_FRI_FOLD_MAIN_COLS,
        NUM_FRI_FOLD_PREPROCESSED_COLS,
    },
    FriFoldChip,
};
use crate::{
    chips::chips::recursion_memory_v2::MemoryAccessCols,
    compiler::recursion_v2::{instruction::Instruction, program::RecursionProgram},
    machine::{chip::ChipBehavior, utils::pad_to_power_of_two},
    recursion_v2::{runtime::RecursionRecord, types::FriFoldInstr},
};
use itertools::Itertools;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::BorrowMut;

impl<const DEGREE: usize, F: PrimeField32> ChipBehavior<F> for FriFoldChip<DEGREE, F> {
    type Record = RecursionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "FriFold".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_FRI_FOLD_PREPROCESSED_COLS
    }
    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let mut rows: Vec<[F; NUM_FRI_FOLD_PREPROCESSED_COLS]> = Vec::new();
        program
            .instructions
            .iter()
            .filter_map(|instruction| {
                if let Instruction::FriFold(instr) = instruction {
                    Some(instr)
                } else {
                    None
                }
            })
            .for_each(|instruction| {
                let FriFoldInstr {
                    base_single_addrs,
                    ext_single_addrs,
                    ext_vec_addrs,
                    alpha_pow_mults,
                    ro_mults,
                } = instruction.as_ref();
                let mut row_add =
                    vec![[F::ZERO; NUM_FRI_FOLD_PREPROCESSED_COLS]; ext_vec_addrs.ps_at_z.len()];

                row_add.iter_mut().enumerate().for_each(|(i, row)| {
                    let row: &mut FriFoldPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                    row.is_first = F::from_bool(i == 0);

                    // Only need to read z, x, and alpha on the first iteration, hence the
                    // multiplicities are i==0.
                    row.z_mem = MemoryAccessCols {
                        addr: ext_single_addrs.z,
                        mult: -F::from_bool(i == 0),
                    };
                    row.x_mem = MemoryAccessCols {
                        addr: base_single_addrs.x,
                        mult: -F::from_bool(i == 0),
                    };
                    row.alpha_mem = MemoryAccessCols {
                        addr: ext_single_addrs.alpha,
                        mult: -F::from_bool(i == 0),
                    };

                    // Read the memory for the input vectors.
                    row.alpha_pow_input_mem = MemoryAccessCols {
                        addr: ext_vec_addrs.alpha_pow_input[i],
                        mult: F::NEG_ONE,
                    };
                    row.ro_input_mem = MemoryAccessCols {
                        addr: ext_vec_addrs.ro_input[i],
                        mult: F::NEG_ONE,
                    };
                    row.p_at_z_mem = MemoryAccessCols {
                        addr: ext_vec_addrs.ps_at_z[i],
                        mult: F::NEG_ONE,
                    };
                    row.p_at_x_mem = MemoryAccessCols {
                        addr: ext_vec_addrs.mat_opening[i],
                        mult: F::NEG_ONE,
                    };

                    // Write the memory for the output vectors.
                    row.alpha_pow_output_mem = MemoryAccessCols {
                        addr: ext_vec_addrs.alpha_pow_output[i],
                        mult: alpha_pow_mults[i],
                    };
                    row.ro_output_mem = MemoryAccessCols {
                        addr: ext_vec_addrs.ro_output[i],
                        mult: ro_mults[i],
                    };

                    row.is_real = F::ONE;
                });
                rows.extend(row_add);
            });

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect(),
            NUM_FRI_FOLD_PREPROCESSED_COLS,
        );

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_FRI_FOLD_PREPROCESSED_COLS, F>(&mut trace.values);

        Some(trace)
    }

    fn generate_main(&self, input: &Self::Record, _output: &mut Self::Record) -> RowMajorMatrix<F> {
        let rows = input
            .fri_fold_events
            .iter()
            .map(|event| {
                let mut row = [F::ZERO; NUM_FRI_FOLD_MAIN_COLS];

                let cols: &mut FriFoldMainCols<F> = row.as_mut_slice().borrow_mut();

                cols.x = event.base_single.x;
                cols.z = event.ext_single.z;
                cols.alpha = event.ext_single.alpha;

                cols.p_at_z = event.ext_vec.ps_at_z;
                cols.p_at_x = event.ext_vec.mat_opening;
                cols.alpha_pow_input = event.ext_vec.alpha_pow_input;
                cols.ro_input = event.ext_vec.ro_input;

                cols.alpha_pow_output = event.ext_vec.alpha_pow_output;
                cols.ro_output = event.ext_vec.ro_output;

                row
            })
            .collect_vec();

        // Convert the trace to a row major matrix.
        let mut trace =
            RowMajorMatrix::new(rows.into_iter().flatten().collect(), NUM_FRI_FOLD_MAIN_COLS);

        // Pad the trace to a power of two.
        pad_to_power_of_two::<NUM_FRI_FOLD_MAIN_COLS, F>(&mut trace.values);

        trace
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }
}
