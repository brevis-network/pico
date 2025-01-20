use crate::{
    chips::chips::batch_fri::{
        columns::{
            BatchFRICols, BatchFRIPreprocessedCols, NUM_BATCH_FRI_COLS,
            NUM_BATCH_FRI_PREPROCESSED_COLS,
        },
        BatchFRIChip,
    },
    compiler::recursion_v2::{
        instruction::Instruction, program::RecursionProgram, types::BatchFRIInstr,
    },
    emulator::recursion::emulator::RecursionRecord,
    machine::{chip::ChipBehavior, utils::pad_to_power_of_two},
};
use p3_air::BaseAir;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::BorrowMut;

impl<F> BaseAir<F> for BatchFRIChip<F> {
    fn width(&self) -> usize {
        NUM_BATCH_FRI_COLS
    }
}

impl<F: PrimeField32> ChipBehavior<F> for BatchFRIChip<F> {
    type Record = RecursionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "BatchFRI".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_BATCH_FRI_PREPROCESSED_COLS
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let mut rows: Vec<[F; NUM_BATCH_FRI_PREPROCESSED_COLS]> = Vec::new();
        program
            .instructions
            .iter()
            .filter_map(|instruction| {
                if let Instruction::BatchFRI(instr) = instruction {
                    Some(instr)
                } else {
                    None
                }
            })
            .for_each(|instruction| {
                let BatchFRIInstr {
                    base_vec_addrs,
                    ext_single_addrs,
                    ext_vec_addrs,
                    acc_mult,
                } = instruction.as_ref();
                let len = ext_vec_addrs.p_at_z.len();
                let mut row_add = vec![[F::ZERO; NUM_BATCH_FRI_PREPROCESSED_COLS]; len];
                debug_assert_eq!(*acc_mult, F::ONE);

                row_add.iter_mut().enumerate().for_each(|(_i, row)| {
                    let row: &mut BatchFRIPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                    row.is_real = F::ONE;
                    row.is_end = F::from_bool(_i == len - 1);
                    row.acc_addr = ext_single_addrs.acc;
                    row.alpha_pow_addr = ext_vec_addrs.alpha_pow[_i];
                    row.p_at_z_addr = ext_vec_addrs.p_at_z[_i];
                    row.p_at_x_addr = base_vec_addrs.p_at_x[_i];
                });
                rows.extend(row_add);
            });

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_BATCH_FRI_PREPROCESSED_COLS,
        );

        // Pad the trace to a power of two.
        let log_size = program.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_BATCH_FRI_PREPROCESSED_COLS, F>(&mut trace.values, log_size);

        Some(trace)
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let rows = input
            .batch_fri_events
            .iter()
            .map(|event| {
                let mut row = [F::ZERO; NUM_BATCH_FRI_COLS];
                let cols: &mut BatchFRICols<F> = row.as_mut_slice().borrow_mut();
                cols.acc = event.ext_single.acc;
                cols.alpha_pow = event.ext_vec.alpha_pow;
                cols.p_at_z = event.ext_vec.p_at_z;
                cols.p_at_x = event.base_vec.p_at_x;
                row
            })
            .collect::<Vec<_>>();

        // Convert the trace to a row major matrix.
        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_BATCH_FRI_COLS,
        );

        let log_rows = input.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_BATCH_FRI_COLS, F>(&mut trace.values, log_rows);

        trace
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }
}
