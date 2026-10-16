use crate::{
    chips::chips::ext_dot_product::{
        columns::{
            ExtDotProductCols, ExtDotProductPreprocessedCols, NUM_EXT_DOT_PRODUCT_COLS,
            NUM_EXT_DOT_PRODUCT_PREPROCESSED_COLS,
        },
        ExtDotProductChip,
    },
    compiler::recursion::{
        instruction::Instruction,
        program::RecursionProgram,
        types::{ExtDotProductEvent, ExtDotProductInstr},
    },
    emulator::recursion::emulator::RecursionRecord,
    machine::{
        chip::{ChipBehavior, PreprocessedRows},
        utils::pad_to_power_of_two,
    },
    primitives::consts::{EXT_DOT_PRODUCT_DATAPAR, EXT_DOT_PRODUCT_GROUPS},
};
use p3_air::BaseAir;
use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::BorrowMut;

impl<F> BaseAir<F> for ExtDotProductChip<F> {
    fn width(&self) -> usize {
        NUM_EXT_DOT_PRODUCT_COLS
    }
}

impl<F: PrimeField32> ChipBehavior<F> for ExtDotProductChip<F> {
    type Record = RecursionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "ExtDotProduct".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_EXT_DOT_PRODUCT_PREPROCESSED_COLS
    }

    fn preprocessed_rows(&self, program: &Self::Program) -> Option<PreprocessedRows> {
        Some(PreprocessedRows::Unpadded(
            program.prep_row_counts().ext_dot_product,
        ))
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let mut rows: Vec<[F; NUM_EXT_DOT_PRODUCT_PREPROCESSED_COLS]> = Vec::new();

        program
            .instructions
            .iter()
            .filter_map(|instruction| {
                if let Instruction::ExtDotProduct(instr) = instruction {
                    Some(instr.as_ref())
                } else {
                    None
                }
            })
            .for_each(|instr: &ExtDotProductInstr<F>| {
                let n_groups = instr.val_addrs.len();
                debug_assert_eq!(
                    instr.mu_addrs.len(),
                    n_groups * (EXT_DOT_PRODUCT_DATAPAR / EXT_DOT_PRODUCT_GROUPS)
                );
                // The lowering pads the address vectors to a whole number of rows
                // with zero-address (zero-value) groups.
                debug_assert_eq!(n_groups % EXT_DOT_PRODUCT_GROUPS, 0);
                let n_rows = n_groups / EXT_DOT_PRODUCT_GROUPS;
                for i in 0..n_rows {
                    let mut row = [F::ZERO; NUM_EXT_DOT_PRODUCT_PREPROCESSED_COLS];
                    let cols: &mut ExtDotProductPreprocessedCols<F> =
                        row.as_mut_slice().borrow_mut();
                    cols.is_real = F::ONE;
                    cols.is_end = F::from_bool(i == n_rows - 1);
                    for j in 0..EXT_DOT_PRODUCT_DATAPAR {
                        cols.mu_addrs[j] = instr.mu_addrs[EXT_DOT_PRODUCT_DATAPAR * i + j];
                    }
                    for g in 0..EXT_DOT_PRODUCT_GROUPS {
                        cols.val_addrs[g] = instr.val_addrs[EXT_DOT_PRODUCT_GROUPS * i + g];
                    }
                    cols.acc_addr = instr.acc_addr;
                    cols.mult = if i == n_rows - 1 { instr.mult } else { F::ZERO };
                    rows.push(row);
                }
            });

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_EXT_DOT_PRODUCT_PREPROCESSED_COLS,
        );
        let log_size = program.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_EXT_DOT_PRODUCT_PREPROCESSED_COLS, F>(
            &mut trace.values,
            log_size,
        );
        Some(trace)
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let rows = input
            .ext_dot_product_events
            .iter()
            .map(|event: &ExtDotProductEvent<F>| {
                let mut row = [F::ZERO; NUM_EXT_DOT_PRODUCT_COLS];
                let cols: &mut ExtDotProductCols<F> = row.as_mut_slice().borrow_mut();
                cols.mus = event.mus;
                cols.vals = event.vals;
                cols.acc = event.acc;
                row
            })
            .collect::<Vec<_>>();

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_EXT_DOT_PRODUCT_COLS,
        );
        let log_rows = input.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_EXT_DOT_PRODUCT_COLS, F>(&mut trace.values, log_rows);
        trace
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }
}
