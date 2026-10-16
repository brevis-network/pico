use crate::{
    chips::chips::univariate_fold::{
        columns::{
            UnivariateFoldCols, UnivariateFoldPreprocessedCols, NUM_UNIVARIATE_FOLD_COLS,
            NUM_UNIVARIATE_FOLD_PREPROCESSED_COLS,
        },
        UnivariateFoldChip, MAX_COEFFS,
    },
    compiler::recursion::{
        instruction::Instruction,
        program::RecursionProgram,
        types::{UnivariateFoldEvent, UnivariateFoldInstr},
    },
    emulator::recursion::emulator::RecursionRecord,
    machine::{
        chip::{ChipBehavior, PreprocessedRows},
        utils::pad_to_power_of_two,
    },
    primitives::consts::EXTENSION_DEGREE,
};
use p3_air::BaseAir;
use p3_field::{extension::BinomiallyExtendable, Field, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::BorrowMut;

impl<F> BaseAir<F> for UnivariateFoldChip<F> {
    fn width(&self) -> usize {
        NUM_UNIVARIATE_FOLD_COLS
    }
}

impl<F: PrimeField32 + Field + BinomiallyExtendable<EXTENSION_DEGREE>> ChipBehavior<F>
    for UnivariateFoldChip<F>
{
    type Record = RecursionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "UnivariateFold".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_UNIVARIATE_FOLD_PREPROCESSED_COLS
    }

    fn preprocessed_rows(&self, program: &Self::Program) -> Option<PreprocessedRows> {
        Some(PreprocessedRows::Unpadded(
            program.prep_row_counts().univariate_fold,
        ))
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let mut rows: Vec<[F; NUM_UNIVARIATE_FOLD_PREPROCESSED_COLS]> = Vec::new();

        program
            .instructions
            .iter()
            .filter_map(|instr| {
                if let Instruction::UnivariateFold(i) = instr {
                    Some(i.as_ref())
                } else {
                    None
                }
            })
            .for_each(|instr: &UnivariateFoldInstr<F>| {
                let mut row = [F::ZERO; NUM_UNIVARIATE_FOLD_PREPROCESSED_COLS];
                let cols: &mut UnivariateFoldPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                cols.is_real = F::ONE;
                cols.num_coeffs = F::from_usize(instr.coeffs_addrs.len());
                for (dst, src) in cols.coeffs_addrs.iter_mut().zip(instr.coeffs_addrs.iter()) {
                    *dst = *src;
                }
                cols.claimed_sum_addr = instr.claimed_sum_addr;
                cols.r_addr = instr.r_addr;
                cols.next_sum_addr = instr.next_sum_addr;
                cols.mult = instr.mult;
                rows.push(row);
            });

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_UNIVARIATE_FOLD_PREPROCESSED_COLS,
        );
        let log_size = program.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_UNIVARIATE_FOLD_PREPROCESSED_COLS, F>(
            &mut trace.values,
            log_size,
        );
        Some(trace)
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        let rows = input
            .univariate_fold_events
            .iter()
            .map(|event: &UnivariateFoldEvent<F>| {
                let mut row = [F::ZERO; NUM_UNIVARIATE_FOLD_COLS];
                let cols: &mut UnivariateFoldCols<F> = row.as_mut_slice().borrow_mut();

                // Fill coefficients (padded to MAX_COEFFS).
                for (dst, src) in cols.coeffs.iter_mut().zip(event.coeffs.iter()) {
                    *dst = *src;
                }

                cols.claimed_sum = event.claimed_sum;
                cols.r = event.r;
                cols.next_sum = event.next_sum;

                // eval_at_0 = coeffs[0].
                cols.eval_at_0 = event.coeffs.first().copied().unwrap_or_default();

                // eval_at_1 = coeffs[omega_order] where omega_order = (MAX_COEFFS+1)/2 = 16.
                let omega_order = MAX_COEFFS.div_ceil(2);
                cols.eval_at_1 = event.coeffs.get(omega_order).copied().unwrap_or_default();

                // Horner accumulator: acc[0] = coeffs[MAX_COEFFS-1],
                // acc[i] = acc[i-1] * r + coeffs[MAX_COEFFS-1-i] for i in 1..(MAX_COEFFS-1).
                // Matches the Horner constraints in constraints.rs (next_sum = p(r)).
                {
                    // EF multiplication over [F; 4] using binomial extension with W.
                    let w = <F as BinomiallyExtendable<EXTENSION_DEGREE>>::W;
                    let ef_mul = |a: [F; 4], b: [F; 4]| -> [F; 4] {
                        [
                            a[0] * b[0] + w * (a[1] * b[3] + a[2] * b[2] + a[3] * b[1]),
                            a[0] * b[1] + a[1] * b[0] + w * (a[2] * b[3] + a[3] * b[2]),
                            a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + w * a[3] * b[3],
                            a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0],
                        ]
                    };
                    let ef_add = |a: [F; 4], b: [F; 4]| -> [F; 4] {
                        [a[0] + b[0], a[1] + b[1], a[2] + b[2], a[3] + b[3]]
                    };
                    let r_arr = event.r.0;
                    // acc[0] = coeffs[MAX_COEFFS-1]
                    let c_top = event
                        .coeffs
                        .get(MAX_COEFFS - 1)
                        .copied()
                        .unwrap_or_default();
                    cols.acc[0].0 = c_top.0;
                    // acc[i] = acc[i-1] * r + coeffs[MAX_COEFFS-1-i]
                    for i in 1..(MAX_COEFFS - 1) {
                        let prev = cols.acc[i - 1].0;
                        let coeff = event
                            .coeffs
                            .get(MAX_COEFFS - 1 - i)
                            .copied()
                            .unwrap_or_default();
                        cols.acc[i].0 = ef_add(ef_mul(prev, r_arr), coeff.0);
                    }
                }

                row
            })
            .collect::<Vec<_>>();

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_UNIVARIATE_FOLD_COLS,
        );
        let log_rows = input.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_UNIVARIATE_FOLD_COLS, F>(&mut trace.values, log_rows);
        trace
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }
}
