use crate::{
    chips::chips::horner_eval::{
        columns::{
            HornerEvalCols, HornerEvalPreprocessedCols, NUM_HORNER_EVAL_COLS,
            NUM_HORNER_EVAL_PREPROCESSED_COLS,
        },
        HornerEvalChip,
    },
    compiler::recursion::{
        instruction::Instruction,
        ir::Block,
        program::RecursionProgram,
        types::{HornerEvalEvent, HornerEvalInstr},
    },
    emulator::recursion::emulator::RecursionRecord,
    machine::{
        chip::{ChipBehavior, PreprocessedRows},
        utils::pad_to_power_of_two,
    },
    primitives::consts::{EXTENSION_DEGREE, HORNER_EVAL_DATAPAR},
};
use p3_air::BaseAir;
use p3_field::{extension::BinomiallyExtendable, Field, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use std::borrow::BorrowMut;

impl<F> BaseAir<F> for HornerEvalChip<F> {
    fn width(&self) -> usize {
        NUM_HORNER_EVAL_COLS
    }
}

impl<F: PrimeField32 + Field + BinomiallyExtendable<EXTENSION_DEGREE>> ChipBehavior<F>
    for HornerEvalChip<F>
{
    type Record = RecursionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "HornerEval".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_HORNER_EVAL_PREPROCESSED_COLS
    }

    fn preprocessed_rows(&self, program: &Self::Program) -> Option<PreprocessedRows> {
        Some(PreprocessedRows::Unpadded(
            program.prep_row_counts().horner_eval,
        ))
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let mut rows: Vec<[F; NUM_HORNER_EVAL_PREPROCESSED_COLS]> = Vec::new();

        program
            .instructions
            .iter()
            .filter_map(|instruction| {
                if let Instruction::HornerEval(instr) = instruction {
                    Some(instr.as_ref())
                } else {
                    None
                }
            })
            .for_each(|instr: &HornerEvalInstr<F>| {
                let len = instr.coeff_addrs.len();
                // The lowering front-pads the coefficient vector to a DATAPAR multiple.
                debug_assert_eq!(len % HORNER_EVAL_DATAPAR, 0);
                let n_rows = len / HORNER_EVAL_DATAPAR;
                for i in 0..n_rows {
                    let mut row = [F::ZERO; NUM_HORNER_EVAL_PREPROCESSED_COLS];
                    let cols: &mut HornerEvalPreprocessedCols<F> = row.as_mut_slice().borrow_mut();
                    cols.is_real = F::ONE;
                    cols.is_start = F::from_bool(i == 0);
                    cols.is_end = F::from_bool(i == n_rows - 1);
                    for j in 0..HORNER_EVAL_DATAPAR {
                        cols.coeff_addrs[j] = instr.coeff_addrs[HORNER_EVAL_DATAPAR * i + j];
                    }
                    cols.x_addr = instr.x_addr;
                    cols.out_addr = instr.out_addr;
                    cols.mult = if i == n_rows - 1 { instr.mult } else { F::ZERO };
                    rows.push(row);
                }
            });

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_HORNER_EVAL_PREPROCESSED_COLS,
        );
        let log_size = program.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_HORNER_EVAL_PREPROCESSED_COLS, F>(&mut trace.values, log_size);
        Some(trace)
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        // EF multiplication over [F; 4] (same helper as univariate_fold tracegen).
        let w = <F as BinomiallyExtendable<EXTENSION_DEGREE>>::W;
        let ef_mul = |a: [F; 4], b: [F; 4]| -> [F; 4] {
            [
                a[0] * b[0] + w * (a[1] * b[3] + a[2] * b[2] + a[3] * b[1]),
                a[0] * b[1] + a[1] * b[0] + w * (a[2] * b[3] + a[3] * b[2]),
                a[0] * b[2] + a[1] * b[1] + a[2] * b[0] + w * a[3] * b[3],
                a[0] * b[3] + a[1] * b[2] + a[2] * b[1] + a[3] * b[0],
            ]
        };

        let rows = input
            .horner_eval_events
            .iter()
            .map(|event: &HornerEvalEvent<F>| {
                let mut row = [F::ZERO; NUM_HORNER_EVAL_COLS];
                let cols: &mut HornerEvalCols<F> = row.as_mut_slice().borrow_mut();
                cols.coeffs = event.coeffs;
                cols.x = event.x;
                let x2 = ef_mul(event.x.0, event.x.0);
                cols.x2 = Block(x2);
                cols.x3 = Block(ef_mul(x2, event.x.0));
                cols.x4 = Block(ef_mul(x2, x2));
                cols.acc = event.acc;
                row
            })
            .collect::<Vec<_>>();

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_HORNER_EVAL_COLS,
        );
        let log_rows = input.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_HORNER_EVAL_COLS, F>(&mut trace.values, log_rows);
        trace
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }
}
