use crate::{
    chips::chips::gkr_sumcheck_round::{
        columns::{
            GkrSumcheckRoundCols, GkrSumcheckRoundPreprocessedCols, NUM_GKR_SUMCHECK_ROUND_COLS,
            NUM_GKR_SUMCHECK_ROUND_PREPROCESSED_COLS,
        },
        GkrSumcheckRoundChip,
    },
    compiler::recursion::{
        instruction::Instruction,
        ir::Block,
        program::RecursionProgram,
        types::{GkrSumcheckRoundEvent, GkrSumcheckRoundInstr},
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

impl<F> BaseAir<F> for GkrSumcheckRoundChip<F> {
    fn width(&self) -> usize {
        NUM_GKR_SUMCHECK_ROUND_COLS
    }
}

impl<F: PrimeField32 + Field + BinomiallyExtendable<EXTENSION_DEGREE>> ChipBehavior<F>
    for GkrSumcheckRoundChip<F>
{
    type Record = RecursionRecord<F>;
    type Program = RecursionProgram<F>;

    fn name(&self) -> String {
        "GkrSumcheckRound".to_string()
    }

    fn preprocessed_width(&self) -> usize {
        NUM_GKR_SUMCHECK_ROUND_PREPROCESSED_COLS
    }

    fn preprocessed_rows(&self, program: &Self::Program) -> Option<PreprocessedRows> {
        Some(PreprocessedRows::Unpadded(
            program.prep_row_counts().gkr_sumcheck_round,
        ))
    }

    fn generate_preprocessed(&self, program: &Self::Program) -> Option<RowMajorMatrix<F>> {
        let mut rows: Vec<[F; NUM_GKR_SUMCHECK_ROUND_PREPROCESSED_COLS]> = Vec::new();

        program
            .instructions
            .iter()
            .filter_map(|instr| {
                if let Instruction::GkrSumcheckRound(i) = instr {
                    Some(i.as_ref())
                } else {
                    None
                }
            })
            .for_each(|instr: &GkrSumcheckRoundInstr<F>| {
                let mut row = [F::ZERO; NUM_GKR_SUMCHECK_ROUND_PREPROCESSED_COLS];
                let cols: &mut GkrSumcheckRoundPreprocessedCols<F> =
                    row.as_mut_slice().borrow_mut();
                cols.is_real = F::ONE;
                cols.claim_addr = instr.claim_addr;
                cols.s1_addr = instr.s1_addr;
                cols.s2_addr = instr.s2_addr;
                cols.s3_addr = instr.s3_addr;
                cols.r_addr = instr.r_addr;
                cols.xi_addr = instr.xi_addr;
                cols.eq_in_addr = instr.eq_in_addr;
                cols.next_claim_addr = instr.next_claim_addr;
                cols.eq_out_addr = instr.eq_out_addr;
                cols.mult_next = instr.mult_next;
                cols.mult_eq = instr.mult_eq;
                rows.push(row);
            });

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_GKR_SUMCHECK_ROUND_PREPROCESSED_COLS,
        );
        let log_size = program.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_GKR_SUMCHECK_ROUND_PREPROCESSED_COLS, F>(
            &mut trace.values,
            log_size,
        );
        Some(trace)
    }

    fn generate_main(&self, input: &Self::Record, _: &mut Self::Record) -> RowMajorMatrix<F> {
        // EF multiplication over [F; 4] using the binomial extension with W
        // (same helper as univariate_fold's Horner ladder tracegen).
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
            .gkr_sumcheck_round_events
            .iter()
            .map(|event: &GkrSumcheckRoundEvent<F>| {
                let mut row = [F::ZERO; NUM_GKR_SUMCHECK_ROUND_COLS];
                let cols: &mut GkrSumcheckRoundCols<F> = row.as_mut_slice().borrow_mut();
                cols.claim = event.claim;
                cols.s1 = event.s1;
                cols.s2 = event.s2;
                cols.s3 = event.s3;
                cols.r = event.r;
                cols.xi = event.xi;
                cols.eq_in = event.eq_in;
                cols.r_sq = Block(ef_mul(event.r.0, event.r.0));
                cols.next_claim = event.next_claim;
                cols.eq_out = event.eq_out;
                row
            })
            .collect::<Vec<_>>();

        let mut trace = RowMajorMatrix::new(
            rows.into_iter().flatten().collect::<Vec<_>>(),
            NUM_GKR_SUMCHECK_ROUND_COLS,
        );
        let log_rows = input.fixed_log2_rows(&self.name());
        pad_to_power_of_two::<NUM_GKR_SUMCHECK_ROUND_COLS, F>(&mut trace.values, log_rows);
        trace
    }

    fn is_active(&self, _record: &Self::Record) -> bool {
        true
    }
}
