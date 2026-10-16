use std::marker::PhantomData;

mod columns;
mod constraints;
#[cfg(test)]
mod tests;
mod traces;

pub use columns::*;

/// Horner evaluation of a univariate polynomial with a row-chained accumulator.
///
/// One HornerEval instruction spans `len` trace rows, one per coefficient in
/// EVALUATION order (highest degree first), and binds out = P(x):
///   - the first row of a segment starts the accumulator: acc = coeff;
///   - subsequent rows chain: acc = prev_acc * x + coeff;
///   - x is read from memory only on the segment-start row (is_start) and
///     copied row-to-row inside the segment (next.x == x), so an n-coefficient
///     evaluation costs one x read instead of n;
///   - the last row (is_end) writes acc to memory with the backfilled mult.
///
/// Used for the WHIR final-polynomial evaluations (one 2^log_final_poly_len
/// Horner per query) and the BatchConstraint round-0 claim, replacing
/// 2 ExtAlu instructions per coefficient with a single instruction per
/// evaluation.
#[derive(Default)]
pub struct HornerEvalChip<F> {
    pub _phantom: PhantomData<fn(F) -> F>,
}
