use std::marker::PhantomData;

mod columns;
mod constraints;
#[cfg(test)]
mod tests;
mod traces;

pub use columns::*;

/// Extension-field dot product with a row-chained running accumulator.
///
/// One ExtDotProduct instruction spans `len` trace rows (one per element) and
/// binds acc_final = sum_i mu[i] * val[i]:
///   - the first row of a segment starts the accumulator: acc = mu * val;
///   - subsequent rows accumulate: acc = prev_acc + mu * val;
///   - the last row (is_end) writes acc to memory with the backfilled mult.
///
/// Segments are delimited by the preprocessed `is_end` flag (same layout
/// mechanics as BatchFRIChip).
///
/// Used for the WHIR round-0 codeword fold `sum_c mu_pow[c] * opened_row[c]`,
/// replacing 2 ExtAlu instructions per element with a single instruction per
/// dot product.
#[derive(Default)]
pub struct ExtDotProductChip<F> {
    pub _phantom: PhantomData<fn(F) -> F>,
}
