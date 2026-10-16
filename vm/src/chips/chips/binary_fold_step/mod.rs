use std::marker::PhantomData;

mod columns;
mod constraints;
#[cfg(test)]
mod tests;
mod traces;

pub use columns::*;

/// One WHIR binary k-fold butterfly step in a single row.
///
/// Verifies out = v_lo + (alpha - tw*xi) * (v_lo - v_hi) * (inv_tw * xi_inv / 2),
/// the per-element update of the WHIR verifier's `binary_k_fold` (tw/inv_tw are
/// the twiddle constants, xi/xi_inv the successive squarings of the query root).
/// Two auxiliary columns keep every constraint within max degree 4:
///   amt = alpha - tw*xi,   tih = inv_tw * xi_inv * (1/2).
///
/// Replaces the 8-instruction (3 BaseAlu + 5 ExtAlu) chain per fold pair.
#[derive(Default)]
pub struct BinaryFoldStepChip<F> {
    pub _phantom: PhantomData<fn(F) -> F>,
}
