use std::marker::PhantomData;

mod columns;
mod constraints;
#[cfg(test)]
mod tests;
mod traces;

pub use columns::*;

/// High-degree univariate sumcheck round verifier (coefficient form).
///
/// Verifies poly(0)+poly(1)==claimed_sum and computes next_sum = poly(r)
/// using Horner's method.  Shared by BatchConstraint round-0 (univariate skip)
/// and Stacking round-0; the polynomial degree is encoded in `num_coeffs`.
///
/// Each row holds `MAX_COEFFS` extension-field coefficient slots; unused slots
/// are padded with zero.  The actual number of coefficients is fixed per
/// instruction (stored in the preprocessed trace as `num_coeffs`).
#[derive(Default)]
pub struct UnivariateFoldChip<F> {
    pub _phantom: PhantomData<fn(F) -> F>,
}

/// Maximum number of polynomial coefficients supported per row.
/// Sized for l_skip=4: 2*(2^4-1)+1 = 31.  Increase if needed.
pub const MAX_COEFFS: usize = 31;
