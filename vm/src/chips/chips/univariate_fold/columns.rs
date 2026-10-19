use crate::{
    chips::chips::univariate_fold::MAX_COEFFS,
    compiler::recursion::{ir::Block, types::Address},
};
use pico_derive::AlignedBorrow;

pub const NUM_UNIVARIATE_FOLD_COLS: usize = core::mem::size_of::<UnivariateFoldCols<u8>>();
pub const NUM_UNIVARIATE_FOLD_PREPROCESSED_COLS: usize =
    core::mem::size_of::<UnivariateFoldPreprocessedCols<u8>>();

/// Preprocessed columns: addresses, active coefficient count, liveness flag.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct UnivariateFoldPreprocessedCols<F: Copy> {
    pub is_real: F,
    /// Number of active coefficients (≤ MAX_COEFFS).
    pub num_coeffs: F,
    /// Addresses of the coefficient array (addresses for coeffs[0..MAX_COEFFS]).
    pub coeffs_addrs: [Address<F>; MAX_COEFFS],
    pub claimed_sum_addr: Address<F>,
    pub r_addr: Address<F>,
    pub next_sum_addr: Address<F>,
    /// Multiplicity for writing next_sum.
    pub mult: F,
}

/// Main columns: the coefficient EF values, the claim, the challenge, and the output.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct UnivariateFoldCols<F: Copy> {
    /// Polynomial coefficients in ascending degree order (padded to MAX_COEFFS).
    pub coeffs: [Block<F>; MAX_COEFFS],
    pub claimed_sum: Block<F>,
    pub r: Block<F>,
    pub next_sum: Block<F>,
    /// Auxiliary: poly(0) and poly(1) for the sumcheck constraint.
    pub eval_at_0: Block<F>,
    pub eval_at_1: Block<F>,
    /// Horner accumulator for constraining next_sum = p(r).
    /// acc[0] = coeffs[MAX_COEFFS-1] (highest-degree coeff).
    /// acc[i] = acc[i-1] * r + coeffs[MAX_COEFFS-1-i] for i in 1..(MAX_COEFFS-1).
    /// Final: next_sum = acc[MAX_COEFFS-2] * r + coeffs[0] (enforced as a constraint).
    pub acc: [Block<F>; MAX_COEFFS - 1],
}
