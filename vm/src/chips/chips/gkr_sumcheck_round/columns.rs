use crate::compiler::recursion::{ir::Block, types::Address};
use pico_derive::AlignedBorrow;

pub const NUM_GKR_SUMCHECK_ROUND_COLS: usize = core::mem::size_of::<GkrSumcheckRoundCols<u8>>();
pub const NUM_GKR_SUMCHECK_ROUND_PREPROCESSED_COLS: usize =
    core::mem::size_of::<GkrSumcheckRoundPreprocessedCols<u8>>();

/// Preprocessed columns: memory addresses for inputs/outputs + liveness flag.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct GkrSumcheckRoundPreprocessedCols<F: Copy> {
    pub is_real: F,
    pub claim_addr: Address<F>,
    pub s1_addr: Address<F>,
    pub s2_addr: Address<F>,
    pub s3_addr: Address<F>,
    pub r_addr: Address<F>,
    pub xi_addr: Address<F>,
    pub eq_in_addr: Address<F>,
    pub next_claim_addr: Address<F>,
    pub eq_out_addr: Address<F>,
    /// Multiplicity for writing next_claim.
    pub mult_next: F,
    /// Multiplicity for writing eq_out.
    pub mult_eq: F,
}

/// Main columns: the EF values for the round plus the r^2 helper.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct GkrSumcheckRoundCols<F: Copy> {
    pub claim: Block<F>,
    pub s1: Block<F>,
    pub s2: Block<F>,
    pub s3: Block<F>,
    pub r: Block<F>,
    pub xi: Block<F>,
    pub eq_in: Block<F>,
    /// Auxiliary: r_sq = r * r (keeps the cubic-interpolation constraint at degree 4).
    pub r_sq: Block<F>,
    pub next_claim: Block<F>,
    pub eq_out: Block<F>,
}
