use crate::compiler::recursion::{ir::Block, types::Address};
use pico_derive::AlignedBorrow;

pub const NUM_LAGRANGE_EVAL_D2_COLS: usize = core::mem::size_of::<LagrangeEvalD2Cols<u8>>();
pub const NUM_LAGRANGE_EVAL_D2_PREPROCESSED_COLS: usize =
    core::mem::size_of::<LagrangeEvalD2PreprocessedCols<u8>>();

/// Preprocessed columns: memory addresses for inputs/output + liveness flag.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct LagrangeEvalD2PreprocessedCols<F: Copy> {
    pub is_real: F,
    pub claim_addr: Address<F>,
    pub s1_addr: Address<F>,
    pub s2_addr: Address<F>,
    pub r_addr: Address<F>,
    pub next_claim_addr: Address<F>,
    /// Multiplicity for writing next_claim.
    pub mult: F,
}

/// Main columns: the EF values for the round inputs and the folded output.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct LagrangeEvalD2Cols<F: Copy> {
    pub claim: Block<F>,
    pub s1: Block<F>,
    pub s2: Block<F>,
    pub r: Block<F>,
    pub next_claim: Block<F>,
}
