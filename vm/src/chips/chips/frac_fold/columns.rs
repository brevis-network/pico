use crate::compiler::recursion::{ir::Block, types::Address};
use pico_derive::AlignedBorrow;

pub const NUM_FRAC_FOLD_COLS: usize = core::mem::size_of::<FracFoldCols<u8>>();
pub const NUM_FRAC_FOLD_PREPROCESSED_COLS: usize =
    core::mem::size_of::<FracFoldPreprocessedCols<u8>>();

/// Preprocessed columns: memory addresses for inputs/outputs + liveness flag.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct FracFoldPreprocessedCols<F: Copy> {
    pub is_real: F,
    pub in_p1_addr: Address<F>,
    pub in_q1_addr: Address<F>,
    pub in_p2_addr: Address<F>,
    pub in_q2_addr: Address<F>,
    pub out_p_addr: Address<F>,
    pub out_q_addr: Address<F>,
    /// Multiplicity for writing output (typically 1 when real).
    pub mult: F,
}

/// Main columns: the actual EF values for each fraction and the output.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct FracFoldCols<F: Copy> {
    pub p1: Block<F>,
    pub q1: Block<F>,
    pub p2: Block<F>,
    pub q2: Block<F>,
    pub out_p: Block<F>,
    pub out_q: Block<F>,
}
