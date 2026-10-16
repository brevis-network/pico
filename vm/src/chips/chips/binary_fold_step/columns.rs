use crate::compiler::recursion::{ir::Block, types::Address};
use pico_derive::AlignedBorrow;

pub const NUM_BINARY_FOLD_STEP_COLS: usize = core::mem::size_of::<BinaryFoldStepCols<u8>>();
pub const NUM_BINARY_FOLD_STEP_PREPROCESSED_COLS: usize =
    core::mem::size_of::<BinaryFoldStepPreprocessedCols<u8>>();

/// Preprocessed columns: memory addresses + liveness flag.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct BinaryFoldStepPreprocessedCols<F: Copy> {
    pub is_real: F,
    pub tw_addr: Address<F>,
    pub xi_addr: Address<F>,
    pub inv_tw_addr: Address<F>,
    pub xi_inv_addr: Address<F>,
    pub alpha_addr: Address<F>,
    pub v_lo_addr: Address<F>,
    pub v_hi_addr: Address<F>,
    pub out_addr: Address<F>,
    /// Multiplicity for writing out.
    pub mult: F,
}

/// Main columns: inputs, two degree-splitting helpers, and the output.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct BinaryFoldStepCols<F: Copy> {
    pub tw: F,
    pub xi: F,
    pub inv_tw: F,
    pub xi_inv: F,
    pub alpha: Block<F>,
    pub v_lo: Block<F>,
    pub v_hi: Block<F>,
    /// Auxiliary: amt = alpha - tw * xi.
    pub amt: Block<F>,
    /// Auxiliary: tih = inv_tw * xi_inv * (1/2).
    pub tih: F,
    pub out: Block<F>,
}
