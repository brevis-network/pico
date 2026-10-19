use crate::{
    compiler::recursion::{ir::Block, types::Address},
    primitives::consts::HORNER_EVAL_DATAPAR,
};
use pico_derive::AlignedBorrow;

pub const NUM_HORNER_EVAL_COLS: usize = core::mem::size_of::<HornerEvalCols<u8>>();
pub const NUM_HORNER_EVAL_PREPROCESSED_COLS: usize =
    core::mem::size_of::<HornerEvalPreprocessedCols<u8>>();

/// Preprocessed columns: per-row addresses + segment bookkeeping.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct HornerEvalPreprocessedCols<F: Copy> {
    pub is_real: F,
    /// 1 on the first row of an instruction's segment (x is bus-read here).
    pub is_start: F,
    /// 1 on the last row of an instruction's segment (acc is written here).
    pub is_end: F,
    /// Coefficient addresses in evaluation order (highest degree first).
    pub coeff_addrs: [Address<F>; HORNER_EVAL_DATAPAR],
    pub x_addr: Address<F>,
    pub out_addr: Address<F>,
    /// Multiplicity for writing out (nonzero only on is_end rows).
    pub mult: F,
}

/// Main columns: DATAPAR coefficients, the (segment-constant) point with its
/// power helpers, and the accumulator AFTER folding this row's coefficients.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct HornerEvalCols<F: Copy> {
    pub coeffs: [Block<F>; HORNER_EVAL_DATAPAR],
    pub x: Block<F>,
    /// x^2 (degree-splitting helper).
    pub x2: Block<F>,
    /// x^3.
    pub x3: Block<F>,
    /// x^4.
    pub x4: Block<F>,
    pub acc: Block<F>,
}
