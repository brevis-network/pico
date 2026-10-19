use crate::{
    compiler::recursion::{ir::Block, types::Address},
    primitives::consts::{EXT_DOT_PRODUCT_DATAPAR, EXT_DOT_PRODUCT_GROUPS},
};
use pico_derive::AlignedBorrow;

pub const NUM_EXT_DOT_PRODUCT_COLS: usize = core::mem::size_of::<ExtDotProductCols<u8>>();
pub const NUM_EXT_DOT_PRODUCT_PREPROCESSED_COLS: usize =
    core::mem::size_of::<ExtDotProductPreprocessedCols<u8>>();

/// Preprocessed columns: per-row element addresses + segment bookkeeping.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct ExtDotProductPreprocessedCols<F: Copy> {
    pub is_real: F,
    /// 1 on the last row of an instruction's segment.
    pub is_end: F,
    /// One mu address per element lane (EXTENSION_DEGREE per packed value block;
    /// padding lanes use the zero address).
    pub mu_addrs: [Address<F>; EXT_DOT_PRODUCT_DATAPAR],
    /// One PACKED value-block address per group (each block's lanes are
    /// EXTENSION_DEGREE base-field values).
    pub val_addrs: [Address<F>; EXT_DOT_PRODUCT_GROUPS],
    pub acc_addr: Address<F>,
    /// Multiplicity for writing acc (nonzero only on is_end rows).
    pub mult: F,
}

/// Main columns: EXT_DOT_PRODUCT_GROUPS packed value blocks, their per-lane mus,
/// and the running accumulator (its value AFTER folding in this row's elements).
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct ExtDotProductCols<F: Copy> {
    pub mus: [Block<F>; EXT_DOT_PRODUCT_DATAPAR],
    pub vals: [Block<F>; EXT_DOT_PRODUCT_GROUPS],
    pub acc: Block<F>,
}
