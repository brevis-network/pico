use crate::{
    compiler::recursion::{ir::Block, types::Address},
    primitives::consts::{EXT_DOT_PRODUCT_DATAPAR, EXT_DOT_PRODUCT_GROUPS, PACK_LANES},
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
    /// One mu address per element lane (PACK_LANES per packed value block;
    /// padding lanes use the zero address).
    pub mu_addrs: [Address<F>; EXT_DOT_PRODUCT_DATAPAR],
    /// One PACKED value-block address per group (the first PACK_LANES lanes of
    /// each block are base-field values, the rest are zero).
    pub val_addrs: [Address<F>; EXT_DOT_PRODUCT_GROUPS],
    pub acc_addr: Address<F>,
    /// Multiplicity for writing acc (nonzero only on is_end rows).
    pub mult: F,
}

/// Main columns: the `PACK_LANES` value lanes of each of the EXT_DOT_PRODUCT_GROUPS packed
/// value blocks (their padding lanes are the constant zero on the bus and have no column), the
/// per-lane mus, and the running accumulator (its value AFTER folding in this row's elements).
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct ExtDotProductCols<F: Copy> {
    pub mus: [Block<F>; EXT_DOT_PRODUCT_DATAPAR],
    pub vals: [[F; PACK_LANES]; EXT_DOT_PRODUCT_GROUPS],
    pub acc: Block<F>,
}
