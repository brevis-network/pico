use crate::{compiler::recursion::types::Address, primitives::consts::PACK_BLOCK_DATAPAR};
use pico_derive::AlignedBorrow;

pub const NUM_PACK_BLOCK_COLS: usize = core::mem::size_of::<PackBlockCols<u8>>();
pub const NUM_PACK_BLOCK_PREPROCESSED_COLS: usize =
    core::mem::size_of::<PackBlockPreprocessedCols<u8>>();

/// One pack operation's preprocessed data.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct PackBlockPreprocessedValueCols<F: Copy> {
    pub is_real: F,
    pub in_addrs: [Address<F>; 4],
    pub out_addr: Address<F>,
    pub mult: F,
}

/// Preprocessed columns: DATAPAR independent pack operations per row.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct PackBlockPreprocessedCols<F: Copy> {
    pub values: [PackBlockPreprocessedValueCols<F>; PACK_BLOCK_DATAPAR],
}

/// Main columns: the packed lanes of each operation.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct PackBlockCols<F: Copy> {
    pub values: [[F; 4]; PACK_BLOCK_DATAPAR],
}
