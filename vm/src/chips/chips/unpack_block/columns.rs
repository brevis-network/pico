use crate::{
    chips::chips::recursion_memory::MemoryAccessCols,
    compiler::recursion::{ir::Block, types::Address},
};
use pico_derive::AlignedBorrow;

pub const NUM_UNPACK_BLOCK_COLS: usize = core::mem::size_of::<UnpackBlockCols<u8>>();
pub const NUM_UNPACK_BLOCK_PREPROCESSED_COLS: usize =
    core::mem::size_of::<UnpackBlockPreprocessedCols<u8>>();

/// Preprocessed columns: input address + liveness flag + per-lane output accesses.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct UnpackBlockPreprocessedCols<F: Copy> {
    pub is_real: F,
    pub in_addr: Address<F>,
    pub out: [MemoryAccessCols<F>; 4],
}

/// Main columns: the unpacked Block value.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct UnpackBlockCols<F: Copy> {
    pub val: Block<F>,
}
