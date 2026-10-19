use crate::compiler::recursion::{ir::Block, types::Address};
use pico_derive::AlignedBorrow;

pub const NUM_ASSERT_ZERO_EXT_COLS: usize = core::mem::size_of::<AssertZeroExtCols<u8>>();
pub const NUM_ASSERT_ZERO_EXT_PREPROCESSED_COLS: usize =
    core::mem::size_of::<AssertZeroExtPreprocessedCols<u8>>();

/// Preprocessed columns: address and liveness flag.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct AssertZeroExtPreprocessedCols<F: Copy> {
    pub is_real: F,
    pub addr: Address<F>,
}

/// Main columns: the extension-field value that must be zero.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct AssertZeroExtCols<F: Copy> {
    pub val: Block<F>,
}
