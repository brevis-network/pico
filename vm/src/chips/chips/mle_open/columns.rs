use crate::compiler::recursion::{ir::Block, types::Address};
use pico_derive::AlignedBorrow;

pub const NUM_MLE_OPEN_COLS: usize = core::mem::size_of::<MleOpenCols<u8>>();
pub const NUM_MLE_OPEN_PREPROCESSED_COLS: usize =
    core::mem::size_of::<MleOpenPreprocessedCols<u8>>();

/// Preprocessed columns: addresses, AIR/column identifiers, liveness flag.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct MleOpenPreprocessedCols<F: Copy> {
    pub is_real: F,
    /// Encoded air_id and col_id (air_id << 16 | col_id).
    pub col_ref: F,
    pub opening_value_addr: Address<F>,
}

/// Main columns: the MLE opening value being verified.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct MleOpenCols<F: Copy> {
    /// The claimed MLE opening value for the (air_id, col_id) column at xi.
    pub opening_value: Block<F>,
}
