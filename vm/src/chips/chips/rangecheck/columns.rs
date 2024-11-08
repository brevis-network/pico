use core::mem::size_of;
use pico_derive::AlignedBorrow;

use super::NUM_RANGECHECK_OPS;

/// The number of main trace columns for `RangeCheckChip`.
pub const NUM_RANGECHECK_PREPROCESSED_COLS: usize = size_of::<RangeCheckPreprocessedCols<u8>>();

/// The number of multiplicity columns for `RangeCheckChip`.
pub const NUM_RANGECHECK_MULT_COLS: usize = size_of::<RangeCheckMultCols<u8>>();

#[derive(AlignedBorrow, Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct RangeCheckPreprocessedCols<T> {
    /// The value of the table entry
    pub value: T,

    /// 1 if the value is between [0, 256), 0 otherwise
    pub is_u8: T,

    /// 1 if the value is between [0, 4096), 0 otherwise
    pub is_u12: T,
}

/// For each value in the preprocessed table, a corresponding RangeCheckMultCols row tracks the
/// number of times the operation is used.
#[derive(Debug, Clone, Copy, AlignedBorrow)]
#[repr(C)]
pub struct RangeCheckMultCols<T> {
    /// Chunk number
    /// TRICKY: It's set to 0 for recursion, RiscV chunk starts from 1, so should have no conflict.
    pub chunk: T,

    /// The multiplicities of each range check operation.
    pub multiplicities: [T; NUM_RANGECHECK_OPS],
}
