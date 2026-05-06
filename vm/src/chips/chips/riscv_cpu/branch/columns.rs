use pico_derive::AlignedBorrow;
use std::mem::size_of;

pub const NUM_BRANCH_COLS: usize = size_of::<BranchCols<u8>>();

#[derive(AlignedBorrow, Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct BranchCols<T> {
    /// Whether a equals b.
    pub a_eq_b: T,

    /// Whether a is greater than b.
    pub a_gt_b: T,

    /// Whether a is less than b.
    pub a_lt_b: T,
}
