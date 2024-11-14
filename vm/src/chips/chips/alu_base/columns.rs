use crate::recursion_v2::types::{Address, BaseAluIo};
use pico_derive::AlignedBorrow;

pub const NUM_BASE_ALU_ENTRIES_PER_ROW: usize = 4;

pub const NUM_BASE_ALU_COLS: usize = core::mem::size_of::<BaseAluCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct BaseAluCols<F: Copy> {
    pub values: [BaseAluValueCols<F>; NUM_BASE_ALU_ENTRIES_PER_ROW],
}

pub const NUM_BASE_ALU_VALUE_COLS: usize = core::mem::size_of::<BaseAluValueCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct BaseAluValueCols<F: Copy> {
    pub vals: BaseAluIo<F>,
}

pub const NUM_BASE_ALU_PREPROCESSED_COLS: usize =
    core::mem::size_of::<BaseAluPreprocessedCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct BaseAluPreprocessedCols<F: Copy> {
    pub accesses: [BaseAluAccessCols<F>; NUM_BASE_ALU_ENTRIES_PER_ROW],
}

pub const NUM_BASE_ALU_ACCESS_COLS: usize = core::mem::size_of::<BaseAluAccessCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct BaseAluAccessCols<F: Copy> {
    pub addrs: BaseAluIo<Address<F>>,
    pub is_add: F,
    pub is_sub: F,
    pub is_mul: F,
    pub is_div: F,
    pub mult: F,
}
