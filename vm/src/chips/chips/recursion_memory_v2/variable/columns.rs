use super::super::MemoryAccessCols;
use crate::recursion_v2::air::Block;
use pico_derive::AlignedBorrow;

pub const NUM_VAR_MEM_ENTRIES_PER_ROW: usize = 2;

pub const NUM_MEM_INIT_COLS: usize = core::mem::size_of::<MemoryCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryCols<F: Copy> {
    pub values: [Block<F>; NUM_VAR_MEM_ENTRIES_PER_ROW],
}

pub const NUM_MEM_PREPROCESSED_INIT_COLS: usize =
    core::mem::size_of::<MemoryPreprocessedCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryPreprocessedCols<F: Copy> {
    pub accesses: [MemoryAccessCols<F>; NUM_VAR_MEM_ENTRIES_PER_ROW],
}
