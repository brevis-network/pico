use super::super::MemoryAccessCols;
use crate::{compiler::recursion_v2::ir::Block, primitives::consts::VAR_MEM_DATAPAR};
use pico_derive::AlignedBorrow;

pub const NUM_MEM_INIT_COLS: usize = core::mem::size_of::<MemoryCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryCols<F: Copy> {
    pub values: [Block<F>; VAR_MEM_DATAPAR],
}

pub const NUM_MEM_PREPROCESSED_INIT_COLS: usize =
    core::mem::size_of::<MemoryPreprocessedCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryPreprocessedCols<F: Copy> {
    pub accesses: [MemoryAccessCols<F>; VAR_MEM_DATAPAR],
}
