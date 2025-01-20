use super::super::MemoryAccessCols;
use crate::{compiler::recursion_v2::ir::Block, primitives::consts::CONST_MEM_DATAPAR};
use pico_derive::AlignedBorrow;

pub const NUM_MEM_INIT_COLS: usize = core::mem::size_of::<MemoryCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryCols<F: Copy> {
    // At least one column is required, otherwise a bunch of things break.
    _nothing: F,
}

pub const NUM_MEM_PREPROCESSED_INIT_COLS: usize =
    core::mem::size_of::<MemoryPreprocessedCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryPreprocessedCols<F: Copy> {
    pub values_and_accesses: [(Block<F>, MemoryAccessCols<F>); CONST_MEM_DATAPAR],
}
