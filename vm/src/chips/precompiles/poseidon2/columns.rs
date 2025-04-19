use std::mem::size_of;

use pico_derive::AlignedBorrow;

use crate::{
    chips::{
        chips::riscv_memory::read_write::columns::{MemoryReadCols, MemoryWriteCols},
        gadgets::poseidon2::columns::Poseidon2ValueCols,
    },
    configs::config::Poseidon2Config,
    primitives::consts::PERMUTATION_WIDTH,
};

pub const fn num_poseidon2_cols<Config: Poseidon2Config>() -> usize {
    size_of::<Poseidon2Cols<u8, Config>>()
}

#[derive(AlignedBorrow)]
#[repr(C)]
pub struct Poseidon2Cols<T, Config: Poseidon2Config> {
    pub chunk: T,
    pub clk: T,
    pub input_memory_ptr: T,
    pub input_memory: [MemoryReadCols<T>; PERMUTATION_WIDTH],

    pub output_memory_ptr: T,
    pub output_memory: [MemoryWriteCols<T>; PERMUTATION_WIDTH],

    // TODO: is it safe to remove state_linear_layer cols?
    pub value_cols: Poseidon2ValueCols<T, Config>,
}
