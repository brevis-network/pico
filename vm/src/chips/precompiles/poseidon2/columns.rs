use std::mem::size_of;

use pico_derive::AlignedBorrow;

use crate::chips::chips::{
    poseidon2_wide_v2::{NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS, WIDTH},
    riscv_memory::read_write::columns::{MemoryReadCols, MemoryWriteCols},
};

pub const NUM_POSEIDON2_COLS: usize = size_of::<Poseidon2Cols<u8>>();

#[derive(AlignedBorrow)]
#[repr(C)]
pub struct Poseidon2Cols<T> {
    pub chunk: T,
    pub clk: T,
    pub nonce: T,
    pub input_memory_ptr: T,
    pub input_memory: [MemoryReadCols<T>; WIDTH],

    pub output_memory_ptr: T,
    pub output_memory: [MemoryWriteCols<T>; WIDTH],

    pub inputs: [T; WIDTH],
    pub state_linear_layer: [T; WIDTH],

    /// Beginning Full Rounds
    pub beginning_full_rounds: [FullRound<T>; NUM_EXTERNAL_ROUNDS / 2],

    /// Partial Rounds
    pub partial_rounds: [PartialRound<T>; NUM_INTERNAL_ROUNDS],

    /// Ending Full Rounds
    pub ending_full_rounds: [FullRound<T>; NUM_EXTERNAL_ROUNDS / 2],

    pub is_real: T,
}

/// Full round columns.
#[repr(C)]
pub struct FullRound<T> {
    pub sbox_x3: [T; WIDTH],
    pub sbox_x7: [T; WIDTH],
    pub post: [T; WIDTH],
}

/// Partial round columns.
#[repr(C)]
pub struct PartialRound<T> {
    pub sbox_x3: T,
    pub sbox_x7: T,
    pub post: [T; WIDTH],
}
