use std::mem::size_of;

use pico_derive::AlignedBorrow;

use crate::{
    chips::chips::riscv_memory::read_write::columns::{MemoryReadCols, MemoryWriteCols},
    configs::config::Poseidon2Config,
    primitives::consts::PERMUTATION_WIDTH,
};
use hybrid_array::Array;

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

    pub inputs: [T; PERMUTATION_WIDTH],
    pub state_linear_layer: [T; PERMUTATION_WIDTH],

    /// Beginning Full Rounds
    pub beginning_full_rounds: Array<FullRound<T>, Config::HalfFullRounds>,

    /// Partial Rounds
    pub partial_rounds: Array<PartialRound<T>, Config::PartialRounds>,

    /// Ending Full Rounds
    pub ending_full_rounds: Array<FullRound<T>, Config::HalfFullRounds>,

    pub is_real: T,
}

/// Full round columns.
#[repr(C)]
pub struct FullRound<T> {
    pub sbox_x3: [T; PERMUTATION_WIDTH],
    pub sbox_x7: [T; PERMUTATION_WIDTH],
    pub post: [T; PERMUTATION_WIDTH],
}

/// Partial round columns.
#[repr(C)]
pub struct PartialRound<T> {
    pub sbox_x3: T,
    pub sbox_x7: T,
    pub post: [T; PERMUTATION_WIDTH],
}
