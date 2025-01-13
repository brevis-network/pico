use std::mem::size_of;

use pico_derive::AlignedBorrow;

use crate::{
    chips::chips::riscv_memory::read_write::columns::{MemoryReadCols, MemoryWriteCols},
    primitives::consts::{
        BABYBEAR_NUM_EXTERNAL_ROUNDS, BABYBEAR_NUM_INTERNAL_ROUNDS, KOALABEAR_NUM_EXTERNAL_ROUNDS,
        KOALABEAR_NUM_INTERNAL_ROUNDS, MERSENNE31_NUM_EXTERNAL_ROUNDS,
        MERSENNE31_NUM_INTERNAL_ROUNDS, PERMUTATION_WIDTH,
    },
};

pub const BABYBEAR_NUM_POSEIDON2_COLS: usize = size_of::<
    Poseidon2Cols<u8, { BABYBEAR_NUM_EXTERNAL_ROUNDS / 2 }, BABYBEAR_NUM_INTERNAL_ROUNDS>,
>();

pub const KOALABEAR_NUM_POSEIDON2_COLS: usize = size_of::<
    Poseidon2Cols<u8, { KOALABEAR_NUM_EXTERNAL_ROUNDS / 2 }, KOALABEAR_NUM_INTERNAL_ROUNDS>,
>();

pub const MERSENNE31_NUM_POSEIDON2_COLS: usize = size_of::<
    Poseidon2Cols<u8, { MERSENNE31_NUM_EXTERNAL_ROUNDS / 2 }, MERSENNE31_NUM_INTERNAL_ROUNDS>,
>();

#[derive(AlignedBorrow)]
#[repr(C)]
pub struct Poseidon2Cols<T, const HALF_EXTERNAL_ROUNDS: usize, const NUM_INTERNAL_ROUNDS: usize> {
    pub chunk: T,
    pub clk: T,
    pub nonce: T,
    pub input_memory_ptr: T,
    pub input_memory: [MemoryReadCols<T>; PERMUTATION_WIDTH],

    pub output_memory_ptr: T,
    pub output_memory: [MemoryWriteCols<T>; PERMUTATION_WIDTH],

    pub inputs: [T; PERMUTATION_WIDTH],
    pub state_linear_layer: [T; PERMUTATION_WIDTH],

    /// Beginning Full Rounds
    pub beginning_full_rounds: [FullRound<T>; HALF_EXTERNAL_ROUNDS],

    /// Partial Rounds
    pub partial_rounds: [PartialRound<T>; NUM_INTERNAL_ROUNDS],

    /// Ending Full Rounds
    pub ending_full_rounds: [FullRound<T>; HALF_EXTERNAL_ROUNDS],

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
