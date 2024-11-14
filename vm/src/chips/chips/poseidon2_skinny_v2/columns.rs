use super::utils::{NUM_INTERNAL_ROUNDS, WIDTH};
use crate::chips::{chips::recursion_memory_v2::MemoryAccessCols, utils::indices_arr};
use pico_derive::AlignedBorrow;
use std::mem::{size_of, transmute};

pub const NUM_POSEIDON2_COLS: usize = size_of::<Poseidon2Cols<u8>>();
pub const NUM_POSEIDON2_PREPROCESSED_COLS: usize = size_of::<Poseidon2PreprocessedCols<u8>>();

pub const POSEIDON2_DEGREE9_COL_MAP: Poseidon2Cols<usize> = make_col_map_degree9();

const fn make_col_map_degree9() -> Poseidon2Cols<usize> {
    let indices_arr = indices_arr::<NUM_POSEIDON2_COLS>();
    unsafe { transmute::<[usize; NUM_POSEIDON2_COLS], Poseidon2Cols<usize>>(indices_arr) }
}

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2Cols<T: Copy> {
    pub state_var: [T; WIDTH],
    pub internal_rounds_s0: [T; NUM_INTERNAL_ROUNDS - 1],
}

#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Poseidon2PreprocessedCols<T: Copy> {
    pub memory_preprocessed: [MemoryAccessCols<T>; WIDTH],
    pub round_counters_preprocessed: RoundCountersPreprocessedCols<T>,
}

#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct RoundCountersPreprocessedCols<T: Copy> {
    pub is_input_round: T,
    pub is_external_round: T,
    pub is_internal_round: T,
    pub round_constants: [T; WIDTH],
}
