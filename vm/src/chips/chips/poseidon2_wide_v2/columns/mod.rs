pub mod permutation;
pub mod preprocessed;

use crate::chips::{
    chips::poseidon2_wide_v2::columns::permutation::{PermutationNoSbox, PermutationSBox},
    utils::indices_arr,
};
use std::mem::{size_of, transmute};

/// Struct for the poseidon2 chip that contains sbox columns.
pub type Poseidon2Degree3<T> = PermutationSBox<T>;

pub const NUM_POSEIDON2_DEGREE3_COLS: usize = size_of::<Poseidon2Degree3<u8>>();
pub const POSEIDON2_DEGREE3_COL_MAP: Poseidon2Degree3<usize> = make_col_map_degree3();

const fn make_col_map_degree3() -> Poseidon2Degree3<usize> {
    let indices_arr = indices_arr::<NUM_POSEIDON2_DEGREE3_COLS>();
    unsafe {
        transmute::<[usize; NUM_POSEIDON2_DEGREE3_COLS], Poseidon2Degree3<usize>>(indices_arr)
    }
}

pub type Poseidon2Degree9<T> = PermutationNoSbox<T>;

pub const NUM_POSEIDON2_DEGREE9_COLS: usize = size_of::<Poseidon2Degree9<u8>>();
pub const POSEIDON2_DEGREE9_COL_MAP: Poseidon2Degree9<usize> = make_col_map_degree9();

const fn make_col_map_degree9() -> Poseidon2Degree9<usize> {
    let indices_arr = indices_arr::<NUM_POSEIDON2_DEGREE9_COLS>();
    unsafe {
        transmute::<[usize; NUM_POSEIDON2_DEGREE9_COLS], Poseidon2Degree9<usize>>(indices_arr)
    }
}
