use crate::{
    chips::{chips::recursion_memory_v2::MemoryAccessCols, utils::indices_arr},
    configs::config::Poseidon2Config,
    primitives::consts::{BabyBearConfig, KoalaBearConfig, PERMUTATION_WIDTH},
};
use hybrid_array::Array;
use pico_derive::AlignedBorrow;
use std::mem::{size_of, transmute};
use typenum::Sum;

#[derive(AlignedBorrow, Clone)]
#[repr(C)]
pub struct Poseidon2Cols<T, Config: Poseidon2Config> {
    pub state_var: [T; PERMUTATION_WIDTH],
    pub internal_rounds_s0: Array<T, Config::InternalRoundsM1>,
}

impl<T, Config> Copy for Poseidon2Cols<T, Config>
where
    T: Copy,
    Config: Poseidon2Config,
    Array<T, Config::InternalRoundsM1>: Copy,
{
}

#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Poseidon2PreprocessedCols<T: Copy> {
    pub memory_preprocessed: [MemoryAccessCols<T>; PERMUTATION_WIDTH],
    pub round_counters_preprocessed: RoundCountersPreprocessedCols<T>,
}

#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct RoundCountersPreprocessedCols<T: Copy> {
    pub is_input_round: T,
    pub is_external_round: T,
    pub is_internal_round: T,
    pub round_constants: [T; PERMUTATION_WIDTH],
}

pub const NUM_POSEIDON2_PREPROCESSED_COLS: usize = size_of::<Poseidon2PreprocessedCols<u8>>();

pub const BABYBEAR_NUM_POSEIDON2_COLS: usize = size_of::<Poseidon2Cols<u8, BabyBearConfig>>();
pub const KOALABEAR_NUM_POSEIDON2_COLS: usize = size_of::<Poseidon2Cols<u8, KoalaBearConfig>>();
pub const fn num_poseidon2_cols<Config: Poseidon2Config>() -> usize {
    size_of::<Poseidon2Cols<u8, Config>>()
}
pub type NumPoseidon2ColsGeneric<Config> =
    Sum<<Config as Poseidon2Config>::InternalRoundsM1, typenum::U16>;

pub const BABYBEAR_POSEIDON2_DEGREE9_COL_MAP: Poseidon2Cols<usize, BabyBearConfig> =
    babybear_make_col_map_degree9();
pub const KOALABEAR_POSEIDON2_DEGREE9_COL_MAP: Poseidon2Cols<usize, KoalaBearConfig> =
    koalabear_make_col_map_degree9();

const fn babybear_make_col_map_degree9() -> Poseidon2Cols<usize, BabyBearConfig> {
    let indices_arr = indices_arr::<BABYBEAR_NUM_POSEIDON2_COLS>();
    unsafe {
        transmute::<[usize; BABYBEAR_NUM_POSEIDON2_COLS], Poseidon2Cols<usize, BabyBearConfig>>(
            indices_arr,
        )
    }
}
const fn koalabear_make_col_map_degree9() -> Poseidon2Cols<usize, KoalaBearConfig> {
    let indices_arr = indices_arr::<KOALABEAR_NUM_POSEIDON2_COLS>();
    unsafe {
        transmute::<[usize; KOALABEAR_NUM_POSEIDON2_COLS], Poseidon2Cols<usize, KoalaBearConfig>>(
            indices_arr,
        )
    }
}
