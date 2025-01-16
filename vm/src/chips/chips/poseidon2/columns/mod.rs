pub mod permutation;
pub mod preprocessed;

use crate::{
    chips::{
        chips::poseidon2::columns::permutation::{PermutationNoSbox, PermutationSBox},
        utils::indices_arr,
    },
    primitives::consts::{BabyBearConfig, KoalaBearConfig},
};
use std::mem::{size_of, transmute};

// BABYBEAR_COL_MAP low degree implementations
pub const BABYBEAR_NUM_POSEIDON2_LD_COLS: usize = size_of::<PermutationSBox<u8, BabyBearConfig>>();

pub const BABYBEAR_POSEIDON2_LD_COL_MAP: PermutationSBox<usize, BabyBearConfig> =
    babybear_make_col_map_ld();

const fn babybear_make_col_map_ld() -> PermutationSBox<usize, BabyBearConfig> {
    let indices_arr = indices_arr::<BABYBEAR_NUM_POSEIDON2_LD_COLS>();
    unsafe {
        transmute::<[usize; BABYBEAR_NUM_POSEIDON2_LD_COLS], PermutationSBox<usize, BabyBearConfig>>(
            indices_arr,
        )
    }
}

// BABYBEAR_COL_MAP high degree implementations
pub const BABYBEAR_NUM_POSEIDON2_HD_COLS: usize =
    size_of::<PermutationNoSbox<u8, BabyBearConfig>>();

pub const BABYBEAR_POSEIDON2_HD_COL_MAP: PermutationNoSbox<usize, BabyBearConfig> =
    babybear_make_col_map_hd();

const fn babybear_make_col_map_hd() -> PermutationNoSbox<usize, BabyBearConfig> {
    let indices_arr = indices_arr::<BABYBEAR_NUM_POSEIDON2_HD_COLS>();
    unsafe {
        transmute::<[usize; BABYBEAR_NUM_POSEIDON2_HD_COLS], PermutationNoSbox<usize, BabyBearConfig>>(
            indices_arr,
        )
    }
}

// KOALABEAR_COL_MAP implementations
pub const KOALABEAR_NUM_POSEIDON2_COLS: usize = size_of::<PermutationNoSbox<u8, KoalaBearConfig>>();

pub const KOALABEAR_POSEIDON2_COL_MAP: PermutationNoSbox<usize, KoalaBearConfig> =
    koalabear_make_col_map();

const fn koalabear_make_col_map() -> PermutationNoSbox<usize, KoalaBearConfig> {
    let indices_arr = indices_arr::<KOALABEAR_NUM_POSEIDON2_COLS>();
    unsafe {
        transmute::<[usize; KOALABEAR_NUM_POSEIDON2_COLS], PermutationNoSbox<usize, KoalaBearConfig>>(
            indices_arr,
        )
    }
}
