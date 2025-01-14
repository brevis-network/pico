pub mod permutation;
pub mod preprocessed;

use crate::{
    chips::{
        chips::poseidon2::columns::permutation::{PermutationNoSbox, PermutationSBox},
        utils::indices_arr,
    },
    primitives::consts::{
        BABYBEAR_NUM_EXTERNAL_ROUNDS, BABYBEAR_NUM_INTERNAL_ROUNDS, KOALABEAR_NUM_EXTERNAL_ROUNDS,
        KOALABEAR_NUM_INTERNAL_ROUNDS,
    },
};
use std::mem::{size_of, transmute};

// BABYBEAR_COL_MAP low degree implementations
pub const BABYBEAR_NUM_POSEIDON2_LD_COLS: usize = size_of::<
    PermutationSBox<
        u8,
        BABYBEAR_NUM_EXTERNAL_ROUNDS,
        BABYBEAR_NUM_INTERNAL_ROUNDS,
        { BABYBEAR_NUM_INTERNAL_ROUNDS - 1 },
    >,
>();

pub const BABYBEAR_POSEIDON2_LD_COL_MAP: PermutationSBox<
    usize,
    BABYBEAR_NUM_EXTERNAL_ROUNDS,
    BABYBEAR_NUM_INTERNAL_ROUNDS,
    { BABYBEAR_NUM_INTERNAL_ROUNDS - 1 },
> = babybear_make_col_map_ld();

const fn babybear_make_col_map_ld() -> PermutationSBox<
    usize,
    BABYBEAR_NUM_EXTERNAL_ROUNDS,
    BABYBEAR_NUM_INTERNAL_ROUNDS,
    { BABYBEAR_NUM_INTERNAL_ROUNDS - 1 },
> {
    let indices_arr = indices_arr::<BABYBEAR_NUM_POSEIDON2_LD_COLS>();
    unsafe {
        transmute::<
            [usize; BABYBEAR_NUM_POSEIDON2_LD_COLS],
            PermutationSBox<
                usize,
                BABYBEAR_NUM_EXTERNAL_ROUNDS,
                BABYBEAR_NUM_INTERNAL_ROUNDS,
                { BABYBEAR_NUM_INTERNAL_ROUNDS - 1 },
            >,
        >(indices_arr)
    }
}

// BABYBEAR_COL_MAP high degree implementations
pub const BABYBEAR_NUM_POSEIDON2_HD_COLS: usize = size_of::<
    PermutationNoSbox<u8, BABYBEAR_NUM_EXTERNAL_ROUNDS, { BABYBEAR_NUM_INTERNAL_ROUNDS - 1 }>,
>();

pub const BABYBEAR_POSEIDON2_HD_COL_MAP: PermutationNoSbox<
    usize,
    BABYBEAR_NUM_EXTERNAL_ROUNDS,
    { BABYBEAR_NUM_INTERNAL_ROUNDS - 1 },
> = babybear_make_col_map_hd();

const fn babybear_make_col_map_hd(
) -> PermutationNoSbox<usize, BABYBEAR_NUM_EXTERNAL_ROUNDS, { BABYBEAR_NUM_INTERNAL_ROUNDS - 1 }> {
    let indices_arr = indices_arr::<BABYBEAR_NUM_POSEIDON2_HD_COLS>();
    unsafe {
        transmute::<
            [usize; BABYBEAR_NUM_POSEIDON2_HD_COLS],
            PermutationNoSbox<
                usize,
                BABYBEAR_NUM_EXTERNAL_ROUNDS,
                { BABYBEAR_NUM_INTERNAL_ROUNDS - 1 },
            >,
        >(indices_arr)
    }
}

// KOALABEAR_COL_MAP implementations
pub const KOALABEAR_NUM_POSEIDON2_COLS: usize = size_of::<
    PermutationNoSbox<u8, KOALABEAR_NUM_EXTERNAL_ROUNDS, { KOALABEAR_NUM_INTERNAL_ROUNDS - 1 }>,
>();

pub const KOALABEAR_POSEIDON2_COL_MAP: PermutationNoSbox<
    usize,
    KOALABEAR_NUM_EXTERNAL_ROUNDS,
    { KOALABEAR_NUM_INTERNAL_ROUNDS - 1 },
> = koalabear_make_col_map();

const fn koalabear_make_col_map(
) -> PermutationNoSbox<usize, KOALABEAR_NUM_EXTERNAL_ROUNDS, { KOALABEAR_NUM_INTERNAL_ROUNDS - 1 }>
{
    let indices_arr = indices_arr::<KOALABEAR_NUM_POSEIDON2_COLS>();
    unsafe {
        transmute::<
            [usize; KOALABEAR_NUM_POSEIDON2_COLS],
            PermutationNoSbox<
                usize,
                KOALABEAR_NUM_EXTERNAL_ROUNDS,
                { KOALABEAR_NUM_INTERNAL_ROUNDS - 1 },
            >,
        >(indices_arr)
    }
}
