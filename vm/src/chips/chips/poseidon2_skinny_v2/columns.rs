use crate::{
    chips::{chips::recursion_memory_v2::MemoryAccessCols, utils::indices_arr},
    primitives::consts::{
        BABYBEAR_NUM_INTERNAL_ROUNDS, KOALABEAR_NUM_INTERNAL_ROUNDS, PERMUTATION_WIDTH,
    },
};
use paste::paste;
use pico_derive::AlignedBorrow;
use std::mem::{size_of, transmute};

pub const NUM_POSEIDON2_PREPROCESSED_COLS: usize = size_of::<Poseidon2PreprocessedCols<u8>>();

macro_rules! impl_poseidon2_cols {
    ($name:ident, $capital_name:ident) => {
        paste! {
            pub const [<$capital_name _ NUM_POSEIDON2_COLS>]: usize =
                size_of::<Poseidon2Cols<u8, { [<$capital_name _ NUM_INTERNAL_ROUNDS>] - 1 }>>();

            pub const [<$capital_name _ POSEIDON2_DEGREE9_COL_MAP>]: Poseidon2Cols<
                usize,
                { [<$capital_name _ NUM_INTERNAL_ROUNDS>] - 1 },
            > = [<$name _ make_col_map_degree9>]();

            const fn [<$name _ make_col_map_degree9>](
            ) -> Poseidon2Cols<usize, { [<$capital_name _ NUM_INTERNAL_ROUNDS>] - 1 }> {
                let indices_arr = indices_arr::<[<$capital_name _ NUM_POSEIDON2_COLS>]>();
                unsafe {
                    transmute::<
                        [usize; [<$capital_name _ NUM_POSEIDON2_COLS>]],
                        Poseidon2Cols<usize, { [<$capital_name _ NUM_INTERNAL_ROUNDS>] - 1 }>,
                    >(indices_arr)
                }
            }
        }
    };
}

impl_poseidon2_cols!(babybear, BABYBEAR);
impl_poseidon2_cols!(koalabear, KOALABEAR);

#[derive(AlignedBorrow, Clone, Copy)]
#[repr(C)]
pub struct Poseidon2Cols<T: Copy, const NUM_INTERNAL_ROUNDS_MINUS_ONE: usize> {
    pub state_var: [T; PERMUTATION_WIDTH],
    pub internal_rounds_s0: [T; NUM_INTERNAL_ROUNDS_MINUS_ONE],
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
