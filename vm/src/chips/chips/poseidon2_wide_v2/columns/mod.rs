pub mod permutation;
pub mod preprocessed;

use crate::{
    chips::{
        chips::poseidon2_wide_v2::columns::permutation::{PermutationNoSbox, PermutationSBox},
        utils::indices_arr,
    },
    primitives::consts::{
        BABYBEAR_NUM_EXTERNAL_ROUNDS, BABYBEAR_NUM_INTERNAL_ROUNDS, KOALABEAR_NUM_EXTERNAL_ROUNDS,
        KOALABEAR_NUM_INTERNAL_ROUNDS,
    },
};
use paste::paste;
use std::mem::{size_of, transmute};

/// Struct for the poseidon2 chip that contains sbox columns.
pub type Poseidon2Degree3<
    T,
    const NUM_EXTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS_MINUS_ONE: usize,
> = PermutationSBox<T, NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS_MINUS_ONE>;

macro_rules! impl_poseidon2_degree3 {
    ($name:ident, $capital_name:ident) => {
        paste! {
            pub const [<$capital_name _ NUM_POSEIDON2_DEGREE3_COLS>]: usize = size_of::<
                Poseidon2Degree3<
                    u8,
                    [<$capital_name _ NUM_EXTERNAL_ROUNDS>],
                    [<$capital_name _ NUM_INTERNAL_ROUNDS>],
                    { [<$capital_name _ NUM_INTERNAL_ROUNDS>] - 1 },
                >,
            >();
            pub const [<$capital_name _ POSEIDON2_DEGREE3_COL_MAP>]: Poseidon2Degree3<
                usize,
                [<$capital_name _ NUM_EXTERNAL_ROUNDS>],
                [<$capital_name _ NUM_INTERNAL_ROUNDS>],
                { [<$capital_name _ NUM_INTERNAL_ROUNDS>] - 1 },
            > = [<$name _ make_col_map_degree3>]();

            const fn [<$name _ make_col_map_degree3>]() -> Poseidon2Degree3<
                usize,
                [<$capital_name _ NUM_EXTERNAL_ROUNDS>],
                [<$capital_name _ NUM_INTERNAL_ROUNDS>],
                { [<$capital_name _ NUM_INTERNAL_ROUNDS>] - 1 },
            > {
                let indices_arr = indices_arr::<[<$capital_name _ NUM_POSEIDON2_DEGREE3_COLS>]>();
                unsafe {
                    transmute::<
                        [usize; [<$capital_name _ NUM_POSEIDON2_DEGREE3_COLS>]],
                        Poseidon2Degree3<
                            usize,
                            [<$capital_name _ NUM_EXTERNAL_ROUNDS>],
                            [<$capital_name _ NUM_INTERNAL_ROUNDS>],
                            { [<$capital_name _ NUM_INTERNAL_ROUNDS>] - 1 },
                        >,
                    >(indices_arr)
                }
            }
        }
    };
}

impl_poseidon2_degree3!(babybear, BABYBEAR);
impl_poseidon2_degree3!(koalabear, KOALABEAR);

pub type Poseidon2Degree9<
    T,
    const NUM_EXTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS_MINUS_ONE: usize,
> = PermutationNoSbox<T, NUM_EXTERNAL_ROUNDS, NUM_INTERNAL_ROUNDS_MINUS_ONE>;

macro_rules! impl_poseidon2_degree9 {
    ($name:ident, $capital_name:ident) => {
        paste! {
            pub const [<$capital_name _ NUM_POSEIDON2_DEGREE9_COLS>]: usize = size_of::<
                Poseidon2Degree9<
                    u8,
                    [<$capital_name _ NUM_EXTERNAL_ROUNDS>],
                    { [<$capital_name _ NUM_INTERNAL_ROUNDS>] - 1 },
                >,
            >();
            pub const [<$capital_name _ POSEIDON2_DEGREE9_COL_MAP>]: Poseidon2Degree9<
                usize,
                [<$capital_name _ NUM_EXTERNAL_ROUNDS>],
                { [<$capital_name _ NUM_INTERNAL_ROUNDS>] - 1 },
            > = [<$name _ make_col_map_degree9>]();

            const fn [<$name _ make_col_map_degree9>]() -> Poseidon2Degree9<
                usize,
                [<$capital_name _ NUM_EXTERNAL_ROUNDS>],
                { [<$capital_name _ NUM_INTERNAL_ROUNDS>] - 1 },
            > {
                let indices_arr = indices_arr::<[<$capital_name _ NUM_POSEIDON2_DEGREE9_COLS>]>();
                unsafe {
                    transmute::<
                        [usize; [<$capital_name _ NUM_POSEIDON2_DEGREE9_COLS>]],
                        Poseidon2Degree9<
                            usize,
                            [<$capital_name _ NUM_EXTERNAL_ROUNDS>],
                            { [<$capital_name _ NUM_INTERNAL_ROUNDS>] - 1 },
                        >,
                    >(indices_arr)
                }
            }
        }
    };
}

impl_poseidon2_degree9!(babybear, BABYBEAR);
impl_poseidon2_degree9!(koalabear, KOALABEAR);
