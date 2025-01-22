use crate::{
    chips::chips::recursion_memory_v2::MemoryAccessCols,
    compiler::recursion_v2::types::Address,
    primitives::{
        consts::{PERMUTATION_WIDTH, POSEIDON2_DATAPAR},
        FIELD_HALF_FULL_ROUNDS, FIELD_PARTIAL_ROUNDS, FIELD_SBOX_REGISTERS,
    },
};
use core::mem::size_of;
use pico_derive::AlignedBorrow;

/*
Preprocessed columns
*/
pub const NUM_PREPROCESSED_POSEIDON2_COLS: usize =
    NUM_PREPROCESSED_POSEIDON2_VALUE_COLS * POSEIDON2_DATAPAR;

#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Poseidon2PreprocessedCols<T: Copy> {
    pub values: [Poseidon2PreprocessedValueCols<T>; POSEIDON2_DATAPAR],
}

pub const NUM_PREPROCESSED_POSEIDON2_VALUE_COLS: usize =
    size_of::<Poseidon2PreprocessedValueCols<u8>>();

#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Poseidon2PreprocessedValueCols<T: Copy> {
    pub input: [Address<T>; PERMUTATION_WIDTH],
    pub output: [MemoryAccessCols<T>; PERMUTATION_WIDTH],
    pub is_real_neg: T,
}

/*
Main columns
*/

pub const NUM_POSEIDON2_COLS: usize = NUM_POSEIDON2_VALUE_COLS * POSEIDON2_DATAPAR;

pub const NUM_POSEIDON2_VALUE_COLS: usize = size_of::<Poseidon2ValueCols<u8>>();

#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Poseidon2Cols<T> {
    pub(crate) values: [Poseidon2ValueCols<T>; POSEIDON2_DATAPAR],
}

/// Columns for a Poseidon2 AIR which computes one permutation per row.
///
/// The columns of the STARK are divided into the three different round sections of the Poseidon2
/// Permutation: beginning full rounds, partial rounds, and ending full rounds. For the full
/// rounds we store an [`SBox`] columnset for each state variable, and for the partial rounds we
/// store only for the first state variable. Because the matrix multiplications are linear
/// functions, we need only keep auxiliary columns for the S-box computations.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Poseidon2ValueCols<T> {
    pub is_real: T,

    pub inputs: [T; PERMUTATION_WIDTH],

    /// Beginning Full Rounds
    pub beginning_full_rounds: [FullRound<T>; FIELD_HALF_FULL_ROUNDS],

    /// Partial Rounds
    pub partial_rounds: [PartialRound<T>; FIELD_PARTIAL_ROUNDS],

    /// Ending Full Rounds
    pub ending_full_rounds: [FullRound<T>; FIELD_HALF_FULL_ROUNDS],
}

/// Full round columns.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct FullRound<T> {
    /// Possible intermediate results within each S-box.
    pub sbox: [SBox<T>; PERMUTATION_WIDTH],
    /// The post-state, i.e. the entire layer after this full round.
    pub post: [T; PERMUTATION_WIDTH],
}

/// Partial round columns.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct PartialRound<T> {
    /// Possible intermediate results within the S-box.
    pub sbox: SBox<T>,
    /// The output of the S-box.
    pub post_sbox: T,
}

/// Possible intermediate results within an S-box.
///
/// Use this column-set for an S-box that can be computed with `REGISTERS`-many intermediate results
/// (not counting the final output). The S-box is checked to ensure that `REGISTERS` is the optimal
/// number of registers for the given `DEGREE` for the degrees given in the Poseidon2 paper:
/// `3`, `5`, `7`, and `11`. See `eval_sbox` for more information.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct SBox<T>(pub [T; FIELD_SBOX_REGISTERS]);
