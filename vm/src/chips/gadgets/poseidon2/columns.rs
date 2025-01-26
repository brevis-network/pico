use crate::{
    chips::chips::recursion_memory_v2::MemoryAccessCols,
    compiler::recursion_v2::types::Address,
    primitives::consts::{PERMUTATION_WIDTH, POSEIDON2_DATAPAR, RISCV_POSEIDON2_DATAPAR},
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

pub const RISCV_NUM_POSEIDON2_COLS<
    const FIELD_HALF_FULL_ROUNDS: usize,
    const FIELD_PARTIAL_ROUNDS: usize,
    const FIELD_SBOX_REGISTERS: usize,
>: usize = NUM_POSEIDON2_VALUE_COLS::<FIELD_HALF_FULL_ROUNDS, FIELD_PARTIAL_ROUNDS, FIELD_SBOX_REGISTERS> * RISCV_POSEIDON2_DATAPAR;

#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct RiscvPoseidon2Cols<
    T,
    const FIELD_HALF_FULL_ROUNDS: usize,
    const FIELD_PARTIAL_ROUNDS: usize,
    const FIELD_SBOX_REGISTERS: usize,
> {
    pub(crate) values:
        [Poseidon2ValueCols<T, FIELD_HALF_FULL_ROUNDS, FIELD_PARTIAL_ROUNDS, FIELD_SBOX_REGISTERS>;
            RISCV_POSEIDON2_DATAPAR],
}

pub const NUM_POSEIDON2_COLS<
    const FIELD_HALF_FULL_ROUNDS: usize,
    const FIELD_PARTIAL_ROUNDS: usize,
    const FIELD_SBOX_REGISTERS: usize,
>: usize = NUM_POSEIDON2_VALUE_COLS::<FIELD_HALF_FULL_ROUNDS, FIELD_PARTIAL_ROUNDS, FIELD_SBOX_REGISTERS> * POSEIDON2_DATAPAR;

#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Poseidon2Cols<
    T,
    const FIELD_HALF_FULL_ROUNDS: usize,
    const FIELD_PARTIAL_ROUNDS: usize,
    const FIELD_SBOX_REGISTERS: usize,
> {
    pub(crate) values:
        [Poseidon2ValueCols<T, FIELD_HALF_FULL_ROUNDS, FIELD_PARTIAL_ROUNDS, FIELD_SBOX_REGISTERS>;
            POSEIDON2_DATAPAR],
}

pub const NUM_POSEIDON2_VALUE_COLS<
    const FIELD_HALF_FULL_ROUNDS: usize,
    const FIELD_PARTIAL_ROUNDS: usize,
    const FIELD_SBOX_REGISTERS: usize,
>: usize = size_of::<Poseidon2ValueCols<u8, FIELD_HALF_FULL_ROUNDS, FIELD_PARTIAL_ROUNDS, FIELD_SBOX_REGISTERS>>();

#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct Poseidon2ValueCols<
    T,
    const FIELD_HALF_FULL_ROUNDS: usize,
    const FIELD_PARTIAL_ROUNDS: usize,
    const FIELD_SBOX_REGISTERS: usize,
> {
    pub is_real: T,

    pub inputs: [T; PERMUTATION_WIDTH],

    /// Beginning Full Rounds
    pub beginning_full_rounds: [FullRound<T, FIELD_SBOX_REGISTERS>; FIELD_HALF_FULL_ROUNDS],

    /// Partial Rounds
    pub partial_rounds: [PartialRound<T, FIELD_SBOX_REGISTERS>; FIELD_PARTIAL_ROUNDS],

    /// Ending Full Rounds
    pub ending_full_rounds: [FullRound<T, FIELD_SBOX_REGISTERS>; FIELD_HALF_FULL_ROUNDS],
}

/// Full round columns.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct FullRound<T, const FIELD_SBOX_REGISTERS: usize> {
    /// Possible intermediate results within each S-box.
    pub sbox: [SBox<T, FIELD_SBOX_REGISTERS>; PERMUTATION_WIDTH],
    /// The post-state, i.e. the entire layer after this full round.
    pub post: [T; PERMUTATION_WIDTH],
}

/// Partial round columns.
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct PartialRound<T, const FIELD_SBOX_REGISTERS: usize> {
    /// Possible intermediate results within the S-box.
    pub sbox: SBox<T, FIELD_SBOX_REGISTERS>,
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
pub struct SBox<T, const FIELD_SBOX_REGISTERS: usize>(pub [T; FIELD_SBOX_REGISTERS]);
