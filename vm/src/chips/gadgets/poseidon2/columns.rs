use crate::{
    chips::chips::recursion_memory::MemoryAccessCols,
    compiler::recursion::types::Address,
    configs::config::Poseidon2Config,
    primitives::consts::{PERMUTATION_WIDTH, POSEIDON2_DATAPAR, RISCV_POSEIDON2_DATAPAR},
};
use core::mem::size_of;
use hybrid_array::Array;
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

pub const RISCV_NUM_POSEIDON2_COLS<Config: Poseidon2Config>: usize =
    NUM_POSEIDON2_VALUE_COLS::<Config> * RISCV_POSEIDON2_DATAPAR;

#[derive(AlignedBorrow, Clone, Debug)]
#[repr(C)]
pub struct RiscvPoseidon2Cols<T, Config: Poseidon2Config> {
    pub(crate) values: [Poseidon2ValueCols<T, Config>; RISCV_POSEIDON2_DATAPAR],
}

impl<T, Config> Copy for RiscvPoseidon2Cols<T, Config>
where
    T: Copy,
    Config: Poseidon2Config,
    Poseidon2ValueCols<T, Config>: Copy,
{
}

pub const NUM_POSEIDON2_COLS<Config: Poseidon2Config>: usize =
    NUM_POSEIDON2_VALUE_COLS::<Config> * POSEIDON2_DATAPAR;

#[derive(AlignedBorrow, Clone, Debug)]
#[repr(C)]
pub struct Poseidon2Cols<T, Config: Poseidon2Config> {
    pub(crate) values: [Poseidon2ValueCols<T, Config>; POSEIDON2_DATAPAR],
}

impl<T, Config> Copy for Poseidon2Cols<T, Config>
where
    T: Copy,
    Config: Poseidon2Config,
    Poseidon2ValueCols<T, Config>: Copy,
{
}

pub const NUM_POSEIDON2_VALUE_COLS<Config: Poseidon2Config>: usize = size_of::<Poseidon2ValueCols<u8, Config>>();

#[derive(AlignedBorrow, Clone, Debug)]
#[repr(C)]
pub struct Poseidon2ValueCols<T, Config: Poseidon2Config> {
    pub is_real: T,

    pub inputs: [T; PERMUTATION_WIDTH],

    /// Beginning Full Rounds
    pub beginning_full_rounds: Array<FullRound<T, Config>, Config::HalfFullRounds>,

    /// Partial Rounds
    pub partial_rounds: Array<PartialRound<T, Config>, Config::PartialRounds>,

    /// Ending Full Rounds
    pub ending_full_rounds: Array<FullRound<T, Config>, Config::HalfFullRounds>,
}

impl<T, Config> Copy for Poseidon2ValueCols<T, Config>
where
    T: Copy,
    Config: Poseidon2Config,
    SBox<T, Config>: Copy,
    Array<FullRound<T, Config>, Config::HalfFullRounds>: Copy,
    Array<PartialRound<T, Config>, Config::PartialRounds>: Copy,
{
}

/// Full round columns.
#[derive(AlignedBorrow, Clone, Debug)]
#[repr(C)]
pub struct FullRound<T, Config: Poseidon2Config> {
    /// Possible intermediate results within each S-box.
    pub sbox: [SBox<T, Config>; PERMUTATION_WIDTH],
    /// The post-state, i.e. the entire layer after this full round.
    pub post: [T; PERMUTATION_WIDTH],
}

impl<T, Config> Copy for FullRound<T, Config>
where
    T: Copy,
    Config: Poseidon2Config,
    SBox<T, Config>: Copy,
{
}

/// Partial round columns.
#[derive(AlignedBorrow, Clone, Debug)]
#[repr(C)]
pub struct PartialRound<T, Config: Poseidon2Config> {
    /// Possible intermediate results within the S-box.
    pub sbox: SBox<T, Config>,
    /// The output of the S-box.
    pub post_sbox: T,
}

impl<T, Config> Copy for PartialRound<T, Config>
where
    T: Copy,
    Config: Poseidon2Config,
    SBox<T, Config>: Copy,
{
}

/// Possible intermediate results within an S-box.
///
/// Use this column-set for an S-box that can be computed with `REGISTERS`-many intermediate results
/// (not counting the final output). The S-box is checked to ensure that `REGISTERS` is the optimal
/// number of registers for the given `DEGREE` for the degrees given in the Poseidon2 paper:
/// `3`, `5`, `7`, and `11`. See `eval_sbox` for more information.
#[derive(AlignedBorrow, Clone, Debug)]
#[repr(C)]
pub struct SBox<T, Config: Poseidon2Config>(pub Array<T, Config::SBoxRegisters>);

impl<T, Config> Copy for SBox<T, Config>
where
    T: Copy,
    Config: Poseidon2Config,
    Array<T, Config::SBoxRegisters>: Copy,
{
}
