use crate::{
    chips::chips::recursion_memory::MemoryAccessCols,
    compiler::recursion::types::Address,
    configs::config::Poseidon2Config,
    primitives::consts::{PERMUTATION_WIDTH, POSEIDON2_DATAPAR},
};
use core::mem::size_of;
use hybrid_array::Array;
use pico_derive::AlignedBorrow;
/*
Preprocessed columns
*/
pub const NUM_PREPROCESSED_POSEIDON2_COLS: usize =
    NUM_PREPROCESSED_POSEIDON2_VALUE_COLS * POSEIDON2_DATAPAR;

#[derive(AlignedBorrow, Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct Poseidon2PreprocessedCols<T: Copy> {
    pub values: [Poseidon2PreprocessedValueCols<T>; POSEIDON2_DATAPAR],
}

pub const NUM_PREPROCESSED_POSEIDON2_VALUE_COLS: usize =
    size_of::<Poseidon2PreprocessedValueCols<u8>>();

#[derive(AlignedBorrow, Clone, Copy, Debug, Eq, PartialEq)]
#[repr(C)]
pub struct Poseidon2PreprocessedValueCols<T: Copy> {
    pub input: [Address<T>; PERMUTATION_WIDTH],
    pub output: [MemoryAccessCols<T>; PERMUTATION_WIDTH],
    pub is_real_neg: T,
}

/*
Main columns

The riscv wrapper's rate-8 layout (`RiscvPoseidon2Cols` / `RiscvPoseidon2ValueCols`) lives in
`chips::chips::riscv_poseidon2::columns`; the full-width `Poseidon2ValueCols` below is shared by the
recursion Poseidon2 chips and the riscv Poseidon2 precompile.
*/

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

pub const NUM_POSEIDON2_VALUE_COLS<Config: Poseidon2Config>: usize =
    size_of::<Poseidon2ValueCols<u8, Config>>();

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
/// Holds the `Config::SBoxRegisters`-many intermediate results an S-box needs, not counting its
/// output. The only shape left is KoalaBear's `(F::FIELD_SBOX_DEGREE, Config::SBoxRegisters) =
/// (3, 0)`, a cube that needs no intermediate, so the column is zero-width; `eval_sbox` and
/// `populate_sbox` panic on anything else.
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
