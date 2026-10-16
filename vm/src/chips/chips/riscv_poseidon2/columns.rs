//! Column layout of the riscv Poseidon2 wrapper.
//!
//! The Global chip is the only producer of the riscv `Poseidon2` lookup and always feeds a rate-8
//! input with zero capacity (`lift_x`'s `m_trial[8..16] == 0`), so only `inputs[0..8]` are
//! committed; the eight capacity lanes enter the round constraints as constant zeros. The lookup
//! reads only `outputs[0..7]`, so the last ending full round commits just those seven lanes
//! (`RiscvLastFullRound`): the other nine would appear in no constraint but their own definition.
//! Everything else mirrors the shared `Poseidon2ValueCols` (the recursion chips and the riscv
//! Poseidon2 precompile keep the full-width layout).

use crate::{
    chips::gadgets::poseidon2::columns::{FullRound, PartialRound, SBox},
    configs::config::Poseidon2Config,
    primitives::consts::{PERMUTATION_WIDTH, RISCV_POSEIDON2_DATAPAR},
};
use core::mem::size_of;
use hybrid_array::Array;
use pico_derive::AlignedBorrow;

/// Number of committed permutation inputs per slot (the Poseidon2 absorption rate).
pub const RISCV_POSEIDON2_NUM_INPUTS: usize = 8;

/// Number of committed permutation outputs per slot: the lanes the riscv `Poseidon2` lookup
/// carries (the Global chip's hash-to-curve reads `x_coordinate[0..7]`).
pub const RISCV_POSEIDON2_NUM_OUTPUTS: usize = 7;

/// Columns of one permutation slot (148 for KoalaBear: 1 + 8 + 4·16 + 20 + 3·16 + 7).
pub const RISCV_NUM_POSEIDON2_VALUE_COLS<Config: Poseidon2Config>: usize =
    size_of::<RiscvPoseidon2ValueCols<u8, Config>>();

/// Columns of one trace row (`RISCV_POSEIDON2_DATAPAR` slots; 592 for KoalaBear).
pub const RISCV_NUM_POSEIDON2_COLS<Config: Poseidon2Config>: usize =
    RISCV_NUM_POSEIDON2_VALUE_COLS::<Config> * RISCV_POSEIDON2_DATAPAR;

#[derive(AlignedBorrow, Clone, Debug)]
#[repr(C)]
pub struct RiscvPoseidon2Cols<T, Config: Poseidon2Config> {
    pub(crate) values: [RiscvPoseidon2ValueCols<T, Config>; RISCV_POSEIDON2_DATAPAR],
}

impl<T, Config> Copy for RiscvPoseidon2Cols<T, Config>
where
    T: Copy,
    Config: Poseidon2Config,
    RiscvPoseidon2ValueCols<T, Config>: Copy,
{
}

#[derive(AlignedBorrow, Clone, Debug)]
#[repr(C)]
pub struct RiscvPoseidon2ValueCols<T, Config: Poseidon2Config> {
    pub is_real: T,

    /// The rate part of the permutation input; the capacity lanes `8..16` are constant zero.
    pub inputs: [T; RISCV_POSEIDON2_NUM_INPUTS],

    /// Beginning Full Rounds
    pub beginning_full_rounds: Array<FullRound<T, Config>, Config::HalfFullRounds>,

    /// Partial Rounds
    pub partial_rounds: Array<PartialRound<T, Config>, Config::PartialRounds>,

    /// Ending Full Rounds except the last one.
    pub ending_full_rounds: Array<FullRound<T, Config>, Config::HalfFullRoundsM1>,

    /// The last ending full round; only the looked-up output lanes are committed.
    pub last_full_round: RiscvLastFullRound<T, Config>,
}

impl<T, Config> Copy for RiscvPoseidon2ValueCols<T, Config>
where
    T: Copy,
    Config: Poseidon2Config,
    SBox<T, Config>: Copy,
    Array<FullRound<T, Config>, Config::HalfFullRounds>: Copy,
    Array<PartialRound<T, Config>, Config::PartialRounds>: Copy,
    Array<FullRound<T, Config>, Config::HalfFullRoundsM1>: Copy,
    RiscvLastFullRound<T, Config>: Copy,
{
}

/// The last ending full round of the riscv layout: the S-box registers of all 16 lanes (none for
/// KoalaBear) and the post-state of the `RISCV_POSEIDON2_NUM_OUTPUTS` lanes the lookup reads.
#[derive(AlignedBorrow, Clone, Debug)]
#[repr(C)]
pub struct RiscvLastFullRound<T, Config: Poseidon2Config> {
    /// Possible intermediate results within each S-box.
    pub sbox: [SBox<T, Config>; PERMUTATION_WIDTH],
    /// The post-state of the committed output lanes.
    pub post: [T; RISCV_POSEIDON2_NUM_OUTPUTS],
}

impl<T, Config> Copy for RiscvLastFullRound<T, Config>
where
    T: Copy,
    Config: Poseidon2Config,
    SBox<T, Config>: Copy,
{
}
