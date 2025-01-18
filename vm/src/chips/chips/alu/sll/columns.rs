use crate::{
    compiler::word::Word,
    primitives::consts::{BYTE_SIZE, SLL_DATAPAR, WORD_SIZE},
};
use pico_derive::AlignedBorrow;
use std::mem::size_of;

pub const NUM_SLL_COLS: usize = size_of::<ShiftLeftCols<u8>>();

#[repr(C)]
#[derive(AlignedBorrow, Copy, Clone, Default)]
pub struct ShiftLeftCols<F: Copy + Sized> {
    pub values: [ShiftLeftValueCols<F>; SLL_DATAPAR],
}

pub const NUM_SLL_VALUE_COLS: usize = size_of::<ShiftLeftValueCols<u8>>();

#[repr(C)]
#[derive(AlignedBorrow, Copy, Clone, Default)]
pub struct ShiftLeftValueCols<F: Copy + Sized> {
    /// The output operand, little-endian.
    pub a: Word<F>,

    /// The first input operand, little-endian.
    pub b: Word<F>,

    /// The shift amount, storage as little-endian.
    pub c: Word<F>,

    /// The least significant byte of `c`. Used to verify `shift_by_n_bits` and `shift_by_n_bytes`.
    /// Bit2Decimal(c_lsb[0..3]) = shift_by_n_bits
    /// Bit2Decimal(c_lsb[4..5]) = shift_by_n_bytes
    pub c_lsb: [F; BYTE_SIZE],

    /// A boolean array whose `i`th element indicates whether `num_bits_to_shift = i`.
    pub shift_by_n_bits: [F; BYTE_SIZE],

    /// The number to multiply to shift `b` by `num_bits_to_shift`. (i.e., `2^num_bits_to_shift`)
    pub bit_shift_multiplier: F,

    /// The result of multiplying `b` by `bit_shift_multiplier`.
    pub shift_result: [F; WORD_SIZE],

    /// The carry propagated when multiplying `b` by `bit_shift_multiplier`.
    pub shift_result_carry: [F; WORD_SIZE],

    /// A boolean array whose `i`th element indicates whether `num_bytes_to_shift = i`.
    pub shift_by_n_bytes: [F; WORD_SIZE],

    pub is_real: F,
}
