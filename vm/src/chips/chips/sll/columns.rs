use crate::{
    compiler::word::Word,
    primitives::consts::{BYTE_SIZE, WORD_SIZE},
};
use pico_derive::AlignedBorrow;
use std::mem::size_of;

pub const NUM_SLL_COLS: usize = size_of::<ShiftLeftCols<u8>>();

#[repr(C)]
#[derive(AlignedBorrow, Debug, Copy, Clone)]
pub struct ShiftLeftCols<T: Copy + Sized> {
    /// The chunk number, used for byte lookup table.
    pub chunk: T,

    /// The channel number, used for byte lookup table.
    pub channel: T,

    /// The nonce of the operation.
    pub nonce: T,

    /// The output operand, little-endian.
    pub a: Word<T>,

    /// The first input operand, little-endian.
    pub b: Word<T>,

    /// The shift amount, storage as little-endian.
    pub c: Word<T>,

    /// The least significant byte of `c`. Used to verify `shift_by_n_bits` and `shift_by_n_bytes`.
    /// Bit2Decimal(c_lsb[0..3]) = shift_by_n_bits
    /// Bit2Decimal(c_lsb[4..5]) = shift_by_n_bytes
    pub c_lsb: [T; BYTE_SIZE],

    /// A boolean array whose `i`th element indicates whether `num_bits_to_shift = i`.
    pub shift_by_n_bits: [T; BYTE_SIZE],

    /// The number to multiply to shift `b` by `num_bits_to_shift`. (i.e., `2^num_bits_to_shift`)
    pub bit_shift_multiplier: T,

    /// The result of multiplying `b` by `bit_shift_multiplier`.
    pub shift_result: [T; WORD_SIZE],

    /// The carry propagated when multiplying `b` by `bit_shift_multiplier`.
    pub shift_result_carry: [T; WORD_SIZE],

    /// A boolean array whose `i`th element indicates whether `num_bytes_to_shift = i`.
    pub shift_by_n_bytes: [T; WORD_SIZE],

    pub is_real: T,
}
