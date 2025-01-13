use std::mem::size_of;

use crate::{
    compiler::word::Word,
    primitives::consts::{BYTE_SIZE, LONG_WORD_SIZE, WORD_SIZE},
};
use pico_derive::AlignedBorrow;

pub(crate) const NUM_SLR_COLS: usize = size_of::<ShiftRightCols<u8>>();

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct ShiftRightCols<T: Copy> {
    /// The chunk number, used for byte lookup table.
    pub chunk: T,

    /// The output operand.
    pub a: Word<T>,

    /// The first input operand.
    pub b: Word<T>,

    /// The second input operand.
    pub c: Word<T>,

    /// A boolean array whose `i`th element indicates whether `num_bits_to_shift = i`.
    pub shift_by_n_bits: [T; BYTE_SIZE],

    /// A boolean array whose `i`th element indicates whether `num_bytes_to_shift = i`.
    pub shift_by_n_bytes: [T; WORD_SIZE],

    /// The result of "byte-shifting" the input operand `b` by `num_bytes_to_shift`.
    pub byte_shift_result: [T; LONG_WORD_SIZE],

    /// The result of "bit-shifting" the byte-shifted input by `num_bits_to_shift`.
    pub bit_shift_result: [T; LONG_WORD_SIZE],

    /// The carry output of `shrcarry` on each byte of `byte_shift_result`.
    pub shr_carry_output_carry: [T; LONG_WORD_SIZE],

    /// The shift byte output of `shrcarry` on each byte of `byte_shift_result`.
    pub shr_carry_output_shifted_byte: [T; LONG_WORD_SIZE],

    /// The most significant bit of `b`.
    pub b_msb: T,

    /// The least significant byte of `c`. Used to verify `shift_by_n_bits` and `shift_by_n_bytes`.
    pub c_least_sig_byte: [T; BYTE_SIZE],

    /// If the opcode is SRL.
    pub is_srl: T,

    /// If the opcode is SRA.
    pub is_sra: T,

    /// Selector to know whether this row is enabled.
    pub is_real: T,
}
