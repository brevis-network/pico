use std::mem::size_of;

use crate::{
    compiler::word::Word,
    primitives::consts::{BYTE_SIZE, LONG_WORD_SIZE, SR_DATAPAR, WORD_SIZE},
};
use pico_derive::AlignedBorrow;

pub(crate) const NUM_SLR_COLS: usize = size_of::<ShiftRightCols<u8>>();

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct ShiftRightCols<F: Copy> {
    pub values: [ShiftRightValueCols<F>; SR_DATAPAR],
}

pub const NUM_SLR_VALUE_COLS: usize = size_of::<ShiftRightValueCols<u8>>();

/// The column layout for the chip.
#[derive(AlignedBorrow, Debug, Default, Clone, Copy)]
#[repr(C)]
pub struct ShiftRightValueCols<F: Copy> {
    /// The output operand.
    pub a: Word<F>,

    /// The first input operand.
    pub b: Word<F>,

    /// The second input operand.
    pub c: Word<F>,

    /// A boolean array whose `i`th element indicates whether `num_bits_to_shift = i`.
    pub shift_by_n_bits: [F; BYTE_SIZE],

    /// A boolean array whose `i`th element indicates whether `num_bytes_to_shift = i`.
    pub shift_by_n_bytes: [F; WORD_SIZE],

    /// The result of "byte-shifting" the input operand `b` by `num_bytes_to_shift`.
    pub byte_shift_result: [F; LONG_WORD_SIZE],

    /// The result of "bit-shifting" the byte-shifted input by `num_bits_to_shift`.
    pub bit_shift_result: [F; LONG_WORD_SIZE],

    /// The carry output of `shrcarry` on each byte of `byte_shift_result`.
    pub shr_carry_output_carry: [F; LONG_WORD_SIZE],

    /// The shift byte output of `shrcarry` on each byte of `byte_shift_result`.
    pub shr_carry_output_shifted_byte: [F; LONG_WORD_SIZE],

    /// The most significant bit of `b`.
    pub b_msb: F,

    /// The least significant byte of `c`. Used to verify `shift_by_n_bits` and `shift_by_n_bytes`.
    pub c_least_sig_byte: [F; BYTE_SIZE],

    /// If the opcode is SRL.
    pub is_srl: F,

    /// If the opcode is SRA.
    pub is_sra: F,

    /// Selector to know whether this row is enabled.
    pub is_real: F,
}
