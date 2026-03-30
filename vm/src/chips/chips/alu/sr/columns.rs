use std::mem::size_of;

use crate::{
    chips::gadgets::msb::U16MSBGadget,
    compiler::word::Word,
    primitives::consts::{SR_DATAPAR, WORD_SIZE},
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

/// The column layout for a single shift right operation.
#[derive(AlignedBorrow, Debug, Default, Clone, Copy)]
#[repr(C)]
pub struct ShiftRightValueCols<F: Copy> {
    /// The output operand.
    pub a: Word<F>,

    /// The operand b (the value being shifted).
    pub b: Word<F>,

    /// The operand c (shift amount) for ALU lookup.
    pub c_for_lookup: Word<F>,

    /// The most significant bit of `b` (for SRA/SRAW).
    pub b_msb: U16MSBGadget<F>,

    /// The most significant byte of the result of SRLW/SRAW.
    pub srw_msb: U16MSBGadget<F>,

    /// The bottom 6 bits of `c` (shift amount).
    pub c_bits: [F; 6],

    /// The full c value (shift amount).
    pub c: F,

    /// Whether the shift amount is an immediate value.
    pub imm_c: F,

    /// SRA msb * v0123
    pub sra_msb_v0123: F,

    /// v0123 = 1 << (16 - (c & 15))
    pub v_0123: F,

    /// v012 = 1 << (8 - (c & 7))
    pub v_012: F,

    /// v01 = 1 << (4 - (c & 3))
    pub v_01: F,

    /// The lower bits of each limb.
    pub lower_limb: Word<F>,

    /// The higher bits of each limb.
    pub higher_limb: Word<F>,

    /// The result of the byte-shift.
    pub limb_result: [F; WORD_SIZE],

    /// The shift amount (which u16 limb to shift by).
    pub shift_u16: [F; 4],

    /// If the opcode is SRL.
    pub is_srl: F,

    /// If the opcode is SRA.
    pub is_sra: F,

    /// If the opcode is SRLW.
    pub is_srlw: F,

    /// If the opcode is SRAW.
    pub is_sraw: F,

    /// If the opcode is W and immediate (SRLW/SRAW with immediate shift).
    pub is_w_imm: F,
}
