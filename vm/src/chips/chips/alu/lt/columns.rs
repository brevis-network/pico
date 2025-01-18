use crate::{compiler::word::Word, primitives::consts::LT_DATAPAR};
use pico_derive::AlignedBorrow;
use std::mem::size_of;

pub const NUM_LT_COLS: usize = size_of::<LtCols<u8>>();

/// Layout of Lt Chip Column
#[derive(AlignedBorrow, Default, Clone, Copy)]
#[repr(C)]
pub struct LtCols<F: Copy> {
    pub values: [LtValueCols<F>; LT_DATAPAR],
}

pub const NUM_LT_VALUE_COLS: usize = size_of::<LtValueCols<u8>>();

/// Layout of Lt Value Chip Column
#[derive(AlignedBorrow, Default, Clone, Copy)]
#[repr(C)]
pub struct LtValueCols<F: Copy> {
    /// If the opcode is SLT.
    pub is_slt: F,
    /// If the opcode is SLTU.
    pub is_slt_u: F,
    /// The output operand.
    pub a: Word<F>,
    /// The first input operand.
    pub b: Word<F>,
    /// The second input operand.
    pub c: Word<F>,
    /// Boolean flag to indicate which byte differs.
    /// All flags should be zero when b = c, otherwise, at most 1 in the flags.
    pub byte_flags: [F; 4],
    /// The masking b[3] & 0x7F.
    pub b_masked: F,
    /// The masking c[3] & 0x7F.
    pub c_masked: F,
    /// The multiplication msb_b * is_slt.
    pub bit_b: F,
    /// The multiplication msb_c * is_slt.
    pub bit_c: F,
    /// An inverse of differing byte if c_comp != b_comp.
    pub not_eq_inv: F,
    /// The most significant bit of operand b.
    /// 1: signed 0: unsigned
    pub msb_b: F,
    /// The most significant bit of operand c.
    pub msb_c: F,
    /// The result of the intermediate SLTU operation `b_comp < c_comp`.
    pub slt_u: F,
    /// A boolean flag for an intermediate comparison.
    pub is_cmp_eq: F,
    /// indicate b and c sign bits are same or not.
    pub is_sign_bit_same: F,
    /// The comparison bytes to be looked up.
    pub cmp_bytes: [F; 2],
}
