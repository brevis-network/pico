use crate::compiler::word::Word;
use pico_derive::AlignedBorrow;
use std::mem::size_of;

/// Layout of Lt Chip Column
#[derive(AlignedBorrow, Default, Clone, Copy)]
#[repr(C)]
pub struct LtCols<T: Copy> {
    /// The chunk number, used for byte lookup table.
    pub chunk: T,
    /// The nonce of the operation.
    pub nonce: T,
    /// If the opcode is SLT.
    pub is_slt: T,
    /// If the opcode is SLTU.
    pub is_slt_u: T,
    /// The output operand.
    pub a: Word<T>,
    /// The first input operand.
    pub b: Word<T>,
    /// The second input operand.
    pub c: Word<T>,
    /// Boolean flag to indicate which byte differs.
    /// All flags should be zero when b = c, otherwise, at most 1 in the flags.
    pub byte_flags: [T; 4],
    /// The masking b[3] & 0x7F.
    pub b_masked: T,
    /// The masking c[3] & 0x7F.
    pub c_masked: T,
    /// The multiplication msb_b * is_slt.
    pub bit_b: T,
    /// The multiplication msb_c * is_slt.
    pub bit_c: T,
    /// An inverse of differing byte if c_comp != b_comp.
    pub not_eq_inv: T,
    /// The most significant bit of operand b.
    /// 1: signed 0: unsigned
    pub msb_b: T,
    /// The most significant bit of operand c.
    pub msb_c: T,
    /// The result of the intermediate SLTU operation `b_comp < c_comp`.
    pub slt_u: T,
    /// A boolean flag for an intermediate comparison.
    pub is_cmp_eq: T,
    /// indicate b and c sign bits are same or not.
    pub is_sign_bit_same: T,
    /// The comparison bytes to be looked up.
    pub cmp_bytes: [T; 2],
}

pub const NUM_LT_COLS: usize = size_of::<LtCols<u8>>();
