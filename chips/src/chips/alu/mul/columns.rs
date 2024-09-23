use std::mem::size_of;

use pico_compiler::word::Word;
use pico_derive::AlignedBorrow;

use super::PRODUCT_SIZE;

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MulCols<T> {
    /// The chunk number, used for byte lookup table.
    pub chunk: T,

    /// The channel number, used for byte lookup table.
    pub channel: T,

    /// The nonce of the operation.
    pub nonce: T,

    /// The output operand.
    pub a: Word<T>,

    /// The first input operand.
    pub b: Word<T>,

    /// The second input operand.
    pub c: Word<T>,

    /// Trace.
    pub carry: [T; PRODUCT_SIZE],

    /// An array storing the product of `b * c` after the carry propagation.
    pub product: [T; PRODUCT_SIZE],

    /// The most significant bit of `b`.
    pub b_msb: T,

    /// The most significant bit of `c`.
    pub c_msb: T,

    /// The sign extension of `b`.
    pub b_sign_extend: T,

    /// The sign extension of `c`.
    pub c_sign_extend: T,

    /// Flag indicating whether the opcode is `MUL` (`u32 x u32`).
    pub is_mul: T,

    /// Flag indicating whether the opcode is `MULH` (`i32 x i32`, upper half).
    pub is_mulh: T,

    /// Flag indicating whether the opcode is `MULHU` (`u32 x u32`, upper half).
    pub is_mulhu: T,

    /// Flag indicating whether the opcode is `MULHSU` (`i32 x u32`, upper half).
    pub is_mulhsu: T,

    /// Selector to know whether this row is enabled.
    pub is_real: T,
}

/// The number of main trace columns for `MulChip`.
pub const NUM_MUL_COLS: usize = size_of::<MulCols<u8>>();
