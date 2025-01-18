use std::mem::size_of;

use super::PRODUCT_SIZE;
use crate::{compiler::word::Word, primitives::consts::MUL_DATAPAR};
use pico_derive::AlignedBorrow;

/// The number of main trace columns for `MulChip`.
pub const NUM_MUL_COLS: usize = size_of::<MulCols<u8>>();

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MulCols<T> {
    pub values: [MulValueCols<T>; MUL_DATAPAR],
}

pub const NUM_MUL_VALUE_COLS: usize = size_of::<MulValueCols<u8>>();

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MulValueCols<F> {
    /// The output operand.
    pub a: Word<F>,

    /// The first input operand.
    pub b: Word<F>,

    /// The second input operand.
    pub c: Word<F>,

    /// Trace.
    pub carry: [F; PRODUCT_SIZE],

    /// An array storing the product of `b * c` after the carry propagation.
    pub product: [F; PRODUCT_SIZE],

    /// The most significant bit of `b`.
    pub b_msb: F,

    /// The most significant bit of `c`.
    pub c_msb: F,

    /// The sign extension of `b`.
    pub b_sign_extend: F,

    /// The sign extension of `c`.
    pub c_sign_extend: F,

    /// Flag indicating whether the opcode is `MUL` (`u32 x u32`).
    pub is_mul: F,

    /// Flag indicating whether the opcode is `MULH` (`i32 x i32`, upper half).
    pub is_mulh: F,

    /// Flag indicating whether the opcode is `MULHU` (`u32 x u32`, upper half).
    pub is_mulhu: F,

    /// Flag indicating whether the opcode is `MULHSU` (`i32 x u32`, upper half).
    pub is_mulhsu: F,

    /// Selector to know whether this row is enabled.
    pub is_real: F,
}
