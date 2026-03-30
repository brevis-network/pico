use std::mem::size_of;

use crate::{
    chips::gadgets::mul::MulGadget, compiler::word::Word, primitives::consts::MUL_DATAPAR,
};
use pico_derive::AlignedBorrow;

/// The number of main trace columns for `MulChip`.
pub const NUM_MUL_COLS: usize = size_of::<MulCols<u8>>();

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MulCols<T: Copy> {
    pub values: [MulValueCols<T>; MUL_DATAPAR],
}

pub const NUM_MUL_VALUE_COLS: usize = size_of::<MulValueCols<u8>>();

/// The column layout for the chip.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MulValueCols<F: Copy> {
    /// The output operand.
    pub a: Word<F>,

    /// The first input operand.
    pub b: Word<F>,

    /// The second input operand.
    pub c: Word<F>,

    /// Instance of `MulGadget` to handle multiplication logic in `MulChip`'s ALU operations.
    pub mul_gadget: MulGadget<F>,

    /// Flag indicating whether the opcode is `MUL` (`u32 x u32`).
    pub is_mul: F,

    /// Flag indicating whether the opcode is `MULH` (`i32 x i32`, upper half).
    pub is_mulh: F,

    /// Flag indicating whether the opcode is `MULHU` (`u32 x u32`, upper half).
    pub is_mulhu: F,

    /// Flag indicating whether the opcode is `MULHSU` (`i32 x u32`, upper half).
    pub is_mulhsu: F,

    /// Flag indicating whether the opcode is `MULW` (32-bit multiplication, sign-extended result).
    pub is_mulw: F,
}
