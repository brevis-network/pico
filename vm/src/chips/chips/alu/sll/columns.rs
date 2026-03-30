use crate::{
    chips::gadgets::msb::U16MSBGadget, compiler::word::Word, primitives::consts::SLL_DATAPAR,
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
    /// The output operand.
    pub a: Word<F>,

    /// The input operand
    pub b: Word<F>,

    /// The input operand
    pub c: Word<F>,

    /// The lowerst byte of `c`.
    pub c_bits: [F; 6],

    /// v01 = (c0 + 1) * (3c1 + 1)
    pub v_01: F,

    /// v012 = (c0 + 1) * (3c1 + 1) * (15c2 + 1)
    pub v_012: F,

    /// v012 * c3
    pub v_0123: F,

    /// Flags representing c4 + 2c5.
    pub shift_u16: [F; 4],

    /// The lower bits of each limb.
    pub lower_limb: Word<F>,

    /// The higher bits of each limb.
    pub higher_limb: Word<F>,

    /// The limb results.
    pub limb_result: Word<F>,

    /// The most significant byte of the result of SLLW.
    pub sllw_msb: U16MSBGadget<F>,

    /// If the opcode is SLL.
    pub is_sll: F,

    /// If the opcode is SLLW.
    pub is_sllw: F,
}
