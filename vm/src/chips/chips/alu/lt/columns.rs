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
/// This uses LtSignedGadget which combines:
/// - LtUnsignedGadget for unsigned comparison
/// - U16MSBGadget for MSB extraction of operands
#[derive(AlignedBorrow, Default, Clone, Copy)]
#[repr(C)]
pub struct LtValueCols<F: Copy> {
    /// If the opcode is SLT (signed).
    pub is_slt: F,
    /// If the opcode is SLTU (unsigned).
    pub is_slt_u: F,
    /// The output operand (result of comparison).
    pub a: Word<F>,
    /// The first input operand.
    pub b: Word<F>,
    /// The second input operand.
    pub c: Word<F>,
    /// The signed less-than gadget combining unsigned comparison with MSB extraction.
    /// This contains:
    /// - lt_unsigned: LtUnsignedGadget with byte_flags, comparison bytes
    /// - b_msb: U16MSBGadget for operand b
    /// - c_msb: U16MSBGadget for operand c
    pub lt_signed: crate::chips::gadgets::lt_signed::LtSignedGadget<F>,
}
