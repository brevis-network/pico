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

/// Opcode tag added to the ALU-bus message of a merged branch-comparison row (`is_cmp = 1`):
/// the Cpu's single branch dispatch sends `SLT/SLTU + LT_CMP_OPCODE_TAG` and receives both strict
/// comparison bits from one Lt row. Every other opcode field on the ALU bus is a one-hot sum of
/// `Opcode` discriminants (all `< 2^8`), so `8 + 256` / `9 + 256` can never pair with a plain
/// SLT/SLTU dispatch or with any future opcode. Soundness of this separation needs `is_cmp` to be
/// boolean (see `constraints.rs`).
pub const LT_CMP_OPCODE_TAG: u32 = 1 << 8;

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
    /// Merged branch-comparison row: `a[1]` carries `[b > c]` (else `a[1] = 0`) and the bus
    /// opcode carries `LT_CMP_OPCODE_TAG`. Boolean; zero on padding rows.
    pub is_cmp: F,
}
