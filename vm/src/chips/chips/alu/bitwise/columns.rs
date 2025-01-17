use crate::{compiler::word::Word, primitives::consts::BITWISE_DATAPAR};
use pico_derive::AlignedBorrow;
use std::mem::size_of;

/// The number of main trace columns for `BitwiseChip`.
pub const NUM_BITWISE_COLS: usize = size_of::<BitwiseCols<u8>>();

/// The column that contains multiple value columns
#[derive(AlignedBorrow, Clone, Copy, Default)]
#[repr(C)]
pub struct BitwiseCols<T> {
    pub values: [BitwiseValueCols<T>; BITWISE_DATAPAR],
}

pub const NUM_BITWISE_VALUE_COLS: usize = size_of::<BitwiseValueCols<u8>>();

/// The column layout for the chip.
#[derive(AlignedBorrow, Clone, Copy, Default)]
#[repr(C)]
pub struct BitwiseValueCols<T> {
    /// The chunk number, used for byte lookup table.
    pub chunk: T,

    /// The output operand.
    pub a: Word<T>,

    /// The first input operand.
    pub b: Word<T>,

    /// The second input operand.
    pub c: Word<T>,

    /// If the opcode is XOR.
    pub is_xor: T,

    // If the opcode is OR.
    pub is_or: T,

    /// If the opcode is AND.
    pub is_and: T,
}
