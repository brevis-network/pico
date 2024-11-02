use pico_derive::AlignedBorrow;
use std::mem::size_of;

use super::{NUM_BYTE_LOOKUP_CHANNELS, NUM_BYTE_OPS};

/// The number of main trace columns for `ByteChip`.
pub const NUM_BYTE_PREPROCESSED_COLS: usize = size_of::<BytePreprocessedCols<u8>>();

/// The number of multiplicity columns for `ByteChip`.
pub const NUM_BYTE_MULT_COLS: usize = size_of::<ByteMultCols<u8>>();

#[derive(AlignedBorrow, Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct BytePreprocessedCols<T> {
    /// The first byte operand.
    pub b: T,

    /// The second byte operand.
    pub c: T,

    /// The result of the `AND` operation on `b` and `c`
    pub and: T,

    /// The result of the `OR` operation on `b` and `c`
    pub or: T,

    /// The result of the `XOR` operation on `b` and `c`
    pub xor: T,

    /// The result of the `SLL` operation on `b` and `c`
    pub sll: T,

    /// The result of the `ShrCarry` operation on `b` and `c`
    pub shr: T,
    pub shr_carry: T,

    /// The result of the `LTU` operation on `b` and `c`
    pub ltu: T,

    // TODO: maybe this can be moved into RangeCheckChip?
    /// The most significant bit of `b`.
    pub msb: T,
}

/// For each byte operation in the preprocessed table, a corresponding ByteMultCols row tracks the
/// number of times the operation is used.
#[derive(Debug, Clone, Copy, AlignedBorrow)]
#[repr(C)]
pub struct MultiplicitiesCols<T> {
    pub multiplicities: [T; NUM_BYTE_OPS],
}

#[derive(Debug, Clone, Copy, AlignedBorrow)]
#[repr(C)]
pub struct ByteMultCols<T> {
    /// Chunk number is tracked so that the multiplicities do not overflow.
    pub chunk: T,

    /// The multiplicities of each byte operation.
    pub mult_channels: [MultiplicitiesCols<T>; NUM_BYTE_LOOKUP_CHANNELS as usize],
}
