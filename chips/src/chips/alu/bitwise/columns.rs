use core::mem::size_of;
use pico_compiler::word::Word;
use pico_derive::AlignedBorrow;

/// The number of main trace columns for `BitwiseChip`.
pub const NUM_BITWISE_COLS: usize = size_of::<BitwiseCols<u8>>();

/// The column layout for the chip.
#[derive(AlignedBorrow, Clone, Copy, Default)]
#[repr(C)]
pub struct BitwiseCols<T> {
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

    /// If the opcode is XOR.
    pub is_xor: T,

    // If the opcode is OR.
    pub is_or: T,

    /// If the opcode is AND.
    pub is_and: T,

    /// TODO: Delete after all ALU opcodes integration.
    /// Boolean to indicate whether lookup is supported.
    pub is_lookup_supported: T,
}
