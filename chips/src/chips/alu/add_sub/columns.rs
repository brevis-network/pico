use crate::gadgets::add::AddGadget;
use pico_compiler::word::Word;
use pico_derive::AlignedBorrow;
use std::mem::size_of;

/// The number of main trace columns for `AddSubChip`.
pub const NUM_ADD_SUB_COLS: usize = size_of::<AddSubCols<u8>>();

#[derive(AlignedBorrow, Clone, Copy, Default)]
#[repr(C)]
pub struct AddSubCols<T> {
    /// The chunk number, used for byte lookup table.
    pub chunk: T,

    /// The channel number, used for byte lookup table.
    pub channel: T,

    /// The nonce of the operation.
    pub nonce: T,

    /// Instance of `AddGadget` to handle addition logic in `AddSubChip`'s ALU operations.
    /// It's result will be `a` for the add operation and `b` for the sub operation.
    pub add_operation: AddGadget<T>,

    /// The first input operand.  This will be `b` for add operations and `c` for sub operations.
    pub operand_1: Word<T>,

    /// The second input operand.  This will be `c` for both operations.
    pub operand_2: Word<T>,

    /// Boolean to indicate whether the row is for an add operation.
    pub is_add: T,

    /// Boolean to indicate whether the row is for a sub operation.
    pub is_sub: T,
}
