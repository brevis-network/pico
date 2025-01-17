use crate::{
    chips::gadgets::add::AddGadget, compiler::word::Word, primitives::consts::ADD_SUB_DATAPAR,
};
use pico_derive::AlignedBorrow;
use std::mem::size_of;

/// The number of main trace columns for `AddSubChip`.
pub const NUM_ADD_SUB_COLS: usize = size_of::<AddSubCols<u8>>();

#[derive(AlignedBorrow, Clone, Copy, Default)]
#[repr(C)]
pub struct AddSubCols<F> {
    pub values: [AddSubValueCols<F>; ADD_SUB_DATAPAR],
}

pub const NUM_ADD_SUB_VALUE_COLS: usize = size_of::<AddSubValueCols<u8>>();

#[derive(AlignedBorrow, Clone, Copy, Default)]
#[repr(C)]
pub struct AddSubValueCols<F> {
    /// Instance of `AddGadget` to handle addition logic in `AddSubChip`'s ALU operations.
    /// It's result will be `a` for the add operation and `b` for the sub operation.
    pub add_operation: AddGadget<F>,

    /// The first input operand.  This will be `b` for add operations and `c` for sub operations.
    pub operand_1: Word<F>,

    /// The second input operand.  This will be `c` for both operations.
    pub operand_2: Word<F>,

    /// Boolean to indicate whether the row is for an add operation.
    pub is_add: F,

    /// Boolean to indicate whether the row is for a sub operation.
    pub is_sub: F,
}
