use crate::{
    chips::gadgets::add::AddGadget, compiler::word::Word, primitives::consts::ADD_DATAPAR,
};
use pico_derive::AlignedBorrow;
use std::mem::size_of;

/// The number of main trace columns for `AddChip`.
pub const NUM_ADD_COLS: usize = size_of::<AddCols<u8>>();

#[derive(AlignedBorrow, Clone, Copy, Default)]
#[repr(C)]
pub struct AddCols<F> {
    pub values: [AddValueCols<F>; ADD_DATAPAR],
}

pub const NUM_ADD_VALUE_COLS: usize = size_of::<AddValueCols<u8>>();

#[derive(AlignedBorrow, Clone, Copy, Default)]
#[repr(C)]
pub struct AddValueCols<F> {
    /// Instance of `AddGadget` to handle 64-bit addition logic.
    /// Its result (`add_operation.value`) is `a` = `b` + `c`.
    pub add_operation: AddGadget<F>,

    /// The first input operand (`b` in `a = b + c`), stored as four u16 limbs.
    pub operand_1: Word<F>,

    /// The second input operand (`c` in `a = b + c`), stored as four u16 limbs.
    pub operand_2: Word<F>,

    /// Boolean flag indicating whether this row is an active ADD operation.
    pub is_add: F,
}
