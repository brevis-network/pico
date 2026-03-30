use crate::{
    chips::gadgets::addw::AddwGadget, compiler::word::Word, primitives::consts::ADD_DATAPAR,
};
use pico_derive::AlignedBorrow;
use std::mem::size_of;

/// The number of main trace columns for `AddwChip`.
pub const NUM_ADDW_COLS: usize = size_of::<AddwCols<u8>>();

#[derive(AlignedBorrow, Clone, Copy, Default)]
#[repr(C)]
pub struct AddwCols<F> {
    pub values: [AddwValueCols<F>; ADD_DATAPAR],
}

pub const NUM_ADDW_VALUE_COLS: usize = size_of::<AddwValueCols<u8>>();

#[derive(AlignedBorrow, Clone, Copy, Default)]
#[repr(C)]
pub struct AddwValueCols<F> {
    /// Instance of `AddwGadget` to handle ADDW logic.
    /// Computes the lower 32 bits of `b + c` and tracks the MSB for sign extension.
    pub addw_operation: AddwGadget<F>,

    /// The first input operand (`b` in `a = sign_extend_32(b + c)`), stored as four u16 limbs.
    pub operand_1: Word<F>,

    /// The second input operand (`c` in `a = sign_extend_32(b + c)`), stored as four u16 limbs.
    pub operand_2: Word<F>,

    /// Boolean flag indicating whether this row is an active ADDW operation.
    pub is_addw: F,
}
