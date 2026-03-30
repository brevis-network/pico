use crate::{
    chips::gadgets::sub::SubGadget, compiler::word::Word, primitives::consts::ADD_DATAPAR,
};
use pico_derive::AlignedBorrow;
use std::mem::size_of;

/// The number of main trace columns for `Sub64Chip`.
pub const NUM_SUB_COLS: usize = size_of::<SubCols<u8>>();

#[derive(AlignedBorrow, Clone, Copy, Default)]
#[repr(C)]
pub struct SubCols<F> {
    pub values: [SubValueCols<F>; ADD_DATAPAR],
}

pub const NUM_SUB_VALUE_COLS: usize = size_of::<SubValueCols<u8>>();

#[derive(AlignedBorrow, Clone, Copy, Default)]
#[repr(C)]
pub struct SubValueCols<F> {
    /// Instance of `SubGadget` to handle 64-bit subtraction logic.
    /// Its result (`sub_operation.value`) is `a` = `b` - `c`.
    pub sub_operation: SubGadget<F>,

    /// The first input operand (`b` in `a = b - c`), the minuend, stored as four u16 limbs.
    pub operand_1: Word<F>,

    /// The second input operand (`c` in `a = b - c`), the subtrahend, stored as four u16 limbs.
    pub operand_2: Word<F>,

    /// Boolean flag indicating whether this row is an active SUB operation.
    pub is_sub: F,
}
