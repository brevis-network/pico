use crate::{
    chips::gadgets::subw::SubwGadget, compiler::word::Word, primitives::consts::ADD_DATAPAR,
};
use pico_derive::AlignedBorrow;
use std::mem::size_of;

/// The number of main trace columns for `SubwChip`.
pub const NUM_SUBW_COLS: usize = size_of::<SubwCols<u8>>();

#[derive(AlignedBorrow, Clone, Copy, Default)]
#[repr(C)]
pub struct SubwCols<F> {
    pub values: [SubwValueCols<F>; ADD_DATAPAR],
}

pub const NUM_SUBW_VALUE_COLS: usize = size_of::<SubwValueCols<u8>>();

#[derive(AlignedBorrow, Clone, Copy, Default)]
#[repr(C)]
pub struct SubwValueCols<F> {
    /// Instance of `Subw64Gadget` to handle SUBW logic.
    /// Computes `(b as i32).wrapping_sub(c as i32)` sign-extended, and tracks the MSB.
    pub subw_operation: SubwGadget<F>,

    /// The first input operand (`b` in `a = sign_extend_32(b - c)`), stored as four u16 limbs.
    pub operand_1: Word<F>,

    /// The second input operand (`c` in `a = sign_extend_32(b - c)`), stored as four u16 limbs.
    pub operand_2: Word<F>,

    /// Boolean flag indicating whether this row is an active SUBW operation.
    pub is_subw: F,
}
