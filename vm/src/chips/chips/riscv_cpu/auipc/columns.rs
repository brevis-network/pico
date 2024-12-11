use crate::{
    chips::gadgets::field_range_check::word_range::FieldWordRangeChecker, compiler::word::Word,
};
use pico_derive::AlignedBorrow;
use std::mem::size_of;

pub const NUM_AUIPC_COLS: usize = size_of::<AuipcCols<u8>>();

#[derive(AlignedBorrow, Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct AuipcCols<T> {
    /// The current program counter.
    pub pc: Word<T>,
    pub pc_range_checker: FieldWordRangeChecker<T>,
    pub auipc_nonce: T,
}
