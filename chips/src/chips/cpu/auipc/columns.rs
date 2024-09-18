use crate::gadgets::baby_bear_word::BabyBearWordRangeChecker;
use pico_derive::AlignedBorrow;
use pico_machine::word::Word;
use std::mem::size_of;

pub const NUM_AUIPC_COLS: usize = size_of::<AuipcCols<u8>>();

#[derive(AlignedBorrow, Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct AuipcCols<T> {
    /// The current program counter.
    pub pc: Word<T>,
    pub pc_range_checker: BabyBearWordRangeChecker<T>,
    pub auipc_nonce: T,
}
