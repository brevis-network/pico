pub mod constant;
pub mod variable;

use crate::compiler::recursion::{
    ir::Block,
    types::{Address, MemIo},
};
use pico_derive::AlignedBorrow;

pub const NUM_MEM_ACCESS_COLS: usize = core::mem::size_of::<MemoryAccessCols<u8>>();

use serde::{Deserialize, Serialize};

/// Data describing in what manner to access a particular memory block.
#[derive(AlignedBorrow, Debug, Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[repr(C)]
pub struct MemoryAccessCols<F> {
    /// The address to access.
    pub addr: Address<F>,
    /// The multiplicity which to read/write.
    /// "Positive" values indicate a write, and "negative" values indicate a read.
    pub mult: F,
}

impl<F: Copy> From<&(Address<F>, F)> for MemoryAccessCols<F> {
    fn from(value: &(Address<F>, F)) -> Self {
        Self {
            addr: value.0,
            mult: value.1,
        }
    }
}

impl<F: Copy> From<(Address<F>, F)> for MemoryAccessCols<F> {
    fn from(value: (Address<F>, F)) -> Self {
        Self::from(&value)
    }
}

pub type MemEvent<F> = MemIo<Block<F>>;
