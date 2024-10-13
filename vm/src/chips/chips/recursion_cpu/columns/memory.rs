use crate::chips::chips::recursion_memory::MemoryReadWriteCols;
use pico_derive::AlignedBorrow;
use std::mem::size_of;

#[allow(dead_code)]
pub const NUM_MEMORY_COLS: usize = size_of::<MemoryCols<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryCols<T> {
    pub(crate) memory_addr: T,
    pub(crate) memory: MemoryReadWriteCols<T>,
}
