use crate::{compiler::word::Word, primitives::consts::LOCAL_MEMORY_DATAPAR};
use pico_derive::AlignedBorrow;
use std::mem::size_of;

pub const NUM_MEMORY_LOCAL_INIT_COLS: usize = size_of::<MemoryLocalCols<u8>>();

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct SingleMemoryLocal<T> {
    /// The address of the memory access, split into 3×u16 limbs.
    pub addr: [T; 3],

    /// The initial chunk of the memory access.
    pub initial_chunk: T,

    /// The final chunk of the memory access.
    pub final_chunk: T,

    /// The initial clk of the memory access.
    pub initial_clk: T,

    /// The final clk of the memory access.
    pub final_clk: T,

    /// The initial value of the memory access (4×u16 limbs).
    pub initial_value: Word<T>,

    /// The final value of the memory access (4×u16 limbs).
    pub final_value: Word<T>,

    /// v2 packing trick: initial_value[2] = initial_value_lower + initial_value_upper * 256
    pub initial_value_lower: T,
    pub initial_value_upper: T,

    /// v2 packing trick: final_value[2] = final_value_lower + final_value_upper * 256
    pub final_value_lower: T,
    pub final_value_upper: T,

    /// Whether the memory access is a real access.
    pub is_real: T,
}

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryLocalCols<T> {
    pub memory_local_entries: [SingleMemoryLocal<T>; LOCAL_MEMORY_DATAPAR],
}
