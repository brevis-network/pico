use pico_derive::AlignedBorrow;

use crate::chips::chips::recursion_memory_v2::MemoryAccessCols;

pub const NUM_EXP_REVERSE_BITS_LEN_COLS: usize = core::mem::size_of::<ExpReverseBitsLenCols<u8>>();
pub const NUM_EXP_REVERSE_BITS_LEN_PREPROCESSED_COLS: usize =
    core::mem::size_of::<ExpReverseBitsLenPreprocessedCols<u8>>();

#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct ExpReverseBitsLenPreprocessedCols<T: Copy> {
    pub x_mem: MemoryAccessCols<T>,
    pub exponent_mem: MemoryAccessCols<T>,
    pub result_mem: MemoryAccessCols<T>,
    pub iteration_num: T,
    pub is_first: T,
    pub is_last: T,
    pub is_real: T,
}

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct ExpReverseBitsLenCols<T: Copy> {
    /// The base of the exponentiation.
    pub x: T,

    /// The current bit of the exponent. This is read from memory.
    pub current_bit: T,

    /// The previous accumulator squared.
    pub prev_accum_squared: T,

    /// Is set to the value local.prev_accum_squared * local.multiplier.
    pub prev_accum_squared_times_multiplier: T,

    /// The accumulator of the current iteration.
    pub accum: T,

    /// The accumulator squared.
    pub accum_squared: T,

    /// A column which equals x if `current_bit` is on, and 1 otherwise.
    pub multiplier: T,
}
