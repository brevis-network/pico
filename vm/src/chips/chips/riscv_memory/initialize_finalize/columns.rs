use crate::{
    chips::gadgets::{is_zero::IsZeroGadget, lt_word_u16::LtWordU16Gadget},
    compiler::word::Word,
};
use core::mem::size_of;
use pico_derive::AlignedBorrow;

pub(crate) const NUM_MEMORY_INITIALIZE_FINALIZE_COLS: usize =
    size_of::<MemoryInitializeFinalizeCols<u8>>();

#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct MemoryInitializeFinalizeCols<T> {
    /// The chunk number of the memory access.
    pub chunk: T,

    /// The timestamp of the memory access.
    pub timestamp: T,

    /// The address of the memory access, as 3×u16 limbs (little-endian, 48-bit address space).
    pub addr: [T; 3],

    /// The address of the previous memory access, as 3×u16 limbs (little-endian).
    /// On the first row, this comes from public values; on subsequent rows, from the previous row's addr.
    pub prev_addr: [T; 3],

    /// Comparison gadget for asserting `prev_addr < addr` using u16 limb comparison.
    /// Replaces the old bit-level AssertLtColsBits<T, 32>.
    pub lt_cols: LtWordU16Gadget<T>,

    /// The value of the memory access, as 4×u16 limbs (Word<T>).
    /// Replaces the old 32 bit-cols value decomposition.
    pub value: Word<T>,

    /// Lower byte of the third value limb (value.0[2] & 0xFF).
    /// Used for v2 packing trick in the Global message.
    pub value_lower: T,

    /// Upper byte of the third value limb ((value.0[2] >> 8) & 0xFF).
    /// Used for v2 packing trick in the Global message.
    pub value_upper: T,

    /// Whether the memory access is a real access.
    pub is_real: T,

    /// Whether or not we are making the comparison assertion `prev_addr < addr`.
    /// Equal to `is_real * (1 - is_prev_addr_zero.result)` on the first row,
    /// and `is_real` on subsequent rows.
    pub is_comp: T,

    /// A witness to assert whether or not the previous address is zero.
    /// Uses the sum of prev_addr u16 limbs as input.
    pub is_prev_addr_zero: IsZeroGadget<T>,
}
