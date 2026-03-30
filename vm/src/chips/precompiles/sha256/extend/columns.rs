use crate::chips::{
    chips::riscv_memory::read_write::columns::{MemoryReadCols, MemoryWriteCols},
    gadgets::{
        addr_add::AddrAddGadget,
        u32::{
            add4_u32::Add4U32Gadget, rotate_right_u32::FixedRotateRightU32Gadget,
            shift_right_u32::FixedShiftRightU32Gadget, xor_u32::XorU32Gadget,
        },
    },
};
use pico_derive::AlignedBorrow;
use std::mem::size_of;

pub const NUM_SHA_EXTEND_COLS: usize = size_of::<ShaExtendCols<u8>>();

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct ShaExtendCols<T> {
    /// Inputs.
    pub chunk: T,
    pub clk: T,
    pub w_ptr: [T; 3],
    pub w_i_minus_15_ptr: AddrAddGadget<T>,
    pub w_i_minus_2_ptr: AddrAddGadget<T>,
    pub w_i_minus_16_ptr: AddrAddGadget<T>,
    pub w_i_minus_7_ptr: AddrAddGadget<T>,
    pub w_i_ptr: AddrAddGadget<T>,

    /// Control flags.
    pub i: T,

    /// Inputs to `s0`.
    pub w_i_minus_15: MemoryReadCols<T>,
    pub w_i_minus_15_rr_7: FixedRotateRightU32Gadget<T>,
    pub w_i_minus_15_rr_18: FixedRotateRightU32Gadget<T>,
    pub w_i_minus_15_rs_3: FixedShiftRightU32Gadget<T>,
    pub s0_intermediate: XorU32Gadget<T>,

    /// `s0 := (w[i-15] rightrotate  7) xor (w[i-15] rightrotate 18) xor (w[i-15] rightshift 3)`.
    pub s0: XorU32Gadget<T>,

    /// Inputs to `s1`.
    pub w_i_minus_2: MemoryReadCols<T>,
    pub w_i_minus_2_rr_17: FixedRotateRightU32Gadget<T>,
    pub w_i_minus_2_rr_19: FixedRotateRightU32Gadget<T>,
    pub w_i_minus_2_rs_10: FixedShiftRightU32Gadget<T>,
    pub s1_intermediate: XorU32Gadget<T>,

    /// `s1 := (w[i-2] rightrotate 17) xor (w[i-2] rightrotate 19) xor (w[i-2] rightshift 10)`.
    pub s1: XorU32Gadget<T>,

    /// Inputs to `s2`.
    pub w_i_minus_16: MemoryReadCols<T>,
    pub w_i_minus_7: MemoryReadCols<T>,

    /// `w[i] := w[i-16] + s0 + w[i-7] + s1`.
    pub s2: Add4U32Gadget<T>,

    /// Result.
    pub w_i: MemoryWriteCols<T>,

    /// Selector.
    pub is_real: T,
}
