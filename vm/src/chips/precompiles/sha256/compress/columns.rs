use crate::chips::{
    chips::riscv_memory::read_write::columns::MemoryReadWriteCols,
    gadgets::{
        addr_add::AddrAddGadget,
        u32::{
            add5_u32::Add5U32Gadget, add_u32::AddU32Gadget, and_u32::AndU32Gadget,
            not_u32::NotU32Gadget, rotate_right_u32::FixedRotateRightU32Gadget,
            xor_u32::XorU32Gadget,
        },
    },
};
use pico_derive::AlignedBorrow;
use std::mem::size_of;

pub const NUM_SHA_COMPRESS_COLS: usize = size_of::<ShaCompressCols<u8>>();

/// A set of columns needed to compute the SHA-256 compression function.
///
/// Each sha compress syscall is processed over 80 columns, split into 10 octets. The first octet is
/// for initialization, the next 8 octets are for compression, and the last octet is for finalize.
/// During init, the columns are initialized with the input values, one word at a time. During each
/// compression cycle, one iteration of sha compress is computed. During finalize, the columns are
/// combined and written back to memory.
#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct ShaCompressCols<T> {
    /// Inputs.
    pub chunk: T,
    pub clk: T,
    pub w_ptr: [T; 3],
    pub h_ptr: [T; 3],

    pub index: T,

    /// Which cycle within the octet we are currently processing.
    pub octet: [T; 8],

    /// This will specify which octet we are currently processing.
    ///  - The first octet is for initialize.
    ///  - The next 8 octets are for compress.
    ///  - The last octet is for finalize.
    pub octet_num: [T; 10],

    /// Memory access. During init and compression, this is read only. During finalize, this is
    /// used to write the result into memory.
    pub mem: MemoryReadWriteCols<T>,

    /// The write value to the memory.
    pub mem_value: [T; 2],

    /// Current memory address being written/read. During init and finalize, this is A-H. During
    /// compression, this is w[i] being read only.
    pub mem_addr: [T; 3],

    pub mem_addr_init: AddrAddGadget<T>,
    pub mem_addr_compress: AddrAddGadget<T>,
    pub mem_addr_finalize: AddrAddGadget<T>,

    pub a: [T; 2],
    pub b: [T; 2],
    pub c: [T; 2],
    pub d: [T; 2],
    pub e: [T; 2],
    pub f: [T; 2],
    pub g: [T; 2],
    pub h: [T; 2],

    /// Current value of K[i]. This is a constant array that loops around every 64 iterations.
    pub k: [T; 2],

    pub e_rr_6: FixedRotateRightU32Gadget<T>,
    pub e_rr_11: FixedRotateRightU32Gadget<T>,
    pub e_rr_25: FixedRotateRightU32Gadget<T>,
    pub s1_intermediate: XorU32Gadget<T>,
    /// `S1 := (e rightrotate 6) xor (e rightrotate 11) xor (e rightrotate 25)`.
    pub s1: XorU32Gadget<T>,

    pub e_and_f: AndU32Gadget<T>,
    pub e_not: NotU32Gadget<T>,
    pub e_not_and_g: AndU32Gadget<T>,
    /// `ch := (e and f) xor ((not e) and g)`.
    pub ch: XorU32Gadget<T>,

    /// `temp1 := h + S1 + ch + k[i] + w[i]`.
    pub temp1: Add5U32Gadget<T>,

    pub a_rr_2: FixedRotateRightU32Gadget<T>,
    pub a_rr_13: FixedRotateRightU32Gadget<T>,
    pub a_rr_22: FixedRotateRightU32Gadget<T>,
    pub s0_intermediate: XorU32Gadget<T>,
    /// `S0 := (a rightrotate 2) xor (a rightrotate 13) xor (a rightrotate 22)`.
    pub s0: XorU32Gadget<T>,

    pub a_and_b: AndU32Gadget<T>,
    pub a_and_c: AndU32Gadget<T>,
    pub b_and_c: AndU32Gadget<T>,
    pub maj_intermediate: XorU32Gadget<T>,
    /// `maj := (a and b) xor (a and c) xor (b and c)`.
    pub maj: XorU32Gadget<T>,

    /// `temp2 := S0 + maj`.
    pub temp2: AddU32Gadget<T>,

    /// The next value of `e` is `d + temp1`.
    pub d_add_temp1: AddU32Gadget<T>,
    /// The next value of `a` is `temp1 + temp2`.
    pub temp1_add_temp2: AddU32Gadget<T>,

    /// During finalize, this is one of a-h and is being written into `mem`.
    pub finalized_operand: [T; 2],
    pub finalize_add: AddU32Gadget<T>,

    pub is_initialize: T,
    pub is_compression: T,
    pub is_finalize: T,

    pub is_real: T,
}
