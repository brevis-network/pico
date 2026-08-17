use std::mem::size_of;

use pico_derive::AlignedBorrow;

use crate::{
    chips::{
        chips::riscv_memory::read_write::columns::{MemoryReadCols, MemoryWriteCols},
        gadgets::{
            addr_add::AddrAddGadget, poseidon2::columns::Poseidon2ValueCols,
            syscall_addr::SyscallAddrGadget,
        },
    },
    configs::config::Poseidon2Config,
};

use super::STATE_NUM_DWORDS;

pub const fn num_poseidon2_cols<Config: Poseidon2Config>() -> usize {
    size_of::<Poseidon2Cols<u8, Config>>()
}

#[derive(AlignedBorrow)]
#[repr(C)]
pub struct Poseidon2Cols<T, Config: Poseidon2Config> {
    pub chunk: T,
    pub clk: T,

    /// The input buffer pointer, as 3 u16 limbs, with its alignment and bounds witness.
    ///
    /// This is the encoding the whole machine uses for an address: the syscall bus receives
    /// `arg1` from `SyscallChip` as a 3-limb `Addr` (`chips/syscall/traces.rs`), and the memory
    /// bus tuple is `[chunk, clk, addr[0], addr[1], addr[2], value..]`
    /// (`machine/builder/riscv_memory.rs`). It used to be a single `T` holding the whole
    /// pointer, which matched neither side.
    pub input_memory_ptr: SyscallAddrGadget<T>,
    /// `input_memory_ptr + 8 * i`, carried across limbs.
    pub input_addrs: [AddrAddGadget<T>; STATE_NUM_DWORDS],
    pub input_memory: [MemoryReadCols<T>; STATE_NUM_DWORDS],

    pub output_memory_ptr: SyscallAddrGadget<T>,
    /// `output_memory_ptr + 8 * i`, carried across limbs.
    pub output_addrs: [AddrAddGadget<T>; STATE_NUM_DWORDS],
    pub output_memory: [MemoryWriteCols<T>; STATE_NUM_DWORDS],

    // TODO: is it safe to remove state_linear_layer cols?
    pub value_cols: Poseidon2ValueCols<T, Config>,
}
