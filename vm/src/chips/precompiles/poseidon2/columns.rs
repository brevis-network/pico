use std::mem::size_of;

use pico_derive::AlignedBorrow;

use crate::{
    chips::{
        chips::riscv_memory::read_write::columns::{MemoryReadCols, MemoryWriteCols},
        gadgets::{
            addr_add::AddrAddGadget, field_range_check::word_range::FieldWordRangeChecker,
            poseidon2::columns::Poseidon2ValueCols, syscall_addr::SyscallAddrGadget,
        },
    },
    configs::config::Poseidon2Config,
    primitives::consts::PERMUTATION_WIDTH,
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

    /// `state[j] < p` for each of the 16 state words read from guest memory.
    ///
    /// One per *state word*, not per dword: a dword carries two of them, and each is compared
    /// on its own two u16 limbs. Indexed by state word, so dword `i` owns entries `2i` and
    /// `2i + 1`.
    ///
    /// Needed because `F::from_u32` on the emulator side reduces silently, so a guest word at
    /// or above `p` would emulate as `word - p` and the AIR would have no way to say the two
    /// disagree. The syscall now rejects such a word up front
    /// (`syscalls/precompiles/poseidon2/permute.rs`); this is the proving-side half of that
    /// agreement.
    pub input_range_checkers: [FieldWordRangeChecker<T>; PERMUTATION_WIDTH],

    /// `state[j] < p` for each of the 16 state words written back to guest memory.
    ///
    /// This is the load-bearing one. The output binding in `constraints.rs` pins only a weighted
    /// sum of u16 limbs *modulo the field order*, so `state[j] + p` -- and sometimes `+ 2p` --
    /// satisfies the same equation inside `[0, 2^32)`. Without this the prover chooses which of
    /// those representatives lands in guest memory, which is a soundness gap rather than an
    /// unfinished port.
    pub output_range_checkers: [FieldWordRangeChecker<T>; PERMUTATION_WIDTH],

    // TODO: is it safe to remove state_linear_layer cols?
    pub value_cols: Poseidon2ValueCols<T, Config>,
}
