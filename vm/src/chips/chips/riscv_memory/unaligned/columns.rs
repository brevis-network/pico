use crate::{
    chips::{
        chips::riscv_memory::read_write::columns::{
            MemoryInstructionCols, MemoryReadWriteLiteCols,
        },
        gadgets::{code_range::CodeRangeCols, u16_to_u8::U16ToU8Gadget},
    },
    compiler::word::Word,
};
use pico_derive::AlignedBorrow;
use std::mem::size_of;

pub const NUM_MEMORY_UNALIGNED_COLS: usize = size_of::<MemoryUnalignedCols<u8>>();

/// The bytes in a dword.
pub const DWORD_BYTES: usize = 8;

/// One load or store.
#[derive(AlignedBorrow, Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct MemoryUnalignedCols<F> {
    /// The chunk and the instruction's clk, both bound to the Cpu row by the dispatch lookup.
    pub chunk: F,
    pub clk: F,

    /// The address `op_b + op_c` as two u16 limbs, proven by the same in-chip carry chain as
    /// `MemoryReadWrite`'s: a guest address lies below `2^32`.
    pub addr_word: [F; 2],
    /// `1 / addr_word[1]`: the access lies at or above `2^16`. The next dword lies above it.
    pub addr_limb1_inv: F,
    /// The address's byte offset in its dword, one-hot: `offset[k] = 1` for `addr mod 8 = k`.
    pub offset: [F; DWORD_BYTES],
    /// The access runs past its dword into the next one.
    pub cross: F,
    /// The next dword's address carries into limb 1: the access's dword is the last of its
    /// 64 KiB, at a low limb of `0xfff8`.
    pub next_carry: F,
    /// `1 / (low limb of the dword - 0xfff8)`, where the next dword's address does not carry.
    pub next_carry_inv: F,

    /// The access to the dword that holds the first byte, at `clk + Memory`.
    pub first: MemoryReadWriteLiteCols<F>,
    /// The access to the next dword, at `clk + C`, on a row that crosses; all zero on one that
    /// does not.
    pub second: MemoryReadWriteLiteCols<F>,
    /// The low byte of each limb of the two dwords' previous values; the high bytes are affine
    /// in these and the limbs.
    pub first_bytes: U16ToU8Gadget<F>,
    pub second_bytes: U16ToU8Gadget<F>,
    /// The low byte of each limb of `op_a`, the value a store writes.
    pub value_bytes: U16ToU8Gadget<F>,

    /// The eight bytes from the address on, across the two dwords, as four limbs: what a load
    /// reads, before its sign or zero fill.
    pub seen: Word<F>,
    /// The first of those bytes, which a byte load reads.
    pub seen_byte: F,
    /// The value whose bit 15 is a signed load's sign: `256 * seen_byte` on LB, `seen[0]` on LH
    /// and `seen[1]` on LW.
    pub sign_src: F,
    /// A signed load's sign bit; zero on the unsigned loads and on LD.
    pub msb: F,

    pub instruction: MemoryInstructionCols<F>,

    /// A store misses the program's code, as in `MemoryReadWrite`; free on a load row.
    pub code_range: CodeRangeCols<F>,
}
