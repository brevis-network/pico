use crate::{compiler::word::Word, primitives::consts::LOCAL_MEMORY_DATAPAR};
use pico_derive::AlignedBorrow;
use std::mem::size_of;

pub const NUM_MEMORY_LOCAL_INIT_COLS: usize = size_of::<MemoryLocalCols<u8>>();
pub const NUM_SINGLE_MEMORY_LOCAL_COLS: usize = size_of::<SingleMemoryLocal<u8>>();

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

    /// Whether this entry *receives* its initial state from the Global bus.
    ///
    /// Zero on a *fresh* entry (`riscv_memory/event.rs`, `is_fresh_local_mem`): the first touch
    /// in the whole execution of a main-memory word outside the program image that starts at
    /// zero. Such an entry declares its initial state instead: the AIR pins `initial_value` to
    /// zero on it and sends no Global receive, and the emulator raises no MemoryInitialize event
    /// for its address. The memory argument's sources for an address are then the
    /// MemoryInitialize row, the image digest or this declaration, and Global balance still
    /// forces exactly one source per finalized address (see `constraints.rs`).
    ///
    /// One on every other real entry (registers, image words, hint-written words, intervals that
    /// inherit their start from an earlier chunk), which are unchanged. Zero on padding rows
    /// (constrained), so it doubles as the degree-1 multiplicity of the Global receive.
    pub has_initial: T,

    /// Whether this entry's interval *starts inside this chunk* (`initial_chunk == final_chunk`).
    ///
    /// An address can have several intervals in one chunk — a syscall splits one whenever it
    /// touches an address the CPU also touched — but only the first of them inherits its start
    /// from an earlier chunk. That one gets a `clk` sentinel on the memory bus, because its real
    /// `initial_clk` belongs to a chunk whose clock has already been reset and would fail the
    /// monotonicity check. The rest carry their real `initial_clk`: see `initial_clk_regional`.
    ///
    /// Zero on padding rows (constrained), so it doubles as a degree-1 lookup multiplicity.
    pub initial_in_chunk: T,

    /// The `clk` this entry puts on the *regional* memory bus for its initial state: the real
    /// `initial_clk` when the interval starts in this chunk, and the sentinel `0` when it starts
    /// in an earlier one. Materialized because a lookup message has to be affine and
    /// `initial_in_chunk * initial_clk` is degree 2.
    ///
    /// The Global message keeps the real `(initial_chunk, initial_clk)` either way, so the
    /// cross-chunk multiset chain is untouched.
    pub initial_clk_regional: T,

    /// `final_clk - initial_clk - 1` in a 16 + 9 limb decomposition, proving
    /// `initial_clk < final_clk` on entries whose interval starts in this chunk.
    ///
    /// Also rules out the entry whose two Global messages carry the same payload (`initial_clk
    /// == final_clk` with equal values), which is otherwise free to add.
    pub clk_diff_16bit_limb: T,
    pub clk_diff_hi9: T,
}

#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct MemoryLocalCols<T> {
    pub memory_local_entries: [SingleMemoryLocal<T>; LOCAL_MEMORY_DATAPAR],
}
