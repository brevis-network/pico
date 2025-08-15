use hashbrown::HashMap;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::{
    chips::chips::riscv_memory::event::MemoryRecord,
    emulator::riscv::{memory::Memory, syscalls::SyscallCode},
};

/// Holds data describing the current state of a program's emulation.
#[serde_as]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RiscvEmulationState {
    /// The global clock keeps track of how many instructions have been emulated through all chunks.
    pub global_clk: u64,

    /// Current batch number
    pub current_batch: u32,

    /// The chunk clock keeps track of how many chunks have been emulated.
    pub current_chunk: u32,

    /// The execution chunk clock keeps track of how many chunks with cpu events have been emulated.
    pub current_execution_chunk: u32,

    /// The clock increments by 4 (possibly more in syscalls) for each instruction that has been
    /// emulated in this chunk.
    pub clk: u32,

    /// The program counter.
    pub pc: u32,

    /// Uninitialized memory addresses that have a specific value they should be initialized with.
    /// SyscallHintRead uses this to write hint data into uninitialized memory.
    // #[serde(
    //     serialize_with = "serialize_hashmap_as_vec",
    //     deserialize_with = "deserialize_hashmap_as_vec"
    // )]
    pub uninitialized_memory: Memory<u32>,

    /// A stream of input values (global to the entire program).
    pub input_stream: Vec<Vec<u8>>,

    /// A ptr to the current position in the input stream incremented by HINT_READ opcode.
    pub input_stream_ptr: usize,

    /// A stream of public values from the program (global to entire program).
    pub public_values_stream: Vec<u8>,

    /// A ptr to the current position in the public values stream, incremented when reading from
    /// public_values_stream.
    pub public_values_stream_ptr: usize,

    pub memory: Memory<MemoryRecord>,

    /// Keeps track of how many times a certain syscall has been called.
    pub syscall_counts: HashMap<SyscallCode, u64>,
}

impl RiscvEmulationState {
    #[must_use]
    /// Create a new [`EmulationState`].
    pub fn new(pc_start: u32) -> Self {
        Self {
            global_clk: 0,
            current_batch: 0,
            // Start at chunk 1 since chunk 0 is reserved for memory initialization.
            current_chunk: 1,
            current_execution_chunk: 1,
            clk: 0,
            pc: pc_start,
            ..Default::default()
        }
    }
}
