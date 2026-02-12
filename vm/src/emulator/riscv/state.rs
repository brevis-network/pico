use hashbrown::HashMap;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::emulator::riscv::{memory::Memory, syscalls::SyscallCode};

// Re-export ContiguousRiscvMemory for use in other modules
pub use crate::emulator::riscv::memory::ContiguousRiscvMemory;

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

    /// The main memory using the new contiguous memory model.
    /// Registers are stored at addresses 0-127 (32 registers × 4 bytes).
    /// Main memory starts at address 128.
    pub memory: ContiguousRiscvMemory,

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
            memory: ContiguousRiscvMemory::new(),
            ..Default::default()
        }
    }

    /// Clone the state without copying memory data (fast, ~1ms).
    ///
    /// The `memory` field will be a fresh zeroed memory (using `new()`)
    /// instead of copying the full memory data from the original.
    ///
    /// This is useful for snapshot states where memory will be populated
    /// separately from a snapshot or rolled back.
    pub fn clone_without_memory(&self) -> Self {
        let uninitialized_memory = Default::default();
        let input_stream = self.input_stream.clone();
        let public_values_stream = self.public_values_stream.clone();
        let syscall_counts = self.syscall_counts.clone();

        // Get a pre-allocated memory from the pool (blocking wait).
        // This will block if the pool is empty (e.g. all items in use).
        let memory = crate::emulator::riscv::memory::GLOBAL_MEMORY_POOL
            .1
            .recv()
            .expect("Global memory pool channel closed");

        Self {
            global_clk: self.global_clk,
            current_batch: self.current_batch,
            current_chunk: self.current_chunk,
            current_execution_chunk: self.current_execution_chunk,
            clk: self.clk,
            pc: self.pc,
            uninitialized_memory,
            input_stream,
            input_stream_ptr: self.input_stream_ptr,
            public_values_stream,
            public_values_stream_ptr: self.public_values_stream_ptr,
            // Use pooled memory or new() for fast zeroed allocation
            memory,
            syscall_counts,
        }
    }
}
