use hashbrown::HashMap;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::emulator::riscv::{
    event_types::{RvAddr, RvChunk, RvClk, RvTimestamp, RvValue},
    memory::Memory64,
    syscalls::SyscallCode,
};

// Re-export ContiguousRiscvMemory for use in other modules
pub use crate::emulator::riscv::memory::ContiguousRiscvMemory;

#[derive(Debug, Copy, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeRegisterRecord {
    pub chunk: RvChunk,
    pub timestamp: RvTimestamp,
    pub value: RvValue,
}

/// Holds data describing the current state of a program's emulation.
#[serde_as]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RiscvEmulationState {
    /// The global clock keeps track of how many instructions have been emulated through all chunks.
    pub global_clk: RvClk,

    /// Current batch number
    pub current_batch: u32,

    /// The chunk clock keeps track of how many chunks have been emulated.
    pub current_chunk: RvChunk,

    /// The clock increments by 4 (possibly more in syscalls) for each instruction that has been
    /// emulated in this chunk.
    pub clk: RvClk,

    /// The program counter.
    pub pc: RvAddr,

    /// Architectural integer registers x0..x31.
    pub registers: [RuntimeRegisterRecord; 32],

    /// Uninitialized memory addresses that have a specific value they should be initialized with.
    /// Hint reads store sparse aligned dword state here so postprocess can emit the exact
    /// initialization values that entered guest memory.
    pub uninitialized_memory: Memory64<u64>,

    /// A stream of input values (global to the entire program).
    pub input_stream: Vec<Vec<u8>>,

    /// A ptr to the current position in the input stream incremented by HINT_READ opcode.
    pub input_stream_ptr: usize,

    /// A stream of public values from the program (global to entire program).
    pub public_values_stream: Vec<u8>,

    /// Main memory using the contiguous byte-addressed memory model.
    /// Architectural registers are stored separately in `registers`.
    pub memory: ContiguousRiscvMemory,

    /// Keeps track of how many times a certain syscall has been called.
    pub syscall_counts: HashMap<SyscallCode, u64>,
}

impl RiscvEmulationState {
    #[must_use]
    /// Create a new [`EmulationState`].
    pub fn new(pc_start: RvAddr) -> Self {
        Self {
            global_clk: 0,
            current_batch: 0,
            // Start at chunk 1 since chunk 0 is reserved for memory initialization.
            current_chunk: 1,
            clk: 0,
            pc: pc_start,
            registers: [RuntimeRegisterRecord::default(); 32],
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
            clk: self.clk,
            pc: self.pc,
            registers: self.registers,
            uninitialized_memory,
            input_stream,
            input_stream_ptr: self.input_stream_ptr,
            public_values_stream,
            // Use pooled memory or new() for fast zeroed allocation
            memory,
            syscall_counts,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::RiscvEmulationState;

    #[test]
    fn state_serde_roundtrip_with_high_rv64_values() {
        let mut state = RiscvEmulationState::new(0x1_0000_0000);
        state.clk = u64::from(u32::MAX) + 123;
        state
            .uninitialized_memory
            .insert(0x1_0000_1000, 0xDEAD_BEEF_DEAD_BEEF);

        let encoded = bincode::serialize(&state).expect("state should serialize");
        let decoded: RiscvEmulationState =
            bincode::deserialize(&encoded).expect("state should deserialize");

        assert_eq!(decoded.pc, 0x1_0000_0000);
        assert_eq!(decoded.clk, u64::from(u32::MAX) + 123);
        assert_eq!(
            decoded.uninitialized_memory.get(0x1_0000_1000).copied(),
            Some(0xDEAD_BEEF_DEAD_BEEF)
        );
    }
}
