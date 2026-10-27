use hashbrown::HashMap;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::{
    emulator::riscv::{
        event_types::{RvAddr, RvChunk, RvClk, RvTimestamp, RvValue},
        memory::{Memory64, RecvTimeoutError, GLOBAL_MEMORY_POOL, POOL_WAIT},
        syscalls::SyscallCode,
    },
    primitives::consts::CHUNK_CLK_START,
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
            clk: RvClk::from(CHUNK_CLK_START),
            pc: pc_start,
            registers: [RuntimeRegisterRecord::default(); 32],
            memory: ContiguousRiscvMemory::new(),
            ..Default::default()
        }
    }

    /// Clone the state without copying memory data.
    ///
    /// The `memory` field is handed out by the global pool instead of being copied from the
    /// original, so this costs a pool handout — and waits while the pool is empty.
    ///
    /// This is useful for snapshot states where memory will be populated
    /// separately from a snapshot or rolled back.
    pub fn clone_without_memory(&self) -> Self {
        let uninitialized_memory = Default::default();
        let input_stream = self.input_stream.clone();
        let public_values_stream = self.public_values_stream.clone();
        let syscall_counts = self.syscall_counts.clone();

        // Get a pre-allocated memory from the pool (blocking wait). Waiting here is the only
        // back-pressure the pipeline has — the record channel is unbounded — so this keeps
        // waiting however long it takes, and only says so once the wait stops looking normal.
        let mut reported = false;
        let memory = loop {
            match GLOBAL_MEMORY_POOL.1.recv_timeout(POOL_WAIT) {
                Ok(memory) => break memory,
                Err(RecvTimeoutError::Disconnected) => {
                    panic!("Global memory pool channel closed")
                }
                Err(RecvTimeoutError::Timeout) => {
                    if !std::mem::replace(&mut reported, true) {
                        tracing::warn!(
                            "waiting on the memory pool for over {}s; if nothing is proving, \
                             raise MEMORY_POOL_SIZE",
                            POOL_WAIT.as_secs()
                        );
                    }
                }
            }
        };

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
