use hashbrown::HashMap;
use nohash_hasher::BuildNoHashHasher;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::{
    chips::chips::riscv_memory::event::MemoryRecord,
    emulator::riscv::{
        record::{EmulationRecord, MemoryAccessRecord},
        riscv_emulator::EmulatorMode,
        syscalls::SyscallCode,
    },
};

/// Holds data describing the current state of a program's emulation.
#[serde_as]
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RiscvEmulationState {
    /// The global clock keeps track of how many instrutions have been emulated through all chunks.
    pub global_clk: u64,

    /// The chunk clock keeps track of how many chunks have been emulated.
    pub current_chunk: u32,

    /// The execution chunk clock keeps track of how many chunks with cpu events have been emulated.
    pub current_execution_chunk: u32,

    /// The clock increments by 4 (possibly more in syscalls) for each instruction that has been
    /// emulated in this chunk.
    pub clk: u32,

    /// The channel alternates between 0 and [crate::bytes::NUM_BYTE_LOOKUP_CHANNELS],
    /// used to controll byte lookup multiplicity.
    pub channel: u8,

    /// The program counter.
    pub pc: u32,

    /// Uninitialized memory addresses that have a specific value they should be initialized with.
    /// SyscallHintRead uses this to write hint data into uninitialized memory.
    // #[serde(
    //     serialize_with = "serialize_hashmap_as_vec",
    //     deserialize_with = "deserialize_hashmap_as_vec"
    // )]
    pub uninitialized_memory: HashMap<u32, u32, BuildNoHashHasher<u32>>,

    /// A stream of input values (global to the entire program).
    pub input_stream: Vec<Vec<u8>>,

    /// A ptr to the current position in the input stream incremented by HINT_READ opcode.
    pub input_stream_ptr: usize,

    /// A ptr to the current position in the proof stream, incremented after verifying a proof.
    pub proof_stream_ptr: usize,

    /// A stream of public values from the program (global to entire program).
    pub public_values_stream: Vec<u8>,

    /// A ptr to the current position in the public values stream, incremented when reading from
    /// public_values_stream.
    pub public_values_stream_ptr: usize,

    pub memory: HashMap<u32, MemoryRecord, BuildNoHashHasher<u32>>,

    /// Keeps track of how many times a certain syscall has been called.
    pub syscall_counts: HashMap<SyscallCode, u64>,
}

/// Holds data to track changes made to the runtime since a fork point.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct ForkState {
    /// The `global_clk` value at the fork point.
    pub global_clk: u64,
    /// The original `clk` value at the fork point.
    pub clk: u32,
    /// The original `pc` value at the fork point.
    pub pc: u32,
    /// All memory changes since the fork point.
    pub memory_diff: HashMap<u32, Option<MemoryRecord>, BuildNoHashHasher<u32>>,
    /// The original memory access record at the fork point.
    pub op_record: MemoryAccessRecord,
    /// The original emulation record at the fork point.
    pub record: EmulationRecord,
    /// Whether `emit_events` was enabled at the fork point.
    pub emulator_mode: EmulatorMode,
}

impl RiscvEmulationState {
    #[must_use]
    /// Create a new [`EmulationState`].
    pub fn new(pc_start: u32) -> Self {
        Self {
            global_clk: 0,
            // Start at chunk 1 since chunk 0 is reserved for memory initialization.
            current_chunk: 1,
            current_execution_chunk: 1,
            clk: 0,
            channel: 0,
            pc: pc_start,
            memory: HashMap::default(),
            uninitialized_memory: HashMap::default(),
            input_stream: Vec::new(),
            input_stream_ptr: 0,
            public_values_stream: Vec::new(),
            public_values_stream_ptr: 0,
            proof_stream_ptr: 0,
            syscall_counts: HashMap::new(),
        }
    }
}
