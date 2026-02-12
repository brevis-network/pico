use hashbrown::HashMap;
use pico_vm::{
    chips::chips::riscv_memory::event::MemoryRecord,
    compiler::riscv::program::Program,
    emulator::riscv::memory::{ContiguousRiscvMemory, Memory},
    primitives::consts::{DIGEST_SIZE, PV_DIGEST_NUM_WORDS},
};
use std::sync::Arc;

use crate::{
    hook::{default_hook_map, Hook},
    lookup_block_fn,
    syscall::max_syscall_extra_cycles,
    types::BlockFn,
};

use super::{
    constants::{FAST_PATH_CLK_MARGIN, FAST_PATH_EVENT_MARGIN},
    types::{ChunkSplitState, RegisterRecord},
};

/// Core AOT Emulator struct with all base functionality.
///
/// This struct contains all the state and methods needed for AOT emulation.
/// User crates should wrap this in a newtype and include the generated code.
pub struct AotEmulatorCore {
    /// Compiled program containing instruction stream for interpreter fallback.
    pub(crate) program: Arc<Program>,
    /// 32 general-purpose registers (x0-x31)
    pub registers: [u32; 32],
    /// Tracks whether a register has ever been accessed (read or written).
    pub(crate) reg_present: [bool; 32],
    /// Program counter
    pub pc: u32,
    /// Instruction counter for comparison with Pico's `state.global_clk`
    pub insn_count: u64,
    /// Current chunk number (starts at 1; chunk 0 reserved for memory init)
    pub current_chunk: u32,
    /// Current batch number (snapshot batching)
    pub current_batch: u32,
    /// Chunk-local clock (baseline increments by 4 per instruction)
    pub clk: u32,
    /// Maximum extra syscall cycles (used for conservative chunk boundary checks)
    pub max_syscall_cycles: u32,
    /// Memory (word-addressable, aligned to 4-byte boundaries) with consolidated value + metadata
    pub memory: ContiguousRiscvMemory,
    /// Input stream for syscall reads (HINT_READ)
    pub input_stream: Vec<Vec<u8>>,
    /// Current position in input_stream
    pub input_stream_ptr: usize,
    /// Uninitialized memory for HINT_READ
    pub uninitialized_memory: Memory<u32>,
    /// Hook map for write-based host calls.
    pub(crate) hook_map: HashMap<u32, Hook>,
    /// Stdout buffer
    pub(crate) stdout: String,
    /// Stderr buffer
    pub(crate) stderr: String,
    /// Per-batch execution controls (set by `next_state_batch`)
    pub batch_chunk_target: u32,
    pub batch_chunks_emulated: u32,
    pub batch_stop: bool,
    pub batch_chunk_size: u32,
    /// Pre-computed chunk boundary threshold (chunk_size*4 - max_syscall_cycles)
    pub batch_clk_threshold: u32,
    /// Fast-path threshold for early exit (batch_clk_threshold - FAST_PATH_MARGIN)
    /// When clk < this value AND events < event_fast_threshold, skip the full check.
    pub batch_clk_fast_threshold: u32,
    /// Fast-path event threshold for early exit (memory_rw_event_threshold - max_block_events)
    /// Events below this combined with clk below fast threshold allows skipping full check.
    pub batch_event_fast_threshold: usize,
    /// Snapshot (rollback) register data for the current batch
    pub batch_start_registers: [u32; 32],
    pub batch_start_reg_present: [bool; 32],
    /// Register metadata (chunk/timestamp) for current state.
    pub register_records: [RegisterRecord; 32],
    /// Register metadata at batch start.
    pub batch_start_register_records: [RegisterRecord; 32],
    /// Lightweight tracking: which registers were accessed
    pub accessed_regs: [bool; 32],
    /// Memory snapshot of pre-batch values (only addresses accessed in this batch).
    pub memory_snapshot: ContiguousRiscvMemory,
    /// Bitmap of registers snapshotted in this batch (0-31).
    pub snapshot_registers_bitmap: u32,
    /// A stream of public values from the program (global to entire program).
    pub public_values_stream: Vec<u8>,
    /// Current position in public_values_stream.
    pub public_values_stream_ptr: usize,
    /// Committed value digest updated by COMMIT syscall.
    pub committed_value_digest: [u32; PV_DIGEST_NUM_WORDS],
    /// Deferred proofs digest updated by COMMIT_DEFERRED_PROOFS syscall.
    pub deferred_proofs_digest: [u32; DIGEST_SIZE],
    /// Chunk split counters used for baseline parity.
    pub chunk_split_state: ChunkSplitState,
    /// Saved state for unconstrained execution blocks.
    pub(crate) unconstrained_state: Option<UnconstrainedState>,
}

#[derive(Debug)]
pub struct UnconstrainedState {
    pub(crate) pc: u32,
    pub(crate) clk: u32,
    pub(crate) insn_count: u64,
    pub(crate) current_chunk: u32,
    pub(crate) batch_chunks_emulated: u32,
    pub(crate) batch_stop: bool,
    pub(crate) registers: [u32; 32],
    pub(crate) reg_present: [bool; 32],
    pub(crate) register_records: [RegisterRecord; 32],
    // Note: accessed_regs is intentionally NOT saved/restored.
    // They persist across unconstrained mode to match baseline behavior where
    // memory_snapshot accumulates all accesses during the batch.
    pub(crate) memory_diff: HashMap<u32, MemoryRecord>,
    pub(crate) committed_value_digest: [u32; PV_DIGEST_NUM_WORDS],
    pub(crate) deferred_proofs_digest: [u32; DIGEST_SIZE],
}

impl AotEmulatorCore {
    // ========================================================================
    // Construction & Initialization
    // ========================================================================

    /// Create a new emulator initialized with the program's memory image and optional stdin.
    ///
    /// Initializes all state including registers, memory, syscall tables, and batch tracking.
    pub fn new(program: Arc<Program>, input_stream: Vec<Vec<u8>>) -> Self {
        let max_syscall_cycles = max_syscall_extra_cycles();
        let hook_map = default_hook_map();

        let mut emu = Self {
            program: program.clone(),
            registers: [0; 32],
            reg_present: [false; 32],
            pc: program.pc_start,
            insn_count: 0,
            current_chunk: 1,
            current_batch: 0,
            clk: 0,
            max_syscall_cycles,
            memory: ContiguousRiscvMemory::new(),
            input_stream,
            input_stream_ptr: 0,
            uninitialized_memory: Memory::new_preallocated(),
            hook_map,
            stdout: Default::default(),
            stderr: Default::default(),
            batch_chunk_target: 0,
            batch_chunks_emulated: 0,
            batch_stop: false,
            batch_chunk_size: u32::MAX / 4,
            batch_clk_threshold: u32::MAX,
            batch_clk_fast_threshold: u32::MAX.saturating_sub(FAST_PATH_CLK_MARGIN),
            batch_event_fast_threshold: usize::MAX.saturating_sub(FAST_PATH_EVENT_MARGIN),
            batch_start_registers: [0; 32],
            batch_start_reg_present: [false; 32],
            register_records: [RegisterRecord::default(); 32],
            batch_start_register_records: [RegisterRecord::default(); 32],
            accessed_regs: [false; 32],
            memory_snapshot: ContiguousRiscvMemory::new(),
            snapshot_registers_bitmap: 0,
            public_values_stream: Vec::new(),
            public_values_stream_ptr: 0,
            committed_value_digest: [0; PV_DIGEST_NUM_WORDS],
            deferred_proofs_digest: [0; DIGEST_SIZE],
            chunk_split_state: ChunkSplitState::default(),
            unconstrained_state: None,
        };

        // Initialize memory from Program struct (consolidated value + metadata)
        for (addr, value) in program.memory_image.iter() {
            emu.memory.insert(
                *addr,
                MemoryRecord {
                    value: *value,
                    chunk: 0,
                    timestamp: 0,
                },
            );
        }

        emu
    }

    #[inline(always)]
    pub fn program_pc_base(&self) -> u32 {
        self.program.pc_base
    }

    #[inline(always)]
    pub fn program_len(&self) -> usize {
        self.program.instructions.len()
    }

    /// Get the result value (typically in x10/a0).
    pub fn get_result(&self) -> u32 {
        self.registers[10]
    }

    /// Save current state for later differencing and clear access tracking.
    #[inline(always)]
    pub fn save_batch_start_state(&mut self) {
        self.batch_start_registers = self.registers;
        self.batch_start_reg_present = self.reg_present;
        self.batch_start_register_records = self.register_records;
        self.clear_accessed_regs();
        self.snapshot_registers_bitmap = 0;
    }

    /// Look up a block function for the given program counter.
    #[inline(always)]
    pub fn lookup_block(&self, pc: u32) -> Option<BlockFn> {
        lookup_block_fn(pc)
    }
}
