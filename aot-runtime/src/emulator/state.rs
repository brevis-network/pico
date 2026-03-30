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
    pub registers: [u64; 32],
    /// Tracks whether a register has ever been accessed (read or written).
    pub(crate) reg_present: [bool; 32],
    /// Program counter
    pub pc: u64,
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
    pub uninitialized_memory: Memory<u64, u64>,
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
    /// Event threshold for memory read/write events.
    pub batch_memory_rw_threshold: usize,
    /// Event threshold for global lookup events in base units (before legacy x2 expansion).
    pub batch_global_lookup_base_threshold: usize,
    /// Fast-path event threshold for early exit (memory_rw_event_threshold - max_block_events)
    /// Events below this combined with clk below fast threshold allows skipping full check.
    pub batch_event_fast_threshold: usize,
    /// Snapshot (rollback) register data for the current batch
    pub batch_start_registers: [u64; 32],
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
    pub(crate) pc: u64,
    pub(crate) clk: u32,
    pub(crate) insn_count: u64,
    pub(crate) current_chunk: u32,
    pub(crate) batch_chunks_emulated: u32,
    pub(crate) batch_stop: bool,
    pub(crate) registers: [u64; 32],
    pub(crate) reg_present: [bool; 32],
    pub(crate) register_records: [RegisterRecord; 32],
    // Note: accessed_regs is intentionally NOT saved/restored.
    // They persist across unconstrained mode to match baseline behavior where
    // memory_snapshot accumulates all accesses during the batch.
    pub(crate) memory_diff: HashMap<u64, MemoryRecord>,
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
            batch_memory_rw_threshold: usize::MAX,
            batch_global_lookup_base_threshold: usize::MAX,
            batch_event_fast_threshold: usize::MAX.saturating_sub(FAST_PATH_EVENT_MARGIN),
            batch_start_registers: [0; 32],
            batch_start_reg_present: [false; 32],
            register_records: [RegisterRecord::default(); 32],
            batch_start_register_records: [RegisterRecord::default(); 32],
            accessed_regs: [false; 32],
            memory_snapshot: ContiguousRiscvMemory::new(),
            snapshot_registers_bitmap: 0,
            public_values_stream: Vec::new(),
            committed_value_digest: [0; PV_DIGEST_NUM_WORDS],
            deferred_proofs_digest: [0; DIGEST_SIZE],
            chunk_split_state: ChunkSplitState::default(),
            unconstrained_state: None,
        };

        // Initialize memory from Program struct (consolidated value + metadata)
        for (addr, value) in program.memory_image.iter() {
            emu.memory.insert_u64(
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
    pub fn program_pc_base(&self) -> u64 {
        self.program.pc_base
    }

    #[inline(always)]
    pub fn program_len(&self) -> usize {
        self.program.instructions.len()
    }

    /// Get the result value (typically in x10/a0).
    pub fn get_result(&self) -> u64 {
        self.registers[10]
    }

    /// Save current state for later differencing and clear access tracking.
    #[inline(always)]
    pub fn save_batch_start_state(&mut self) {
        self.batch_start_registers = self.registers;
        self.batch_start_reg_present = self.reg_present;
        self.batch_start_register_records = self.register_records;
        self.memory_snapshot.clear();
        self.clear_accessed_regs();
        self.snapshot_registers_bitmap = 0;
    }

    /// Look up a block function for the given program counter.
    #[inline(always)]
    pub fn lookup_block(&self, pc: u64) -> Option<BlockFn> {
        lookup_block_fn(pc)
    }
}

#[cfg(test)]
mod tests {
    use super::AotEmulatorCore;
    use crate::types::NextStep;
    use pico_vm::compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program};
    use std::{collections::BTreeMap, sync::Arc};

    fn test_program_with_instructions(
        pc_base: u64,
        pc_start: u64,
        instructions: Vec<Instruction>,
    ) -> Arc<Program> {
        let mut program = Program::new(instructions, pc_start, pc_base);
        program.memory_image = Arc::new(BTreeMap::from([(0x100, 0x1_0000_0001)]));
        Arc::new(program)
    }

    fn test_program(pc_base: u64, pc_start: u64) -> Arc<Program> {
        test_program_with_instructions(
            pc_base,
            pc_start,
            vec![
                Instruction::new(Opcode::ADD, 1, 0, 0, false, false),
                Instruction::new(Opcode::ADD, 2, 0, 0, false, false),
            ],
        )
    }

    #[test]
    fn phase2_constructor_and_fetch_support_widened_pc_space() {
        let pc_base = u64::from(u32::MAX) + 4;
        let pc_start = pc_base + 4;
        let emu = AotEmulatorCore::new(test_program(pc_base, pc_start), Vec::new());

        assert_eq!(emu.pc, pc_start);
        assert_eq!(emu.program_pc_base(), pc_base);
        assert_eq!(emu.memory.get(0x100).value, 0x1_0000_0001);
        assert_eq!(emu.fetch_instruction(pc_base).unwrap().opcode, Opcode::ADD);
        assert_eq!(emu.fetch_instruction(pc_start).unwrap().opcode, Opcode::ADD);
    }

    #[test]
    fn phase2_fetch_instruction_reports_u64_pc_errors() {
        let pc_base = u64::from(u32::MAX) + 4;
        let emu = AotEmulatorCore::new(test_program(pc_base, pc_base), Vec::new());

        let unaligned = emu.fetch_instruction(pc_base + 2).unwrap_err();
        assert!(unaligned.contains("Unaligned PC"));

        let outside = emu.fetch_instruction(pc_base + 0x100).unwrap_err();
        assert!(outside.contains("outside program"));
    }

    #[test]
    fn phase2_registers_and_unconstrained_state_preserve_u64_values() {
        let pc_base = 0x2000;
        let mut emu = AotEmulatorCore::new(test_program(pc_base, pc_base), Vec::new());
        let wide_value = u64::from(u32::MAX) + 0x55;

        emu.write_reg(10, wide_value);
        emu.pc = u64::from(u32::MAX) + 0x40;
        assert_eq!(emu.read_reg(10), wide_value);
        assert_eq!(emu.read_reg_snapshot(10), wide_value);

        emu.enter_unconstrained_mode();
        emu.write_reg(10, 7);
        emu.pc = 0x44;
        let next_pc = emu.exit_unconstrained_mode().unwrap();

        assert_eq!(emu.read_reg(10), wide_value);
        assert_eq!(emu.pc, u64::from(u32::MAX) + 0x40);
        assert_eq!(next_pc, u64::from(u32::MAX) + 0x44);
    }

    #[test]
    fn phase2_snapshot_preserves_widened_registers_and_pc() {
        let mut emu = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        let wide_pc = u64::from(u32::MAX) + 0x88;
        let wide_value = u64::from(u32::MAX) + 0x1234;

        emu.pc = wide_pc;
        emu.write_reg(5, wide_value);
        emu.save_batch_start_state();
        emu.write_reg(5, wide_value);

        let snapshot = emu.build_snapshot_state();
        assert_eq!(snapshot.pc, wide_pc);

        let mut snapshot = snapshot;
        emu.fill_snapshot_memory_delta(&mut snapshot);
        assert_eq!(snapshot.registers[5].value, wide_value);
    }

    #[test]
    fn phase5_snapshot_preserves_untouched_live_registers() {
        let mut emu = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());

        emu.write_reg(1, 0x1111);
        emu.write_reg(2, 0x2222);
        emu.save_batch_start_state();

        emu.write_reg(1, 0x3333);

        let mut snapshot = emu.build_snapshot_state();
        emu.fill_snapshot_memory_delta(&mut snapshot);

        assert_eq!(snapshot.registers[1].value, 0x1111);
        assert_eq!(snapshot.registers[2].value, 0x2222);
    }

    #[test]
    fn phase5_snapshot_reads_capture_prestate_for_precompile_inputs() {
        let mut emu = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        emu.write_mem_dword(0x100, 0x4646_4646_4646_4646);
        emu.save_batch_start_state();

        let mut input = [0u64; 1];
        emu.read_mem_dword_span_snapshot(0x100, &mut input);
        emu.write_mem_dword(0x100, 0);

        let mut snapshot = emu.build_snapshot_state();
        emu.fill_snapshot_memory_delta(&mut snapshot);

        assert_eq!(input[0], 0x4646_4646_4646_4646);
        assert_eq!(snapshot.memory.get(0x100).value, 0x4646_4646_4646_4646);
    }

    #[test]
    fn phase5_full_prestate_snapshot_resets_memory_snapshot() {
        let mut emu = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        emu.write_mem_dword(0x100, 0x1111_2222_3333_4444);
        emu.save_batch_start_state();
        let _ = emu.read_mem_dword_snapshot(0x100);

        let mut snapshot = emu.build_snapshot_state();
        emu.fill_snapshot_memory_full_prestate(&mut snapshot);

        assert_eq!(snapshot.memory.get(0x100).value, 0x1111_2222_3333_4444);
        assert!(!emu.memory_snapshot.has_accessed(0x100));
        assert_eq!(emu.memory_snapshot.get(0x100).value, 0);
    }

    #[test]
    fn phase2_dynamic_next_step_keeps_u64_pc() {
        let pc = u64::from(u32::MAX) + 0x999;
        match NextStep::Dynamic(pc) {
            NextStep::Dynamic(next_pc) => assert_eq!(next_pc, pc),
            _ => unreachable!(),
        }
    }

    #[test]
    fn phase3_memory_helpers_support_lw_lwu_ld_sd_round_trip() {
        let mut emu = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        emu.write_reg(1, 0x100);
        emu.write_mem_word(0x100, 0xffff_ff80);
        emu.write_mem_word(0x104, 0x1234_5678);

        emu.lw(2, 1, 0, 0x1004).unwrap();
        assert_eq!(emu.read_reg_unsafe(2), 0xffff_ffff_ffff_ff80);

        emu.lwu(3, 1, 0, 0x1008).unwrap();
        assert_eq!(emu.read_reg_unsafe(3), 0x0000_0000_ffff_ff80);

        emu.ld(4, 1, 0, 0x100c).unwrap();
        assert_eq!(emu.read_reg_unsafe(4), 0x1234_5678_ffff_ff80);

        emu.write_reg(5, 0x0123_4567_89ab_cdef);
        emu.sd(5, 1, 8, 0x1010).unwrap();
        assert_eq!(emu.read_mem_word_unsafe(0x108), 0x89ab_cdef);
        assert_eq!(emu.read_mem_word_unsafe(0x10c), 0x0123_4567);

        let mut tracked = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        tracked.write_reg_tracked(1, 0x100);
        tracked.write_mem_word(0x100, 0xffff_ff80);
        tracked.write_mem_word(0x104, 0x1234_5678);
        tracked.lw_tracked(2, 1, 0, 0x1004).unwrap();
        tracked.lwu_tracked(3, 1, 0, 0x1008).unwrap();
        tracked.ld_tracked(4, 1, 0, 0x100c).unwrap();
        assert_eq!(tracked.read_reg_unsafe(2), 0xffff_ffff_ffff_ff80);
        assert_eq!(tracked.read_reg_unsafe(3), 0x0000_0000_ffff_ff80);
        assert_eq!(tracked.read_reg_unsafe(4), 0x1234_5678_ffff_ff80);

        let mut no_count = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        no_count.write_reg_no_count(1, 0x100);
        no_count.write_mem_word(0x100, 0xffff_ff80);
        no_count.write_mem_word(0x104, 0x1234_5678);
        no_count.lw_no_count(2, 1, 0, 0x1004).unwrap();
        no_count.lwu_no_count(3, 1, 0, 0x1008).unwrap();
        no_count.ld_no_count(4, 1, 0, 0x100c).unwrap();
        assert_eq!(no_count.read_reg_unsafe(2), 0xffff_ffff_ffff_ff80);
        assert_eq!(no_count.read_reg_unsafe(3), 0x0000_0000_ffff_ff80);
        assert_eq!(no_count.read_reg_unsafe(4), 0x1234_5678_ffff_ff80);
    }

    #[test]
    fn phase3_signed_compare_helpers_use_i64_machine_values() {
        let mut emu = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        emu.write_reg(1, u64::MAX);
        emu.write_reg(2, 1);
        emu.slti(3, 1, 1, 0x1004);
        emu.sltr(4, 1, 2, 0x1008);
        assert_eq!(emu.read_reg_unsafe(3), 1);
        assert_eq!(emu.read_reg_unsafe(4), 1);

        let mut tracked = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        tracked.write_reg_tracked(1, u64::MAX);
        tracked.write_reg_tracked(2, 1);
        tracked.slti_tracked(3, 1, 1, 0x1004);
        tracked.sltr_tracked(4, 1, 2, 0x1008);
        assert_eq!(tracked.read_reg_unsafe(3), 1);
        assert_eq!(tracked.read_reg_unsafe(4), 1);

        let mut no_count = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        no_count.write_reg_no_count(1, u64::MAX);
        no_count.write_reg_no_count(2, 1);
        no_count.slti_no_count(3, 1, 1, 0x1004);
        no_count.sltr_no_count(4, 1, 2, 0x1008);
        assert_eq!(no_count.read_reg_unsafe(3), 1);
        assert_eq!(no_count.read_reg_unsafe(4), 1);
    }

    #[test]
    fn phase3_helper_immediates_sign_extend_from_low_32_bits() {
        let mut emu = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        emu.write_reg(1, 0x20f1f8);
        emu.adi(2, 1, u64::from(0xffff_fef8u32), 0x1004);
        emu.apc(3, 0x2021f8, u64::from(0x0000_d000u32), 0x1008);
        assert_eq!(emu.read_reg_unsafe(2), 0x20f0f0);
        assert_eq!(emu.read_reg_unsafe(3), 0x20f1f8);

        let mut tracked = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        tracked.write_reg_tracked(1, 0x20f1f8);
        tracked.adi_tracked(2, 1, u64::from(0xffff_fef8u32), 0x1004);
        tracked.apc_tracked(3, 0x2021f8, u64::from(0x0000_d000u32), 0x1008);
        assert_eq!(tracked.read_reg_unsafe(2), 0x20f0f0);
        assert_eq!(tracked.read_reg_unsafe(3), 0x20f1f8);

        let mut no_count = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        no_count.write_reg_no_count(1, 0x20f1f8);
        no_count.adi_no_count(2, 1, u64::from(0xffff_fef8u32), 0x1004);
        no_count.apc_no_count(3, 0x2021f8, u64::from(0x0000_d000u32), 0x1008);
        assert_eq!(no_count.read_reg_unsafe(2), 0x20f0f0);
        assert_eq!(no_count.read_reg_unsafe(3), 0x20f1f8);
    }

    #[test]
    fn phase3_shift_helpers_use_rv64_masks_and_sign() {
        let mut emu = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        emu.write_reg(1, 1);
        emu.write_reg(2, 40);
        emu.slr(3, 1, 2, 0x1004);
        assert_eq!(emu.read_reg_unsafe(3), 1u64 << 40);

        emu.write_reg(4, 0x8000_0000_0000_0000);
        emu.sai(5, 4, 63, 0x1008);
        assert_eq!(emu.read_reg_unsafe(5), u64::MAX);

        let mut tracked = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        tracked.write_reg_tracked(1, 1);
        tracked.write_reg_tracked(2, 40);
        tracked.slr_tracked(3, 1, 2, 0x1004);
        tracked.write_reg_tracked(4, 0x8000_0000_0000_0000);
        tracked.sai_tracked(5, 4, 63, 0x1008);
        assert_eq!(tracked.read_reg_unsafe(3), 1u64 << 40);
        assert_eq!(tracked.read_reg_unsafe(5), u64::MAX);

        let mut no_count = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        no_count.write_reg_no_count(1, 1);
        no_count.write_reg_no_count(2, 40);
        no_count.slr_no_count(3, 1, 2, 0x1004);
        no_count.write_reg_no_count(4, 0x8000_0000_0000_0000);
        no_count.sai_no_count(5, 4, 63, 0x1008);
        assert_eq!(no_count.read_reg_unsafe(3), 1u64 << 40);
        assert_eq!(no_count.read_reg_unsafe(5), u64::MAX);
    }

    #[test]
    fn phase3_interpreter_branch_uses_signed_i64_comparison() {
        let program = test_program_with_instructions(
            0x1000,
            0x1000,
            vec![
                Instruction::new(Opcode::BLT, 1, 2, 8_i64 as u64, false, true),
                Instruction::new(Opcode::ADD, 3, 0, 0, false, false),
                Instruction::new(Opcode::ADD, 4, 0, 0, false, false),
            ],
        );
        let mut emu = AotEmulatorCore::new(program, Vec::new());
        emu.write_reg(1, u64::MAX);
        emu.write_reg(2, 1);

        match emu.interpret_from_current_pc().unwrap() {
            NextStep::Direct(_) => unreachable!(),
            NextStep::Dynamic(pc) => assert_eq!(pc, 0x1008),
            NextStep::Halt => unreachable!(),
        }
        assert_eq!(emu.pc, 0x1008);
    }

    #[test]
    fn phase3_interpreter_shifts_use_rv64_masks_and_sign() {
        let sll_program = test_program_with_instructions(
            0x1000,
            0x1000,
            vec![
                Instruction::new(Opcode::SLL, 3, 1, 2, false, false),
                Instruction::new(Opcode::JALR, 0, 0, 0, false, true),
            ],
        );
        let mut emu = AotEmulatorCore::new(sll_program, Vec::new());
        emu.write_reg(1, 1);
        emu.write_reg(2, 40);
        assert!(emu.interpret_from_current_pc().is_ok());
        assert_eq!(emu.read_reg_unsafe(3), 1u64 << 40);

        let sra_program = test_program_with_instructions(
            0x1000,
            0x1000,
            vec![
                Instruction::new(Opcode::SRA, 5, 4, 63, false, true),
                Instruction::new(Opcode::JALR, 0, 0, 0, false, true),
            ],
        );
        let mut emu = AotEmulatorCore::new(sra_program, Vec::new());
        emu.write_reg(4, 0x8000_0000_0000_0000);
        assert!(emu.interpret_from_current_pc().is_ok());
        assert_eq!(emu.read_reg_unsafe(5), u64::MAX);
    }

    #[test]
    fn phase3_interpreter_jalr_clears_low_bit_for_vm_parity() {
        let program = test_program_with_instructions(
            0x1000,
            0x1000,
            vec![Instruction::new(
                Opcode::JALR,
                2,
                1,
                2_i64 as u64,
                false,
                true,
            )],
        );
        let mut emu = AotEmulatorCore::new(program, Vec::new());
        emu.write_reg(1, 0x1235);

        match emu.interpret_from_current_pc().unwrap() {
            NextStep::Dynamic(pc) => assert_eq!(pc, 0x1236),
            _ => unreachable!(),
        }
        assert_eq!(emu.pc, 0x1236);
        assert_eq!(emu.read_reg_unsafe(2), 0x1004);
    }

    #[test]
    fn phase4_word_helpers_sign_extend_across_families() {
        let mut emu = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        emu.write_reg(1, 0x1_0000_0000);
        emu.write_reg(2, 0xffff_ffff);
        emu.addw(3, 1, 2, 0x1004);
        emu.subw(4, 1, 2, 0x1008);
        assert_eq!(emu.read_reg_unsafe(3), u64::MAX);
        assert_eq!(emu.read_reg_unsafe(4), 1);

        let mut tracked = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        tracked.write_reg_tracked(1, 0x1_0000_0000);
        tracked.write_reg_tracked(2, 0xffff_ffff);
        tracked.addw_tracked(3, 1, 2, 0x1004);
        tracked.subw_tracked(4, 1, 2, 0x1008);
        assert_eq!(tracked.read_reg_unsafe(3), u64::MAX);
        assert_eq!(tracked.read_reg_unsafe(4), 1);

        let mut no_count = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        no_count.write_reg_no_count(1, 0x1_0000_0000);
        no_count.write_reg_no_count(2, 0xffff_ffff);
        no_count.addw_no_count(3, 1, 2, 0x1004);
        no_count.subw_no_count(4, 1, 2, 0x1008);
        assert_eq!(no_count.read_reg_unsafe(3), u64::MAX);
        assert_eq!(no_count.read_reg_unsafe(4), 1);
    }

    #[test]
    fn phase4_shiftw_helpers_use_word_masks_and_sign_extension() {
        let mut emu = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        emu.write_reg(1, 1);
        emu.write_reg(2, 40);
        emu.write_reg(3, 0x8000_0000);
        emu.sllw(4, 1, 2, 0x1004);
        emu.srlw(5, 3, 2, 0x1008);
        emu.sraw(6, 3, 2, 0x100c);
        assert_eq!(emu.read_reg_unsafe(4), 1 << 8);
        assert_eq!(emu.read_reg_unsafe(5), 0x0080_0000);
        assert_eq!(emu.read_reg_unsafe(6), 0xffff_ffff_ff80_0000);

        let mut tracked = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        tracked.write_reg_tracked(1, 1);
        tracked.write_reg_tracked(2, 40);
        tracked.write_reg_tracked(3, 0x8000_0000);
        tracked.sllw_tracked(4, 1, 2, 0x1004);
        tracked.srlw_tracked(5, 3, 2, 0x1008);
        tracked.sraw_tracked(6, 3, 2, 0x100c);
        assert_eq!(tracked.read_reg_unsafe(4), 1 << 8);
        assert_eq!(tracked.read_reg_unsafe(5), 0x0080_0000);
        assert_eq!(tracked.read_reg_unsafe(6), 0xffff_ffff_ff80_0000);

        let mut no_count = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        no_count.write_reg_no_count(1, 1);
        no_count.write_reg_no_count(2, 40);
        no_count.write_reg_no_count(3, 0x8000_0000);
        no_count.sllw_no_count(4, 1, 2, 0x1004);
        no_count.srlw_no_count(5, 3, 2, 0x1008);
        no_count.sraw_no_count(6, 3, 2, 0x100c);
        assert_eq!(no_count.read_reg_unsafe(4), 1 << 8);
        assert_eq!(no_count.read_reg_unsafe(5), 0x0080_0000);
        assert_eq!(no_count.read_reg_unsafe(6), 0xffff_ffff_ff80_0000);
    }

    #[test]
    fn phase4_mulw_divw_remw_edge_cases_match_rv64_word_rules() {
        let mut emu = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        emu.write_reg(1, 0xffff_ffff);
        emu.write_reg(2, 2);
        emu.write_reg(3, 0x8000_0000);
        emu.write_reg(4, u64::MAX);
        emu.write_reg(5, 0);
        emu.mulw(6, 1, 2, 0x1004);
        emu.divw(7, 3, 4, 0x1008);
        emu.divuw(8, 3, 5, 0x100c);
        emu.remw(9, 3, 4, 0x1010);
        emu.remuw(10, 3, 5, 0x1014);
        assert_eq!(emu.read_reg_unsafe(6), 0xffff_ffff_ffff_fffe);
        assert_eq!(emu.read_reg_unsafe(7), 0xffff_ffff_8000_0000);
        assert_eq!(emu.read_reg_unsafe(8), u64::MAX);
        assert_eq!(emu.read_reg_unsafe(9), 0);
        assert_eq!(emu.read_reg_unsafe(10), 0xffff_ffff_8000_0000);

        let mut tracked = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        tracked.write_reg_tracked(1, 0xffff_ffff);
        tracked.write_reg_tracked(2, 2);
        tracked.write_reg_tracked(3, 0x8000_0000);
        tracked.write_reg_tracked(4, u64::MAX);
        tracked.write_reg_tracked(5, 0);
        tracked.mulw_tracked(6, 1, 2, 0x1004);
        tracked.divw_tracked(7, 3, 4, 0x1008);
        tracked.divuw_tracked(8, 3, 5, 0x100c);
        tracked.remw_tracked(9, 3, 4, 0x1010);
        tracked.remuw_tracked(10, 3, 5, 0x1014);
        assert_eq!(tracked.read_reg_unsafe(6), 0xffff_ffff_ffff_fffe);
        assert_eq!(tracked.read_reg_unsafe(7), 0xffff_ffff_8000_0000);
        assert_eq!(tracked.read_reg_unsafe(8), u64::MAX);
        assert_eq!(tracked.read_reg_unsafe(9), 0);
        assert_eq!(tracked.read_reg_unsafe(10), 0xffff_ffff_8000_0000);

        let mut no_count = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        no_count.write_reg_no_count(1, 0xffff_ffff);
        no_count.write_reg_no_count(2, 2);
        no_count.write_reg_no_count(3, 0x8000_0000);
        no_count.write_reg_no_count(4, u64::MAX);
        no_count.write_reg_no_count(5, 0);
        no_count.mulw_no_count(6, 1, 2, 0x1004);
        no_count.divw_no_count(7, 3, 4, 0x1008);
        no_count.divuw_no_count(8, 3, 5, 0x100c);
        no_count.remw_no_count(9, 3, 4, 0x1010);
        no_count.remuw_no_count(10, 3, 5, 0x1014);
        assert_eq!(no_count.read_reg_unsafe(6), 0xffff_ffff_ffff_fffe);
        assert_eq!(no_count.read_reg_unsafe(7), 0xffff_ffff_8000_0000);
        assert_eq!(no_count.read_reg_unsafe(8), u64::MAX);
        assert_eq!(no_count.read_reg_unsafe(9), 0);
        assert_eq!(no_count.read_reg_unsafe(10), 0xffff_ffff_8000_0000);
    }

    #[test]
    fn phase4_interpreter_executes_all_word_ops() {
        let program = test_program_with_instructions(
            0x1000,
            0x1000,
            vec![
                Instruction::new(Opcode::ADDW, 13, 8, 6, false, false),
                Instruction::new(Opcode::SUBW, 14, 6, 7, false, false),
                Instruction::new(Opcode::SLLW, 10, 7, 2, false, false),
                Instruction::new(Opcode::SRLW, 11, 8, 2, false, false),
                Instruction::new(Opcode::SRAW, 12, 8, 2, false, false),
                Instruction::new(Opcode::MULW, 15, 7, 6, false, false),
                Instruction::new(Opcode::DIVW, 16, 8, 9, false, false),
                Instruction::new(Opcode::DIVUW, 17, 8, 0, false, false),
                Instruction::new(Opcode::REMW, 18, 8, 9, false, false),
                Instruction::new(Opcode::REMUW, 19, 8, 0, false, false),
                Instruction::new(Opcode::JALR, 0, 0, 0, false, true),
            ],
        );
        let mut emu = AotEmulatorCore::new(program, Vec::new());
        emu.write_reg(2, 40);
        emu.write_reg(6, 2);
        emu.write_reg(7, u64::MAX);
        emu.write_reg(8, 0x8000_0000);
        emu.write_reg(9, u64::MAX);

        match emu.interpret_from_current_pc().unwrap() {
            NextStep::Dynamic(pc) => assert_eq!(pc, 0),
            _ => unreachable!(),
        }

        assert_eq!(emu.read_reg_unsafe(10), 0xffff_ffff_ffff_ff00);
        assert_eq!(emu.read_reg_unsafe(11), 0x0080_0000);
        assert_eq!(emu.read_reg_unsafe(12), 0xffff_ffff_ff80_0000);
        assert_eq!(emu.read_reg_unsafe(13), 0xffff_ffff_8000_0002);
        assert_eq!(emu.read_reg_unsafe(14), 3);
        assert_eq!(emu.read_reg_unsafe(15), 0xffff_ffff_ffff_fffe);
        assert_eq!(emu.read_reg_unsafe(16), 0xffff_ffff_8000_0000);
        assert_eq!(emu.read_reg_unsafe(17), u64::MAX);
        assert_eq!(emu.read_reg_unsafe(18), 0);
        assert_eq!(emu.read_reg_unsafe(19), 0xffff_ffff_8000_0000);
    }

    #[test]
    fn phase4_unaligned_dword_accesses_return_errors() {
        let mut emu = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        emu.write_reg(1, 0x104);
        emu.write_reg(2, 0x0123_4567_89ab_cdef);
        assert!(emu
            .ld(3, 1, 0, 0x1004)
            .unwrap_err()
            .contains("Unaligned LD"));
        assert!(emu
            .sd(2, 1, 0, 0x1008)
            .unwrap_err()
            .contains("Unaligned SD"));

        let mut tracked = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        tracked.write_reg_tracked(1, 0x104);
        tracked.write_reg_tracked(2, 0x0123_4567_89ab_cdef);
        assert!(tracked
            .ld_tracked(3, 1, 0, 0x1004)
            .unwrap_err()
            .contains("Unaligned LD"));
        assert!(tracked
            .sd_tracked(2, 1, 0, 0x1008)
            .unwrap_err()
            .contains("Unaligned SD"));

        let mut no_count = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        no_count.write_reg_no_count(1, 0x104);
        no_count.write_reg_no_count(2, 0x0123_4567_89ab_cdef);
        assert!(no_count
            .ld_no_count(3, 1, 0, 0x1004)
            .unwrap_err()
            .contains("Unaligned LD"));
        assert!(no_count
            .sd_no_count(2, 1, 0, 0x1008)
            .unwrap_err()
            .contains("Unaligned SD"));

        let load_program = test_program_with_instructions(
            0x1000,
            0x1000,
            vec![Instruction::new(Opcode::LD, 3, 1, 0, false, true)],
        );
        let mut load_emu = AotEmulatorCore::new(load_program, Vec::new());
        load_emu.write_reg(1, 0x104);
        let load_err = load_emu.interpret_from_current_pc().err().unwrap();
        assert!(load_err.contains("Unaligned doubleword access"));

        let store_program = test_program_with_instructions(
            0x1000,
            0x1000,
            vec![Instruction::new(Opcode::SD, 2, 1, 0, false, true)],
        );
        let mut store_emu = AotEmulatorCore::new(store_program, Vec::new());
        store_emu.write_reg(1, 0x104);
        store_emu.write_reg(2, 0x0123_4567_89ab_cdef);
        let store_err = store_emu.interpret_from_current_pc().err().unwrap();
        assert!(store_err.contains("Unaligned doubleword store"));
    }
}
