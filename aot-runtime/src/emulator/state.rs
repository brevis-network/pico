use hashbrown::HashMap;
use pico_vm::{
    chips::chips::riscv_memory::event::MemoryRecord,
    compiler::riscv::program::Program,
    emulator::riscv::{
        chunk_split::{ChunkSplitConfig, ChunkSplitState},
        memory::{ContiguousRiscvMemory, Memory},
        riscv_emulator::{AbnormalTermination, EmulationError, TerminationReason},
    },
    mle::ledger::CoreRole,
    primitives::consts::{CHUNK_CLK_START, DIGEST_SIZE, PV_DIGEST_NUM_WORDS},
};
use std::sync::Arc;

use crate::{
    hook::{default_hook_map, Hook},
    lookup_block_fn,
    syscall::max_syscall_extra_cycles,
    types::BlockFn,
};

use super::{types::RegisterFile, AotSink};

/// Running totals over a run's batches. A first touch is the one access per batch that records an
/// address's prior state in the batch's prestate. A load and a store narrower than the doubleword
/// both need that prior value — the store keeps the bytes it does not write — while a doubleword
/// store needs only the record it overwrites, so the three are counted apart.
#[derive(Debug, Default)]
pub struct SnapshotCounts {
    pub first_touch_loads: u64,
    /// Byte, halfword and word stores.
    pub first_touch_partial_stores: u64,
    /// Doubleword stores, hint writes included: a hint's prior state is the zero record.
    pub first_touch_full_stores: u64,
    /// Registers whose batch-start record the snapshot restores, counted once per segment.
    pub first_touch_registers: u64,
}

/// Which kind of access touched an address first, as [`SnapshotCounts`] counts it.
#[derive(Clone, Copy)]
pub(crate) enum Touch {
    Load,
    PartialStore,
    FullStore,
}

/// Core AOT Emulator struct with all base functionality.
///
/// This struct contains all the state and methods needed for AOT emulation.
/// User crates should wrap this in a newtype and include the generated code.
pub struct AotEmulatorCore {
    /// Compiled program containing instruction stream for interpreter fallback.
    pub(crate) program: Arc<Program>,
    /// The 32 general-purpose registers (x0-x31), each with its last access, as the interpreter
    /// keeps them.
    pub registers: RegisterFile,
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
    pub chunk_split_config: ChunkSplitConfig,
    /// The registers at batch start, the prestate the snapshot restores a touched register to.
    pub batch_start_registers: RegisterFile,
    /// The registers accessed in the batch. Kept apart from the records, since an unconstrained
    /// block rolls the records back but not these, as the interpreter's snapshot keeps its touches.
    pub touched_registers: [bool; 32],
    /// Memory snapshot of pre-batch values (only addresses accessed in this batch).
    pub memory_snapshot: ContiguousRiscvMemory,
    /// True iff `memory_snapshot`'s bitmap is currently all-zero (clean). Maintained at batch
    /// granularity (off the per-access hot path) so `save_batch_start_state` can skip the
    /// redundant ~31.5 MB `clear()` bitmap scan: after each batch `fill_snapshot_memory_*` swaps in
    /// a fresh (clean) pooled memory, so the next batch starts clean and the scan finds nothing.
    pub memory_snapshot_clean: bool,
    /// Instruction count at which `should_yield` fires *without* a chunk boundary, so the batch
    /// can hand out a mid-chunk snapshot and the replay of one chunk can be split across threads.
    /// `u64::MAX` — the default — is split replay switched off.
    pub next_sub_yield: u64,
    /// The instruction count a replay stops at, exactly; `u64::MAX` when the core is not
    /// replaying. A compiled block that would run past it falls back to the interpreter
    /// (`can_fit_block`), and `should_yield` stops there through `next_sub_yield`.
    pub(crate) replay_target: u64,
    /// Whether the replay ends its chunk, rather than one of the chunk's segments.
    pub(crate) final_segment: bool,
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
    /// Compiled blocks entered by `run_blocks` or `run_record_blocks`, so a run can show it
    /// executed generated code.
    pub(crate) compiled_block_dispatches: u64,
    /// Instructions the fallback interpreter ran. A generated block that does not fit what is left
    /// of the chunk falls back, so a run that cuts chunks interprets some of its instructions; how
    /// many, against its cycles, is what shows the generated code ran the rest. An unconstrained
    /// region rolls it back with `insn_count`, so it counts cycles.
    pub(crate) fallback_insns: u64,
    /// Recording blocks that ran their bodies, and their instructions; unlike
    /// `compiled_block_dispatches`, a block that fell back on entry is not counted, nor anything
    /// inside an unconstrained region.
    pub(crate) recorder_body_dispatches: u64,
    pub(crate) recorder_body_insns: u64,
    /// Of `recorder_body_insns`, those whose rows the recording blocks wrote directly.
    pub(crate) recorder_direct_insns: u64,
    /// Where the instructions' events go.
    pub(crate) sink: AotSink,
    /// What the snapshot thread's batches cost in prestate, for the stage ledger.
    pub(crate) snapshot_counts: SnapshotCounts,
    /// The pipeline core this is, for the ledger's precompile timers: a replay worker once it has
    /// recovered a snapshot, the snapshot thread's (or a whole run's) until then.
    pub(crate) role: CoreRole,
    /// The typed error behind the `Err` the run is returning. The generated entry point carries
    /// only a `String`, so the batch takes the error the interpreter would have returned from here.
    pub(crate) fault: Option<EmulationError>,
}

#[derive(Debug)]
pub struct UnconstrainedState {
    pub(crate) pc: u64,
    pub(crate) clk: u32,
    pub(crate) insn_count: u64,
    pub(crate) fallback_insns: u64,
    pub(crate) current_chunk: u32,
    pub(crate) batch_chunks_emulated: u32,
    pub(crate) batch_stop: bool,
    pub(crate) registers: RegisterFile,
    // Note: touched_registers is intentionally NOT saved/restored.
    // They persist across unconstrained mode to match baseline behavior where
    // memory_snapshot accumulates all accesses during the batch.
    pub(crate) memory_diff: HashMap<u64, MemoryRecord>,
    pub(crate) committed_value_digest: [u32; PV_DIGEST_NUM_WORDS],
    pub(crate) deferred_proofs_digest: [u32; DIGEST_SIZE],
    pub(crate) commit_in_flight: bool,
    pub(crate) commits: u32,
}

impl AotEmulatorCore {
    // ========================================================================
    // Construction & Initialization
    // ========================================================================

    /// Create a new emulator initialized with the program's memory image and optional stdin.
    ///
    /// Initializes all state including registers, memory, syscall tables, and batch tracking.
    pub fn new(program: Arc<Program>, input_stream: Vec<Vec<u8>>) -> Self {
        let mut emu = Self::unloaded(program.clone(), input_stream);

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

    /// [`Self::new`] before the program's memory image is loaded.
    pub(crate) fn unloaded(program: Arc<Program>, input_stream: Vec<Vec<u8>>) -> Self {
        let max_syscall_cycles = max_syscall_extra_cycles();
        let hook_map = default_hook_map();

        Self {
            program: program.clone(),
            registers: RegisterFile::default(),
            pc: program.pc_start,
            insn_count: 0,
            current_chunk: 1,
            current_batch: 0,
            clk: CHUNK_CLK_START,
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
            chunk_split_config: ChunkSplitConfig::disabled(max_syscall_cycles),
            batch_start_registers: RegisterFile::default(),
            touched_registers: [false; 32],
            memory_snapshot: ContiguousRiscvMemory::new(),
            memory_snapshot_clean: true,
            next_sub_yield: u64::MAX,
            replay_target: u64::MAX,
            final_segment: true,
            public_values_stream: Vec::new(),
            committed_value_digest: [0; PV_DIGEST_NUM_WORDS],
            deferred_proofs_digest: [0; DIGEST_SIZE],
            chunk_split_state: ChunkSplitState::default(),
            unconstrained_state: None,
            compiled_block_dispatches: 0,
            fallback_insns: 0,
            recorder_body_dispatches: 0,
            recorder_body_insns: 0,
            recorder_direct_insns: 0,
            sink: AotSink::Off,
            snapshot_counts: SnapshotCounts::default(),
            role: CoreRole::Snapshot,
            fault: None,
        }
    }

    #[inline(always)]
    pub fn program_pc_base(&self) -> u64 {
        self.program.pc_base
    }

    #[inline(always)]
    pub fn program_len(&self) -> usize {
        self.program.instructions.len()
    }

    /// Save current state for later differencing and clear access tracking.
    #[inline(always)]
    pub fn save_batch_start_state(&mut self) {
        self.batch_start_registers = self.registers;
        // `memory_snapshot` is normally already clean here (the previous batch's
        // `fill_snapshot_memory_*` swapped in fresh pooled memory), so skip the redundant
        // ~31.5 MB bitmap scan. Only clear when the flag says it may be dirty (defensive).
        if !self.memory_snapshot_clean {
            self.memory_snapshot.clear();
            self.memory_snapshot_clean = true;
        }
        self.clear_touched_registers();
    }

    /// Look up a block function for the given program counter.
    #[inline(always)]
    pub fn lookup_block(&self, pc: u64) -> Option<BlockFn> {
        lookup_block_fn(pc)
    }

    /// Records `error` as the run's `fault` and returns its message, for the `Err(String)` that
    /// carries it out through the generated code.
    #[cold]
    pub(crate) fn fail(&mut self, error: EmulationError) -> String {
        let message = error.to_string();
        self.fault = Some(error);
        message
    }

    /// A jump or taken branch at `pc` to `target`, checked as the interpreter checks it
    /// (`RiscvEmulator::jump_target`): a misaligned target, or one outside the program, 0
    /// included, ends the run with the same abnormal termination.
    #[inline(always)]
    pub fn check_jump_target(&mut self, pc: u64, target: u64) -> Result<(), String> {
        if !target.is_multiple_of(4) {
            return Err(self.fail(EmulationError::misaligned_jump(pc, target)));
        }
        if !self.program.contains_pc(target) {
            return Err(self.fail(EmulationError::outside_program(target)));
        }
        Ok(())
    }

    /// `ebreak` at `pc`, failed the way the interpreter fails it.
    #[cold]
    pub fn breakpoint(&mut self, pc: u64) -> String {
        self.fail(AbnormalTermination::fault(TerminationReason::Breakpoint { pc }).into())
    }

    /// `unimp` at `pc`, failed the way the interpreter fails it.
    #[cold]
    pub fn illegal_instruction(&mut self, pc: u64) -> String {
        self.fail(AbnormalTermination::fault(TerminationReason::IllegalInstruction { pc }).into())
    }
}

#[cfg(test)]
mod tests {
    use super::AotEmulatorCore;
    use crate::types::NextStep;
    use pico_vm::{
        compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
        emulator::riscv::state::RuntimeRegisterRecord,
    };
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

    /// The sub-yield has to stay quiet inside an unconstrained region. The replaying interpreter
    /// only tests its target outside one, so a cut landing there hands out a target the worker
    /// runs straight past — and the next segment replays what it already did, with nothing to say
    /// so. A whole-run proof does not notice: the arms still agree and the proof still verifies.
    #[test]
    fn the_sub_yield_does_not_fire_inside_an_unconstrained_region() {
        let pc_base = 0x2000;
        let mut emu = AotEmulatorCore::new(test_program(pc_base, pc_base), Vec::new());
        emu.pc = pc_base;
        emu.insn_count = 100;
        emu.next_sub_yield = 10;

        assert!(
            emu.should_yield(),
            "a cut point that has been reached yields"
        );

        emu.enter_unconstrained_mode();
        assert!(
            !emu.should_yield(),
            "not inside an unconstrained region, however far past the cut point"
        );

        emu.exit_unconstrained_mode().unwrap();
        assert!(emu.should_yield(), "and it comes back on the way out");
    }

    #[test]
    fn phase2_registers_and_unconstrained_state_preserve_u64_values() {
        let pc_base = 0x2000;
        let mut emu = AotEmulatorCore::new(test_program(pc_base, pc_base), Vec::new());
        let wide_value = u64::from(u32::MAX) + 0x55;

        emu.write_reg(10, wide_value);
        emu.pc = u64::from(u32::MAX) + 0x40;
        assert_eq!(emu.read_reg_b(10), wide_value);
        assert_eq!(emu.read_reg_snapshot(10), wide_value);

        emu.enter_unconstrained_mode();
        emu.write_reg(10, 7);
        emu.pc = 0x44;
        let next_pc = emu.exit_unconstrained_mode().unwrap();

        assert_eq!(emu.read_reg_b(10), wide_value);
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

    /// The touched marks outlive the block, so the batch still restores and counts a register only
    /// the block touched.
    #[test]
    fn an_unconstrained_block_rolls_the_records_back_and_keeps_the_touched_marks() {
        let mut emu = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        emu.write_reg(1, 0x1111);
        emu.update_insn_clock();
        emu.save_batch_start_state();
        let before = emu.registers;

        emu.enter_unconstrained_mode();
        emu.write_reg(1, 0x2222);
        emu.write_reg(2, 0x3333);
        emu.exit_unconstrained_mode().unwrap();
        assert_eq!(emu.registers, before);
        assert_eq!(emu.registers[2], RuntimeRegisterRecord::default());

        let mut snapshot = emu.build_snapshot_state();
        emu.fill_snapshot_memory_delta(&mut snapshot);
        assert_eq!(snapshot.registers, before.0);
        assert_eq!(
            emu.snapshot_counts.first_touch_registers, 1,
            "x1, touched in the block and present at batch start; x2 was absent"
        );
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

        emu.lw_no_count(false, 2, 1, 0, 0x1004).unwrap();
        assert_eq!(emu.read_reg_unsafe(2), 0xffff_ffff_ffff_ff80);

        emu.lwu_no_count(false, 3, 1, 0, 0x1008).unwrap();
        assert_eq!(emu.read_reg_unsafe(3), 0x0000_0000_ffff_ff80);

        emu.ld_no_count(false, 4, 1, 0, 0x100c).unwrap();
        assert_eq!(emu.read_reg_unsafe(4), 0x1234_5678_ffff_ff80);

        emu.write_reg(5, 0x0123_4567_89ab_cdef);
        emu.sd_no_count(false, 5, 1, 8, 0x1010).unwrap();
        assert_eq!(emu.read_mem_word_unsafe(0x108), 0x89ab_cdef);
        assert_eq!(emu.read_mem_word_unsafe(0x10c), 0x0123_4567);
    }

    #[test]
    fn phase3_subword_helpers_use_dword_backing_layout() {
        let mut emu = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        emu.write_reg(1, 0x100);
        emu.write_mem_dword(0x100, 0x8877_6655_4433_2211);

        emu.lb_no_count(false, 2, 1, 4, 0x1004);
        emu.lbu_no_count(false, 3, 1, 5, 0x1008);
        emu.lh_no_count(false, 4, 1, 6, 0x100c).unwrap();
        emu.lhu_no_count(false, 5, 1, 2, 0x1010).unwrap();
        assert_eq!(emu.read_reg_unsafe(2), 0x55);
        assert_eq!(emu.read_reg_unsafe(3), 0x66);
        assert_eq!(emu.read_reg_unsafe(4), 0xffff_ffff_ffff_8877);
        assert_eq!(emu.read_reg_unsafe(5), 0x4433);

        emu.write_reg(6, 0xaa);
        emu.sb_no_count(false, 6, 1, 5, 0x1014);
        emu.write_reg(7, 0xbbcc);
        emu.sh_no_count(false, 7, 1, 6, 0x1018).unwrap();
        assert_eq!(emu.read_mem_dword_unsafe(0x100), 0xbbcc_aa55_4433_2211);
    }

    #[test]
    fn phase3_signed_compare_helpers_use_i64_machine_values() {
        let mut emu = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        emu.write_reg(1, u64::MAX);
        emu.write_reg(2, 1);
        emu.slti_no_count(false, 3, 1, 1, 0x1004);
        emu.sltr_no_count(false, 4, 1, 2, 0x1008);
        assert_eq!(emu.read_reg_unsafe(3), 1);
        assert_eq!(emu.read_reg_unsafe(4), 1);
    }

    /// A helper takes its immediate as the program holds it: a negative one already 64 bits wide,
    /// and one past 32 bits whole.
    #[test]
    fn phase3_helper_immediates_are_taken_as_the_program_holds_them() {
        let mut emu = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        emu.write_reg(1, 0x20f1f8);
        emu.adi_no_count(false, 2, 1, -264_i64 as u64, 0x1004);
        emu.apc_no_count(false, 3, 0x2021f8, 0xd000, 0x1008);
        emu.adi_no_count(false, 4, 1, 1 << 32, 0x100c);
        assert_eq!(emu.read_reg_unsafe(2), 0x20f0f0);
        assert_eq!(emu.read_reg_unsafe(3), 0x20f1f8);
        assert_eq!(emu.read_reg_unsafe(4), 0x1_0020_f1f8);
    }

    #[test]
    fn phase3_shift_helpers_use_rv64_masks_and_sign() {
        let mut emu = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        emu.write_reg(1, 1);
        emu.write_reg(2, 40);
        emu.slr_no_count(false, 3, 1, 2, 0x1004);
        assert_eq!(emu.read_reg_unsafe(3), 1u64 << 40);

        emu.write_reg(4, 0x8000_0000_0000_0000);
        emu.sai_no_count(false, 5, 4, 63, 0x1008);
        assert_eq!(emu.read_reg_unsafe(5), u64::MAX);
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
                Instruction::new(Opcode::JALR, 0, 0, 0x1000, false, true),
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
                Instruction::new(Opcode::JALR, 0, 0, 0x1000, false, true),
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
            vec![
                Instruction::new(Opcode::JALR, 2, 1, 2_i64 as u64, false, true),
                Instruction::new(Opcode::ADD, 0, 0, 0, false, false),
            ],
        );
        let mut emu = AotEmulatorCore::new(program, Vec::new());
        // 0x1003 + 2 = 0x1005: bit 0 cleared lands on the second instruction. (A target with bit 1
        // set is misaligned and ends the run; see `check_jump_target`.)
        emu.write_reg(1, 0x1003);

        match emu.interpret_from_current_pc().unwrap() {
            NextStep::Dynamic(pc) => assert_eq!(pc, 0x1004),
            _ => unreachable!(),
        }
        assert_eq!(emu.pc, 0x1004);
        assert_eq!(emu.read_reg_unsafe(2), 0x1004);
    }

    #[test]
    fn phase4_word_helpers_sign_extend_across_families() {
        let mut emu = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        emu.write_reg(1, 0x1_0000_0000);
        emu.write_reg(2, 0xffff_ffff);
        emu.addw_no_count(false, 3, 1, 2, 0x1004);
        emu.subw_no_count(false, 4, 1, 2, 0x1008);
        assert_eq!(emu.read_reg_unsafe(3), u64::MAX);
        assert_eq!(emu.read_reg_unsafe(4), 1);
    }

    #[test]
    fn phase4_shiftw_helpers_use_word_masks_and_sign_extension() {
        let mut emu = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        emu.write_reg(1, 1);
        emu.write_reg(2, 40);
        emu.write_reg(3, 0x8000_0000);
        emu.sllw_no_count(false, 4, 1, 2, 0x1004);
        emu.srlw_no_count(false, 5, 3, 2, 0x1008);
        emu.sraw_no_count(false, 6, 3, 2, 0x100c);
        assert_eq!(emu.read_reg_unsafe(4), 1 << 8);
        assert_eq!(emu.read_reg_unsafe(5), 0x0080_0000);
        assert_eq!(emu.read_reg_unsafe(6), 0xffff_ffff_ff80_0000);
    }

    #[test]
    fn phase4_mulw_divw_remw_edge_cases_match_rv64_word_rules() {
        let mut emu = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        emu.write_reg(1, 0xffff_ffff);
        emu.write_reg(2, 2);
        emu.write_reg(3, 0x8000_0000);
        emu.write_reg(4, u64::MAX);
        emu.write_reg(5, 0);
        emu.mulw_no_count(false, 6, 1, 2, 0x1004);
        emu.divw_no_count(false, 7, 3, 4, 0x1008);
        emu.divuw_no_count(false, 8, 3, 5, 0x100c);
        emu.remw_no_count(false, 9, 3, 4, 0x1010);
        emu.remuw_no_count(false, 10, 3, 5, 0x1014);
        assert_eq!(emu.read_reg_unsafe(6), 0xffff_ffff_ffff_fffe);
        assert_eq!(emu.read_reg_unsafe(7), 0xffff_ffff_8000_0000);
        assert_eq!(emu.read_reg_unsafe(8), u64::MAX);
        assert_eq!(emu.read_reg_unsafe(9), 0);
        assert_eq!(emu.read_reg_unsafe(10), 0xffff_ffff_8000_0000);
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
                Instruction::new(Opcode::JALR, 0, 0, 0x1000, false, true),
            ],
        );
        let mut emu = AotEmulatorCore::new(program, Vec::new());
        emu.write_reg(2, 40);
        emu.write_reg(6, 2);
        emu.write_reg(7, u64::MAX);
        emu.write_reg(8, 0x8000_0000);
        emu.write_reg(9, u64::MAX);

        match emu.interpret_from_current_pc().unwrap() {
            NextStep::Dynamic(pc) => assert_eq!(pc, 0x1000),
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
            .ld_no_count(false, 3, 1, 0, 0x1004)
            .unwrap_err()
            .contains("Unaligned LD"));
        assert!(emu
            .sd_no_count(false, 2, 1, 0, 0x1008)
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

    /// An instruction that reads one register twice leaves it at the interpreter's later read: `b`
    /// (clk + 2) after `c` (clk + 1), and a store's value, operand `a` (clk + 3), after its base.
    /// The helpers the generated code calls and the fallback interpreter both.
    #[test]
    fn a_register_read_twice_keeps_the_interpreters_last_timestamp() {
        let program = test_program_with_instructions(
            0x1000,
            0x1000,
            vec![
                Instruction::new(Opcode::ADDW, 1, 2, 2, false, false),
                Instruction::new(Opcode::DIVW, 3, 2, 2, false, false),
                Instruction::new(Opcode::REM, 3, 2, 2, false, false),
                Instruction::new(Opcode::SD, 4, 4, 0, false, true),
                Instruction::new(Opcode::SB, 4, 4, 9, false, true),
            ],
        );
        let setup = || {
            let mut emu = AotEmulatorCore::new(program.clone(), Vec::new());
            emu.write_reg(2, 7);
            emu.write_reg(4, 0x200);
            emu.update_insn_clock();
            emu
        };
        // (register read twice, its timestamp's offset from the instruction's clock)
        let expected = [(2, 2), (2, 2), (2, 2), (4, 3), (4, 3)];

        let mut emu = setup();
        let helpers: [fn(&mut AotEmulatorCore); 5] = [
            |emu| emu.addw_no_count(false, 1, 2, 2, 0x1004),
            |emu| emu.divw_no_count(false, 3, 2, 2, 0x1008),
            |emu| emu.rem_no_count(false, 3, 2, 2, 0x100c),
            |emu| emu.sd_no_count(false, 4, 4, 0, 0x1010).unwrap(),
            |emu| emu.sb_no_count(false, 4, 4, 9, 0x1014),
        ];
        for (helper, (reg, offset)) in helpers.into_iter().zip(expected) {
            let clk = emu.clk;
            helper(&mut emu);
            assert_eq!(emu.registers[reg].timestamp, clk + offset);
        }

        let mut emu = setup();
        for (reg, offset) in expected {
            let clk = emu.clk;
            emu.debug_interpret_single_step().unwrap();
            assert_eq!(emu.registers[reg].timestamp, clk + offset);
        }
    }

    /// The generated stores read the dword before writing a byte, halfword or word into it; that
    /// read is the store's first touch, not a load's.
    #[test]
    fn a_first_touch_is_counted_as_the_access_that_made_it() {
        let mut emu = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        emu.write_reg_no_count(1, 0x200);
        emu.write_reg_no_count(2, 0x7f);
        emu.lw_no_count(false, 3, 1, 0, 0x1004).unwrap();
        emu.sb_no_count(false, 2, 1, 8, 0x1008);
        emu.sh_no_count(false, 2, 1, 16, 0x100c).unwrap();
        emu.sw_no_count(false, 2, 1, 24, 0x1010).unwrap();
        emu.sd_no_count(false, 2, 1, 32, 0x1014).unwrap();
        emu.write_mem_word_constrained(0x228, 1);
        emu.write_mem_word_syscall(0x230, 1);
        // A second touch of an address the batch has seen records nothing.
        emu.sd_no_count(false, 2, 1, 0, 0x1018).unwrap();

        let counts = &emu.snapshot_counts;
        assert_eq!(
            (
                counts.first_touch_loads,
                counts.first_touch_partial_stores,
                counts.first_touch_full_stores,
            ),
            (1, 5, 1)
        );
    }

    // ── the same outcomes as the interpreter's `jump_target` tests ──

    /// Runs `instructions` at 0x1000 with `x5 = x5`: the termination reason it fails with, and
    /// `x1`, which the jumps link into.
    fn aot_fault(
        instructions: Vec<Instruction>,
        x5: u64,
    ) -> (
        Option<pico_vm::emulator::riscv::riscv_emulator::TerminationReason>,
        u64,
    ) {
        let program = test_program_with_instructions(0x1000, 0x1000, instructions);
        let mut emu = AotEmulatorCore::new(program, Vec::new());
        emu.write_reg(5, x5);
        assert!(
            emu.interpret_from_current_pc().is_err(),
            "the run must fail"
        );
        let reason = emu
            .fault
            .take()
            .and_then(|e| e.abnormal_termination().map(|t| t.reason));
        (reason, emu.read_reg_unsafe(1))
    }

    #[test]
    fn a_misaligned_or_outside_jump_fails_as_in_the_interpreter() {
        use pico_vm::emulator::riscv::riscv_emulator::TerminationReason::{
            MisalignedJumpTarget, OutsideProgram,
        };
        let nop = Instruction::new(Opcode::ADD, 0, 0, 0, false, false);
        let program = |first: Instruction| vec![first, nop, nop, nop];
        let jal = |offset: i64| Instruction::new(Opcode::JAL, 1, offset as u64, 0, true, true);
        let beq = |offset: i64| Instruction::new(Opcode::BEQ, 0, 0, offset as u64, false, true);
        let jalr = Instruction::new(Opcode::JALR, 1, 5, 0, false, true);
        for (first, x5, want) in [
            (
                jal(6),
                0,
                MisalignedJumpTarget {
                    pc: 0x1000,
                    target: 0x1006,
                },
            ),
            (
                beq(2),
                0,
                MisalignedJumpTarget {
                    pc: 0x1000,
                    target: 0x1002,
                },
            ),
            (
                jalr,
                0x1006,
                MisalignedJumpTarget {
                    pc: 0x1000,
                    target: 0x1006,
                },
            ),
            (jal(0x100), 0, OutsideProgram { pc: 0x1100 }),
            (jal(-8), 0, OutsideProgram { pc: 0xff8 }),
            // A jump to 0 is not a halt.
            (jalr, 0, OutsideProgram { pc: 0 }),
        ] {
            let (reason, x1) = aot_fault(program(first), x5);
            assert_eq!(reason, Some(want), "{first:?}");
            assert_eq!(
                x1, 0,
                "{first:?}: the faulting jump wrote its link register"
            );
        }
    }

    /// Running past the last instruction used to end the run as if it had halted.
    #[test]
    fn falling_off_the_end_fails_as_in_the_interpreter() {
        let nop = Instruction::new(Opcode::ADD, 0, 0, 0, false, false);
        let (reason, _) = aot_fault(vec![nop, nop], 0);
        assert_eq!(
            reason,
            Some(
                pico_vm::emulator::riscv::riscv_emulator::TerminationReason::OutsideProgram {
                    pc: 0x1008
                }
            )
        );
    }
}
