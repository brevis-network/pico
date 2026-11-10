use hashbrown::HashMap;
use pico_vm::{
    chips::chips::riscv_memory::event::MemoryRecord,
    compiler::riscv::{opcode::Opcode, program::Program},
    emulator::riscv::{
        chunk_split::{ChunkSplitConfig, ChunkSplitState},
        hook::{default_hook_map, Hook},
        memory::{ContiguousRiscvMemory, Memory},
        riscv_emulator::{
            guard::{access_fault, access_width},
            AbnormalTermination, EmulationError, TerminationReason,
        },
    },
    mle::ledger::CoreRole,
    primitives::consts::{CHUNK_CLK_START, DIGEST_SIZE, PV_DIGEST_NUM_WORDS},
};
use std::sync::Arc;

use crate::{lookup_block_fn, syscall::max_syscall_extra_cycles, types::BlockFn};

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
    /// Loads and stores whose address is not a multiple of their width (Zicclsm), outside
    /// unconstrained blocks: `RiscvEmulationState::misaligned_accesses`, counted the same way.
    pub misaligned_accesses: u64,
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
    /// `Program::code`, which no store may touch.
    pub(crate) code: core::ops::Range<u64>,
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
            misaligned_accesses: 0,
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
            code: program.code(),
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

    /// Ends the run if a load or store at `addr` lands where no guest access may, the way
    /// the interpreter ends it: see `guard::access_fault`.
    #[inline(always)]
    pub(crate) fn check_access(&mut self, opcode: Opcode, addr: u64) -> Result<(), String> {
        let store = matches!(opcode, Opcode::SB | Opcode::SH | Opcode::SW | Opcode::SD);
        match access_fault(opcode, addr, access_width(opcode), store, &self.code) {
            None => Ok(()),
            Some(reason) => Err(self.fault_at(reason)),
        }
    }

    /// Whether a syscall's `width`-byte access at `addr` may happen. One that may not
    /// records the fault, as the interpreter's syscall context does, and does not happen: the
    /// syscall runs on with zero in its place, and `execute_syscall` ends the run when it returns.
    #[inline(always)]
    pub(crate) fn syscall_access_allowed(&mut self, addr: u64, width: u64, store: bool) -> bool {
        match access_fault(Opcode::ECALL, addr, width, store, &self.code) {
            None => true,
            Some(reason) => {
                if self.fault.is_none() {
                    self.fault_at(reason);
                }
                false
            }
        }
    }

    #[cold]
    fn fault_at(&mut self, reason: TerminationReason) -> String {
        self.fail(AbnormalTermination::fault(reason).into())
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
        emulator::riscv::{riscv_emulator::TerminationReason, state::RuntimeRegisterRecord},
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
    fn a_program_based_past_u32_constructs_and_fetches() {
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
    fn fetching_a_misaligned_or_outside_pc_past_u32_fails() {
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
    fn registers_and_the_unconstrained_rollback_keep_64_bit_values() {
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
    fn a_snapshot_keeps_64_bit_registers_and_pc() {
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
    fn a_snapshot_holds_each_register_as_the_batch_started() {
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
    fn a_snapshot_read_captures_the_prestate_a_precompile_reads() {
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
    fn a_full_prestate_snapshot_clears_the_memory_tracker() {
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
    fn a_dynamic_next_step_keeps_a_pc_past_u32() {
        let pc = u64::from(u32::MAX) + 0x999;
        match NextStep::Dynamic(pc) {
            NextStep::Dynamic(next_pc) => assert_eq!(next_pc, pc),
            _ => unreachable!(),
        }
    }

    #[test]
    fn lw_lwu_ld_and_sd_helpers_round_trip() {
        let mut emu = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        emu.write_reg(1, 0x1_0100);
        emu.write_mem_word(0x1_0100, 0xffff_ff80);
        emu.write_mem_word(0x1_0104, 0x1234_5678);

        emu.lw_no_count(false, 2, 1, 0, 0x1004).unwrap();
        assert_eq!(emu.read_reg_unsafe(2), 0xffff_ffff_ffff_ff80);

        emu.lwu_no_count(false, 3, 1, 0, 0x1008).unwrap();
        assert_eq!(emu.read_reg_unsafe(3), 0x0000_0000_ffff_ff80);

        emu.ld_no_count(false, 4, 1, 0, 0x100c).unwrap();
        assert_eq!(emu.read_reg_unsafe(4), 0x1234_5678_ffff_ff80);

        emu.write_reg(5, 0x0123_4567_89ab_cdef);
        emu.sd_no_count(false, 5, 1, 8, 0x1010).unwrap();
        assert_eq!(emu.read_mem_word_unsafe(0x1_0108), 0x89ab_cdef);
        assert_eq!(emu.read_mem_word_unsafe(0x1_010c), 0x0123_4567);
    }

    #[test]
    fn byte_and_halfword_helpers_address_within_the_dword() {
        let mut emu = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        emu.write_reg(1, 0x1_0100);
        emu.write_mem_dword(0x1_0100, 0x8877_6655_4433_2211);

        emu.lb_no_count(false, 2, 1, 4, 0x1004).unwrap();
        emu.lbu_no_count(false, 3, 1, 5, 0x1008).unwrap();
        emu.lh_no_count(false, 4, 1, 6, 0x100c).unwrap();
        emu.lhu_no_count(false, 5, 1, 2, 0x1010).unwrap();
        assert_eq!(emu.read_reg_unsafe(2), 0x55);
        assert_eq!(emu.read_reg_unsafe(3), 0x66);
        assert_eq!(emu.read_reg_unsafe(4), 0xffff_ffff_ffff_8877);
        assert_eq!(emu.read_reg_unsafe(5), 0x4433);

        emu.write_reg(6, 0xaa);
        emu.sb_no_count(false, 6, 1, 5, 0x1014).unwrap();
        emu.write_reg(7, 0xbbcc);
        emu.sh_no_count(false, 7, 1, 6, 0x1018).unwrap();
        assert_eq!(emu.read_mem_dword_unsafe(0x1_0100), 0xbbcc_aa55_4433_2211);
    }

    #[test]
    fn signed_compare_helpers_compare_as_i64() {
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
    fn helper_immediates_are_taken_as_the_program_holds_them() {
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
    fn shift_helpers_mask_the_amount_to_six_bits_and_keep_the_sign() {
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
    fn the_fallback_compares_a_signed_branch_as_i64() {
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
    fn the_fallback_masks_a_shift_amount_to_six_bits_and_keeps_the_sign() {
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
    fn word_add_and_sub_helpers_sign_extend_their_result() {
        let mut emu = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        emu.write_reg(1, 0x1_0000_0000);
        emu.write_reg(2, 0xffff_ffff);
        emu.addw_no_count(false, 3, 1, 2, 0x1004);
        emu.subw_no_count(false, 4, 1, 2, 0x1008);
        assert_eq!(emu.read_reg_unsafe(3), u64::MAX);
        assert_eq!(emu.read_reg_unsafe(4), 1);
    }

    #[test]
    fn word_shift_helpers_mask_the_amount_to_five_bits_and_sign_extend() {
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
    fn word_multiply_and_divide_helpers_handle_overflow_and_division_by_zero() {
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
    fn the_fallback_runs_every_word_instruction() {
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

    /// The reason `emu` ended the run for, which must be an abnormal end with SIGSEGV's code.
    fn segfault(emu: &mut AotEmulatorCore, message: &str) -> TerminationReason {
        let fault = emu
            .fault
            .take()
            .expect("a refused access records its typed error");
        assert_eq!(fault.to_string(), message);
        let termination = *fault
            .abnormal_termination()
            .unwrap_or_else(|| panic!("not an abnormal termination: {fault}"));
        assert_eq!(termination.exit_code, 139, "{termination}");
        termination.reason
    }

    /// A syscall's access that lands where no guest access may ends the run as the interpreter
    /// ends it once the syscall returns: `WRITE` from a buffer below the segments, while an
    /// empty one, which reads nothing, may.
    #[test]
    fn a_syscall_access_where_none_may_land_ends_the_run() {
        use pico_vm::emulator::riscv::syscalls::SyscallCode;
        use TerminationReason::NullAccess;
        let write = SyscallCode::WRITE as u64;
        let mut emu = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        emu.write_reg(12, 4);
        let message = emu
            .execute_syscall(write, 1, 0x8)
            .expect_err("a null buffer");
        assert_eq!(
            segfault(&mut emu, &message),
            NullAccess {
                opcode: Opcode::ECALL,
                addr: 0x8
            }
        );
        let mut emu = AotEmulatorCore::new(test_program(0x1000, 0x1000), Vec::new());
        emu.write_reg(12, 0);
        emu.execute_syscall(write, 1, 0x8).expect("an empty write");
    }

    /// A precompile handed a pointer into the code, below the segments or into the stack guard ends
    /// the run with the same fault, at the same address, whether the core runs the compute-only
    /// copy (no records) or the interpreter's implementation (records): the first operand is
    /// checked as one span, the rest dword by dword, in the interpreter's order.
    #[test]
    fn a_precompile_faults_alike_with_and_without_records() {
        use pico_vm::{emulator::riscv::syscalls::SyscallCode, primitives::layout::HEAP_END};
        use SyscallCode::*;
        let program = test_program_with_instructions(
            0x2_0000,
            0x2_0000,
            vec![Instruction::new(Opcode::ADD, 0, 0, 0, false, false); 256],
        );
        let code = program.code();
        // An operand away from every forbidden range. The Weierstrass adds and the decompressions
        // are left out: the zeros a refused read gives make two equal points or an invalid
        // encoding, which panic both copies, as the same zeros from valid memory do.
        let scratch = 0x10_0000;
        let guard = HEAP_END - 8;
        // (syscall, whether it takes a second pointer)
        let syscalls = [
            (KECCAK_PERMUTE, false),
            (SHA_EXTEND, false),
            (SHA_COMPRESS, true),
            (POSEIDON2_PERMUTE, true),
            (UINT256_MUL, true),
            (ED_ADD, true),
            (SECP256K1_DOUBLE, false),
            (BN254_DOUBLE, false),
            (BLS12381_FP_ADD, true),
        ];
        let mut cases = Vec::new();
        for (syscall, two_pointers) in syscalls {
            let arg2 = if two_pointers { scratch } else { 0 };
            // The first operand in each region, and one running into the code from below it.
            for (region, ptr) in [
                ("code", code.start),
                ("null", 0x1000),
                ("guard", guard),
                ("into code", code.start - 8),
            ] {
                cases.push((syscall, ptr, arg2, region));
            }
            // The second operand running into the guard.
            if two_pointers {
                cases.push((syscall, scratch, guard, "second into guard"));
            }
        }
        let run = |syscall: SyscallCode, arg1: u64, arg2: u64, records: bool| {
            let mut emu = AotEmulatorCore::new(program.clone(), Vec::new());
            if records {
                emu.emit_records();
            }
            emu.execute_syscall(syscall as u64, arg1, arg2)
                .map_err(|message| segfault(&mut emu, &message))
                .map(|_| ())
        };
        let mismatches: Vec<String> = cases
            .into_iter()
            .filter_map(|(syscall, arg1, arg2, region)| {
                let compute_only = run(syscall, arg1, arg2, false);
                let interpreter = run(syscall, arg1, arg2, true);
                // Only SHA_COMPRESS and POSEIDON2 leave their first operand unwritten, so only
                // they may read the code without faulting.
                let reads_only_code =
                    matches!(syscall, SHA_COMPRESS | POSEIDON2_PERMUTE) && region.ends_with("code");
                (compute_only != interpreter || compute_only.is_ok() != reads_only_code).then(
                    || {
                        format!(
                            "{syscall:?} {region}: no records {compute_only:?}, records \
                             {interpreter:?}"
                        )
                    },
                )
            })
            .collect();
        assert!(mismatches.is_empty(), "{}", mismatches.join("\n"));
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
            emu.write_reg(4, 0x1_0200);
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
            |emu| emu.sb_no_count(false, 4, 4, 9, 0x1014).unwrap(),
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
        emu.write_reg_no_count(1, 0x1_0200);
        emu.write_reg_no_count(2, 0x7f);
        emu.lw_no_count(false, 3, 1, 0, 0x1004).unwrap();
        emu.sb_no_count(false, 2, 1, 8, 0x1008).unwrap();
        emu.sh_no_count(false, 2, 1, 16, 0x100c).unwrap();
        emu.sw_no_count(false, 2, 1, 24, 0x1010).unwrap();
        emu.sd_no_count(false, 2, 1, 32, 0x1014).unwrap();
        emu.write_mem_word_constrained(0x1_0228, 1);
        emu.write_mem_word_syscall(0x1_0230, 1);
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
}
