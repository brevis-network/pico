//! The core as a replay worker: started from a snapshot the snapshot thread handed out, and run to
//! that snapshot's target global clock, exactly, writing the interpreter's records.
//!
//! The snapshot thread decided where the chunk ends, so a replay makes no cut decision of its own:
//! its chunk split is off. A compiled block runs only if it ends at or before the target
//! (`can_fit_block`); one that would cross it falls back to the interpreter, which runs one
//! instruction at a time and yields at the target (`should_yield`, through `next_sub_yield`). So a
//! target inside a block is reached by the fallback. Stopping anywhere but the target is an error.
//!
//! The end is the interpreter worker's (`ReplayToTarget` in its `emulate_cycle`): a final segment
//! rolls the chunk over, the segment's one record is cut, and a replay that ended the run hands its
//! final state to the shared `postprocess`.

use std::sync::Arc;

use pico_vm::{
    compiler::riscv::program::Program,
    emulator::riscv::{
        chunk_split::ChunkSplitConfig,
        emulator::{postprocess, FinalState},
        memory::ContiguousRiscvMemory,
        record::EmulationRecord,
        riscv_emulator::EmulationError,
        state::RiscvEmulationState,
    },
    machine::report::EmulationReport,
    mle::ledger::CoreRole,
    primitives::consts::{CHUNK_CLK_START, DIGEST_SIZE, PV_DIGEST_NUM_WORDS},
};

use super::{types::RegisterFile, AotEmulatorCore, EmittedChunk};

impl AotEmulatorCore {
    /// A replay worker's core, recovered from `state` to replay up to `target_global_clk`. Only a
    /// `final_segment` ends the chunk.
    pub fn recover(
        program: Arc<Program>,
        state: RiscvEmulationState,
        target_global_clk: u64,
        final_segment: bool,
    ) -> Self {
        let mut emu = Self::unloaded(program, Vec::new());
        // The replay runs on the snapshot's memory; the one the core was built with is not the
        // pool's to take back.
        drop(emu.recover_in_place(state, target_global_clk, final_segment));
        emu
    }

    /// Whether the core replays a snapshot: [`Self::recover_in_place`] set its target, which is
    /// `u64::MAX` on any other core.
    #[inline(always)]
    pub(crate) fn is_replay_worker(&self) -> bool {
        self.replay_target != u64::MAX
    }

    /// [`Self::recover`] on a core that has replayed before, keeping its allocations: the core is
    /// left as `recover` builds it, except for the touched-register marks, which only the snapshot
    /// thread reads; a replay's helpers still set them, since skipping the store would cost a role
    /// test on every register access. The memory tracker needs nothing, since a replay never writes
    /// it. Returns the memory the previous replay ran on, which only the caller knows whether to
    /// give back to the pool.
    pub fn recover_in_place(
        &mut self,
        state: RiscvEmulationState,
        target_global_clk: u64,
        final_segment: bool,
    ) -> ContiguousRiscvMemory {
        self.pc = state.pc;
        self.insn_count = state.global_clk;
        self.current_batch = state.current_batch;
        self.current_chunk = state.current_chunk;
        self.clk = u32::try_from(state.clk).expect("a chunk's clock fits in u32");
        // The snapshot's zero record for a register never accessed is the core's own encoding.
        self.registers = RegisterFile(state.registers);
        self.uninitialized_memory = state.uninitialized_memory;
        self.input_stream = state.input_stream;
        self.input_stream_ptr = state.input_stream_ptr;
        self.public_values_stream = state.public_values_stream;
        // A worker's record starts with no digest word, as the interpreter's does: its COMMITs
        // write the ones its chunk runs.
        self.committed_value_digest = [0; PV_DIGEST_NUM_WORDS];
        self.deferred_proofs_digest = [0; DIGEST_SIZE];
        self.unconstrained_state = None;
        self.fault = None;
        self.stdout.clear();
        self.stderr.clear();

        self.chunk_split_config = ChunkSplitConfig::disabled(self.max_syscall_cycles);
        // Cleared rather than rebuilt, as the interpreter's worker does: a new state maps its
        // bitset afresh, an `mmap` and an `munmap` per chunk under `mmap-memory`.
        self.chunk_split_state.clear();
        self.batch_chunk_target = 0;
        self.batch_chunks_emulated = 0;
        self.batch_stop = false;
        self.replay_target = target_global_clk;
        self.next_sub_yield = target_global_clk;
        self.final_segment = final_segment;
        self.role = CoreRole::Worker;

        let previous = std::mem::replace(&mut self.memory, state.memory);
        self.restart_sink();
        previous
    }

    /// Runs the recovered snapshot to its target and cuts the segment's record.
    pub fn replay(
        &mut self,
        run_dispatch: impl FnOnce(&mut Self) -> Result<(), String>,
    ) -> Result<(EmittedChunk, EmulationReport), EmulationError> {
        let (start, start_chunk) = (self.insn_count, self.current_chunk);
        if self.replay_target <= start {
            return Err(EmulationError::Aot(format!(
                "nothing to replay: the snapshot stands at instruction {start}, its target is {}",
                self.replay_target
            )));
        }
        if let Err(message) = run_dispatch(self) {
            return Err(self
                .fault
                .take()
                .unwrap_or(EmulationError::AotExecutionFailed(message)));
        }
        if self.insn_count != self.replay_target {
            return Err(EmulationError::Aot(format!(
                "a replay from instruction {start} stopped at {}, not at its target {}",
                self.insn_count, self.replay_target
            )));
        }
        let done = self.is_program_done();
        if let Some(err) = done.then(|| self.run_end_error()).flatten() {
            return Err(err);
        }

        if self.final_segment {
            self.chunk_split_state.clear();
        }
        self.cut_emitted_chunk();
        if self.final_segment {
            self.current_chunk = self
                .current_chunk
                .checked_add(1)
                .expect("the chunk counter fits u32");
            self.clk = CHUNK_CLK_START;
        }
        let mut chunks = self.take_emitted_chunks();
        let chunk = chunks.pop().expect("a replay cuts its segment's record");
        assert!(chunks.is_empty(), "a replay cuts no chunk of its own");
        Ok((
            chunk,
            EmulationReport {
                current_cycle: self.insn_count,
                start_chunk,
                done,
                cycle_tracker: None,
                host_cycle_estimator: None,
            },
        ))
    }

    /// The run's memory initialize and finalize events into `record`, from the state the replay
    /// that ended the run left.
    pub fn postprocess(&self, record: &mut EmulationRecord) {
        postprocess(
            FinalState {
                registers: &self.registers.0,
                uninitialized_memory: &self.uninitialized_memory,
                memory: &self.memory,
                input_stream_ptr: self.input_stream_ptr,
                input_stream_len: self.input_stream.len(),
            },
            record,
        );
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use pico_vm::{
        compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
        emulator::riscv::{
            record::EmulationRecord, record_slots::hold_records_unbounded,
            state::RiscvEmulationState,
        },
        primitives::consts::CHUNK_CLK_START,
    };

    use crate::{AotEmulatorCore, BlockFn, NextStep};

    /// Three `ADDI x1, x1, 1`, then `HALT` (an `ECALL` with `t0 = 0`): a run of four cycles.
    fn program() -> Arc<Program> {
        Arc::new(Program::new(
            vec![
                Instruction::new(Opcode::ADD, 1, 1, 1, false, true),
                Instruction::new(Opcode::ADD, 1, 1, 1, false, true),
                Instruction::new(Opcode::ADD, 1, 1, 1, false, true),
                Instruction::new(Opcode::ECALL, 5, 10, 11, false, false),
            ],
            0x1000,
            0x1000,
        ))
    }

    /// The three `ADDI`s as the generated block at 0x1000 runs them.
    fn addis(emu: &mut AotEmulatorCore) {
        let emitting = emu.is_emitting();
        for next_pc in [0x1004, 0x1008, 0x100c] {
            emu.adi_no_count(emitting, 1, 1, 1, next_pc);
        }
        emu.check_chunk_boundary_fast();
    }

    /// Stands in for the generated block at 0x1000, which runs only if it fits.
    fn block(emu: &mut AotEmulatorCore) -> Result<NextStep, String> {
        if !emu.can_fit_block(3, 0, 0, 1 << 1) {
            return emu.interpret_from_current_pc();
        }
        addis(emu);
        Ok(NextStep::Dynamic(emu.pc))
    }

    /// The same block without its fit test.
    fn unchecked_block(emu: &mut AotEmulatorCore) -> Result<NextStep, String> {
        addis(emu);
        Ok(NextStep::Dynamic(emu.pc))
    }

    fn compiled(emu: &mut AotEmulatorCore) -> Result<(), String> {
        emu.run_blocks(|pc| (pc == 0x1000).then_some(block as BlockFn))
    }

    fn interpreted(emu: &mut AotEmulatorCore) -> Result<(), String> {
        emu.run_blocks(|_| None)
    }

    fn start() -> RiscvEmulationState {
        RiscvEmulationState::new(0x1000)
    }

    #[test]
    fn a_target_inside_a_compiled_block_is_reached_by_the_fallback() {
        hold_records_unbounded();
        let mut emu = AotEmulatorCore::recover(program(), start(), 2, true);
        let (chunk, report) = emu.replay(compiled).expect("the replay reaches its target");
        assert_eq!((emu.insn_count, emu.read_reg_unsafe(1)), (2, 2));
        assert_eq!((chunk.cycles, chunk.compiled_block_dispatches), (2, 1));
        assert_eq!(
            chunk.fallback_insns, 2,
            "the block did not fit, so it fell back"
        );
        assert_eq!(chunk.record.cpu_steps().len(), 2);
        assert_eq!((report.current_cycle, report.done), (2, false));
    }

    #[test]
    fn a_target_at_a_blocks_end_is_reached_by_the_block() {
        hold_records_unbounded();
        let mut emu = AotEmulatorCore::recover(program(), start(), 3, true);
        let (chunk, _) = emu.replay(compiled).expect("the replay reaches its target");
        assert_eq!((emu.insn_count, emu.pc), (3, 0x100c));
        assert_eq!(
            (chunk.compiled_block_dispatches, chunk.fallback_insns),
            (1, 0)
        );
        assert_eq!(chunk.record.cpu_steps().len(), 3);
    }

    #[test]
    fn running_past_the_target_is_an_error() {
        hold_records_unbounded();
        let mut emu = AotEmulatorCore::recover(program(), start(), 2, true);
        let Err(err) = emu.replay(|emu| emu.run_blocks(|_| Some(unchecked_block as BlockFn)))
        else {
            panic!("a block that ignores the target runs past it");
        };
        assert!(
            err.to_string()
                .contains("stopped at 3, not at its target 2"),
            "{err}"
        );
    }

    #[test]
    fn halting_short_of_the_target_is_an_error() {
        hold_records_unbounded();
        let mut emu = AotEmulatorCore::recover(program(), start(), 5, true);
        let Err(err) = emu.replay(interpreted) else {
            panic!("the guest halts at 4");
        };
        assert!(
            err.to_string()
                .contains("stopped at 4, not at its target 5"),
            "{err}"
        );
    }

    #[test]
    #[should_panic(expected = "the chunk counter fits u32")]
    fn rolling_over_past_the_last_chunk_number_is_refused() {
        hold_records_unbounded();
        let mut last = start();
        last.current_chunk = u32::MAX;
        let mut emu = AotEmulatorCore::recover(program(), last, 2, true);
        let _ = emu.replay(interpreted);
    }

    /// Only the segment that ends the chunk rolls it over.
    #[test]
    fn a_middle_segment_leaves_the_chunk_running() {
        hold_records_unbounded();
        for (final_segment, chunk, clk) in
            [(false, 1, CHUNK_CLK_START + 8), (true, 2, CHUNK_CLK_START)]
        {
            let mut emu = AotEmulatorCore::recover(program(), start(), 2, final_segment);
            emu.replay(interpreted)
                .expect("the replay reaches its target");
            assert_eq!((emu.current_chunk, emu.clk), (chunk, clk));
        }
    }

    /// A replay that ends the run hands its final state to `postprocess`: x0 first, and every
    /// register the run used, `HALT`'s `t0`, `a0` and `a1` included.
    #[test]
    fn the_last_replay_postprocesses_its_final_state() {
        hold_records_unbounded();
        let mut emu = AotEmulatorCore::recover(program(), start(), 4, true);
        let (_, report) = emu.replay(compiled).expect("the replay reaches the halt");
        assert!(report.done);
        let mut record = EmulationRecord::new(program());
        emu.postprocess(&mut record);
        let finalized: Vec<_> = record
            .memory_finalize_events
            .iter()
            .map(|event| (event.addr, event.value))
            .collect();
        assert_eq!(finalized, [(0, 0), (1, 3), (5, 0), (10, 0), (11, 0)]);
    }

    #[test]
    fn a_core_recovered_in_place_forgets_the_addresses_it_tracked() {
        hold_records_unbounded();
        let mut emu = AotEmulatorCore::recover(program(), start(), 2, true);
        emu.chunk_split_state.track_address(0x200);
        drop(emu.recover_in_place(start(), 2, true));
        assert_eq!(emu.chunk_split_state.unique_address_count(), 0);
        emu.chunk_split_state.track_address(0x200);
        assert_eq!(emu.chunk_split_state.unique_address_count(), 1);
    }

    /// A reused core replays the next snapshot as a fresh one would, and hands back the memory
    /// the previous replay ran on.
    #[test]
    fn a_core_recovered_in_place_replays_as_a_fresh_one() {
        hold_records_unbounded();
        let next = || {
            let mut state = start();
            state.pc = 0x1008;
            state.global_clk = 2;
            state.current_chunk = 2;
            state.memory.insert(0x200, Default::default());
            state
        };
        let mut first = AotEmulatorCore::recover(program(), start(), 2, true);
        first.replay(compiled).expect("the first replay");

        let previous = first.recover_in_place(next(), 4, true);
        assert!(!previous.has_accessed(0x200));
        assert!(first.memory.has_accessed(0x200));
        let mut fresh = AotEmulatorCore::recover(program(), next(), 4, true);
        let (reused, _) = first.replay(compiled).expect("the reused core's replay");
        let (built, _) = fresh.replay(compiled).expect("the fresh core's replay");
        let steps = |record: &EmulationRecord| -> Vec<_> {
            record
                .cpu_steps()
                .iter()
                .map(|step| step.into_owned())
                .collect()
        };
        assert_eq!(steps(&reused.record), steps(&built.record));
        let boundary = |record: &EmulationRecord| {
            let public_values = &record.public_values;
            (public_values.start_pc, public_values.next_pc)
        };
        assert_eq!(boundary(&reused.record), boundary(&built.record));
    }

    /// `ADDI x1, x0, 0x200`, a store of x1 to 0x200 and a load back, then the halt.
    fn storing() -> Arc<Program> {
        Arc::new(Program::new(
            vec![
                Instruction::new(Opcode::ADD, 1, 0, 0x200, false, true),
                Instruction::new(Opcode::SD, 1, 1, 0, false, true),
                Instruction::new(Opcode::LD, 2, 1, 0, false, true),
                Instruction::new(Opcode::ECALL, 5, 10, 11, false, false),
            ],
            0x1000,
            0x1000,
        ))
    }

    /// Only the snapshot thread reads the memory tracker. A worker is re-armed for batch after
    /// batch and never clears it, so one that wrote it would come to hold every page the run
    /// touched. The same run on a core that is not replaying shows what the tracker would hold.
    #[test]
    fn a_replay_worker_leaves_its_memory_tracker_untouched() {
        hold_records_unbounded();
        let tracked =
            |emu: &AotEmulatorCore| emu.memory_snapshot.accessed_keys().collect::<Vec<_>>();

        let mut serial = AotEmulatorCore::new(storing(), Vec::new());
        interpreted(&mut serial).expect("the run");
        assert_eq!(tracked(&serial), [0x200]);

        let mut worker = AotEmulatorCore::recover(storing(), start(), 4, true);
        worker.replay(interpreted).expect("the replay");
        assert!(tracked(&worker).is_empty());
        drop(worker.recover_in_place(start(), 4, true));
        worker.replay(interpreted).expect("the second replay");
        assert!(tracked(&worker).is_empty());
    }
}
