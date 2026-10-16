use super::AotEmulatorCore;
use hashbrown::HashMap;
use pico_vm::{
    emulator::{
        opts::EmulatorOpts,
        riscv::{
            chunk_split::ChunkSplitConfig,
            memory::{
                Memory, RecvTimeoutError, GLOBAL_MEMORY_POOL, GLOBAL_MEMORY_RECYCLER, POOL_WAIT,
            },
            riscv_emulator::EmulationError,
            state::{RiscvEmulationState, RuntimeRegisterRecord},
        },
    },
    machine::report::EmulationReport,
};

impl AotEmulatorCore {
    // ========================================================================
    // Batch Execution
    // ========================================================================

    #[allow(dead_code)]
    fn initialize_batch(&mut self, opts: EmulatorOpts) -> (u32, u64) {
        let start_chunk = self.current_chunk;
        let start_cycle = self.insn_count;

        self.batch_chunk_target = opts.chunk_batch_size;
        self.batch_chunks_emulated = 0;
        self.batch_stop = false;
        self.chunk_split_config =
            ChunkSplitConfig::for_chunk_size(opts.chunk_size, self.max_syscall_cycles);
        self.save_batch_start_state();

        (start_chunk, start_cycle)
    }

    #[inline(always)]
    fn snapshot_stream_state(&self, snapshot: &mut RiscvEmulationState) {
        snapshot.input_stream = self.input_stream.clone();
        snapshot.input_stream_ptr = self.input_stream_ptr;
        snapshot.public_values_stream = self.public_values_stream.clone();
    }

    #[inline(always)]
    pub fn is_program_done(&self) -> bool {
        self.pc == 0
            || self.pc.wrapping_sub(self.program_pc_base()).wrapping_div(4)
                >= self.program_len() as u64
    }

    #[allow(dead_code)]
    pub(crate) fn run_to_completion(
        &mut self,
        run_dispatch: fn(&mut AotEmulatorCore) -> Result<(), String>,
    ) -> Result<(), String> {
        self.batch_chunk_target = 0;
        self.batch_chunks_emulated = 0;
        self.batch_stop = false;
        self.chunk_split_config = ChunkSplitConfig::disabled(self.max_syscall_cycles);
        run_dispatch(self)
    }

    pub(crate) fn next_state_batch(
        &mut self,
        opts: EmulatorOpts,
        run_dispatch: fn(&mut AotEmulatorCore) -> Result<(), String>,
    ) -> Result<(RiscvEmulationState, EmulationReport), EmulationError> {
        let (mut segments, report) = self.next_state_batch_segments(opts, run_dispatch, 1)?;
        let (state, _) = segments.pop().expect("a batch always yields one segment");
        Ok((state, report))
    }

    /// The batch's replay segments, in clock order, as `(start state, target instruction count)`.
    ///
    /// `segments = 1` is the shipped path and yields exactly what [`Self::next_state_batch`]
    /// always did. Above one, the dispatch is handed back mid-chunk and each hand-back closes a
    /// segment and opens the next — the same save/build/fill sequence a batch boundary runs,
    /// minus the chunk bookkeeping, so the chunk itself is untouched and still proves once.
    pub(crate) fn next_state_batch_segments(
        &mut self,
        opts: EmulatorOpts,
        run_dispatch: fn(&mut AotEmulatorCore) -> Result<(), String>,
        segments: u32,
    ) -> Result<(Vec<(RiscvEmulationState, u64)>, EmulationReport), EmulationError> {
        let (start_chunk, start_cycle) = self.initialize_batch(opts);
        let mut pending = PendingSnapshots {
            closed: Vec::with_capacity(segments as usize),
            open: Some(self.build_snapshot_state()),
        };

        // Where the chunk ends is only known once we reach it, so the cut points aim at the
        // configured chunk size instead. A chunk that stops short yields fewer segments and one
        // that runs long yields a bigger last one; neither is a correctness matter, and the
        // makespan only feels the longest segment.
        let step = u64::from(opts.chunk_size) / u64::from(segments.max(1));
        let mut opened = 0;
        self.arm_sub_yield(segments, opened, start_cycle, step);

        loop {
            if let Err(message) = run_dispatch(self) {
                return Err(self
                    .fault
                    .take()
                    .unwrap_or(EmulationError::AotExecutionFailed(message)));
            }
            if self.batch_stop || self.is_program_done() {
                break;
            }
            // A sub-yield: close the segment that just ran and open the next at the same point.
            self.fill_snapshot_memory_delta(pending.open_mut());
            pending.close(self.insn_count);
            self.save_batch_start_state();
            pending.open = Some(self.build_snapshot_state());
            opened += 1;
            self.arm_sub_yield(segments, opened, self.insn_count, step);
        }
        self.next_sub_yield = u64::MAX;

        // The interpreter refuses a run once its clock reaches `max_cycles`, checked after every
        // instruction. Checked here once the batch has run, and before any of it is handed on, so
        // no replay worker is given cycles past the limit.
        if let Some(max_cycles) = opts.max_cycles.filter(|&max| self.insn_count >= max) {
            return Err(EmulationError::ExceededCycleLimit(max_cycles));
        }

        let done = self.is_program_done();

        if !done {
            self.current_batch = self.current_batch.wrapping_add(1);
        }

        // NOTE: `memory_snapshot_clean` is maintained by `snapshot_addr_if_needed` itself
        // (the single write site), so no protocol-level dirty-marking is needed here.
        if done {
            self.fill_snapshot_memory_full_prestate(pending.open_mut());
        } else {
            self.fill_snapshot_memory_delta(pending.open_mut());
        }
        pending.close(self.insn_count);

        if !done && self.insn_count == start_cycle && self.batch_chunk_target > 0 {
            return Err(EmulationError::AotBatchNoProgress {
                start_cycle,
                chunk_batch_target: self.batch_chunk_target,
            });
        }

        Ok((
            pending.hand_on(),
            EmulationReport {
                current_cycle: self.insn_count,
                start_chunk,
                done,
                cycle_tracker: None,
                host_cycle_estimator: None,
            },
        ))
    }

    /// Point `should_yield` at the next cut, or disarm it on the last segment.
    ///
    /// Always strictly ahead of where we are now: armed at or behind it, the dispatch would hand
    /// back without executing anything and the loop would not advance.
    fn arm_sub_yield(&mut self, segments: u32, opened: u32, from: u64, step: u64) {
        self.next_sub_yield = if step > 0 && opened + 1 < segments {
            from.saturating_add(step)
        } else {
            u64::MAX
        };
    }

    // ========================================================================
    // Snapshot Building
    // ========================================================================

    /// Overwrite touched registers in the snapshot with batch-start prestates.
    ///
    /// Baseline `next_state_batch` clones the current register file first and then rolls back only
    /// registers touched during the batch. AOT must mirror that contract; untouched live registers
    /// remain in the snapshot, while touched ones are restored to batch-start state.
    fn restore_touched_snapshot_registers(&self, snapshot: &mut RiscvEmulationState) {
        let regs = &self.batch_start_registers;
        let reg_present = &self.batch_start_reg_present;
        let reg_records = &self.batch_start_register_records;

        for i in 0..32 {
            if self.accessed_regs[i] && reg_present[i] {
                let old_rec = reg_records[i];
                snapshot.registers[i] = RuntimeRegisterRecord {
                    chunk: old_rec.chunk,
                    timestamp: old_rec.timestamp,
                    value: regs[i],
                };
            }
        }
    }

    /// Build snapshot state header.
    ///
    /// Note: We only include fields essential for trace-mode integration.
    /// Telemetry-only fields are intentionally omitted.
    pub fn build_snapshot_state(&self) -> RiscvEmulationState {
        // Every AOT batch takes a memory here, and one being cut into segments holds all of them
        // at once, so an empty pool can be a standoff rather than back-pressure. Say so once the
        // wait stops looking normal, but keep waiting: a merely slow run must not lose its prove,
        // and `split_segments` already warns at startup about the configuration that stands off.
        let mut reported = false;
        let memory = loop {
            match GLOBAL_MEMORY_POOL.1.recv_timeout(POOL_WAIT) {
                Ok(memory) => break memory,
                Err(RecvTimeoutError::Disconnected) => {
                    panic!("Global memory pool channel closed")
                }
                Err(RecvTimeoutError::Timeout) => {
                    if !std::mem::replace(&mut reported, true) {
                        log::warn!(
                            "waiting on the memory pool for over {}s; raise MEMORY_POOL_SIZE or \
                             cut fewer segments",
                            POOL_WAIT.as_secs()
                        );
                    }
                }
            }
        };
        let mut registers = [RuntimeRegisterRecord::default(); 32];
        for (idx, present) in self.reg_present.iter().copied().enumerate() {
            if present {
                let record = self.register_records[idx];
                registers[idx] = RuntimeRegisterRecord {
                    chunk: record.chunk,
                    timestamp: record.timestamp,
                    value: self.registers[idx],
                };
            }
        }

        let mut snapshot = RiscvEmulationState {
            global_clk: self.insn_count,
            current_batch: self.current_batch,
            current_chunk: self.current_chunk,
            clk: self.clk as u64,
            pc: self.pc,
            registers,
            uninitialized_memory: Memory::default(),
            // Stream fields are filled by `snapshot_stream_state` below; cloning them here
            // is redundant (the clones would be immediately overwritten). Start empty to
            // avoid one input_stream + one public_values_stream clone per batch.
            input_stream: Vec::new(),
            input_stream_ptr: 0,
            public_values_stream: Vec::new(),
            memory,
            syscall_counts: HashMap::default(),
        };
        self.snapshot_stream_state(&mut snapshot);
        snapshot
    }

    /// Fill snapshot with memory delta (old values of accessed locations).
    ///
    /// Only includes registers and memory addresses that were accessed during the batch.
    pub fn fill_snapshot_memory_delta(&mut self, snapshot: &mut RiscvEmulationState) {
        // Swap the accessed snapshot memory into the outgoing snapshot to avoid
        // iterating the full bitmap every batch (matches simple-mode strategy).
        std::mem::swap(&mut snapshot.memory, &mut self.memory_snapshot);
        // `self.memory_snapshot` now holds the fresh (clean) pooled memory recv'd in
        // `build_snapshot_state`, so the next batch can skip its `clear()` scan.
        self.memory_snapshot_clean = true;
        self.restore_touched_snapshot_registers(snapshot);
    }

    /// Fill snapshot with full prestate (complete batch-start state).
    ///
    /// Includes all registers and memory addresses present at batch start, regardless
    /// of whether they were accessed during the batch.
    pub fn fill_snapshot_memory_full_prestate(&mut self, snapshot: &mut RiscvEmulationState) {
        let mut batch_memory_snapshot = std::mem::take(&mut self.memory_snapshot);
        std::mem::swap(
            &mut snapshot.uninitialized_memory,
            &mut self.uninitialized_memory,
        );
        std::mem::swap(&mut snapshot.memory, &mut self.memory);
        snapshot.memory.par_restore_from(&batch_memory_snapshot);
        self.restore_touched_snapshot_registers(snapshot);
        batch_memory_snapshot.reset();
        self.memory_snapshot = batch_memory_snapshot;
        // `batch_memory_snapshot` was just `reset()` (clean). (This is the final/`done` batch, so
        // there is no next `save_batch_start_state`, but keep the flag honest.)
        self.memory_snapshot_clean = true;
    }
}

/// The snapshots a batch has built and not yet handed on. Each holds a memory from the pipeline's
/// pool, which only a replay worker returns and which the pool never replaces, so a batch that
/// fails or unwinds first returns them here: otherwise every failed run would leave the process's
/// pool one memory smaller, and once it is empty every later AOT run waits on it forever.
struct PendingSnapshots {
    closed: Vec<(RiscvEmulationState, u64)>,
    open: Option<RiscvEmulationState>,
}

impl PendingSnapshots {
    fn open_mut(&mut self) -> &mut RiscvEmulationState {
        self.open
            .as_mut()
            .expect("a batch keeps one snapshot open until it closes it")
    }

    /// Closes the open snapshot as a segment that runs up to `target`.
    fn close(&mut self, target: u64) {
        let snapshot = self
            .open
            .take()
            .expect("a batch keeps one snapshot open until it closes it");
        self.closed.push((snapshot, target));
    }

    /// The closed segments, now the caller's to hand on.
    fn hand_on(mut self) -> Vec<(RiscvEmulationState, u64)> {
        std::mem::take(&mut self.closed)
    }
}

impl Drop for PendingSnapshots {
    fn drop(&mut self) {
        let open = self.open.take();
        for snapshot in self
            .closed
            .drain(..)
            .map(|(snapshot, _)| snapshot)
            .chain(open)
        {
            let _ = GLOBAL_MEMORY_RECYCLER.send((snapshot.memory, true));
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        sync::{mpsc, Arc},
        thread,
        time::Duration,
    };

    use pico_vm::{
        compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
        emulator::{
            opts::EmulatorOpts,
            riscv::{
                memory::{memory_pool_size, GLOBAL_MEMORY_RECYCLER},
                riscv_emulator::EmulationError,
                state::RiscvEmulationState,
            },
        },
    };

    use crate::AotEmulatorCore;

    /// Two `ADD`s, then a `JALR` to pc 0, which halts: a run of three cycles.
    fn program() -> Arc<Program> {
        Arc::new(Program::new(
            vec![
                Instruction::new(Opcode::ADD, 1, 0, 0, false, false),
                Instruction::new(Opcode::ADD, 2, 0, 0, false, false),
                Instruction::new(Opcode::JALR, 0, 0, 0, false, true),
            ],
            0x1000,
            0x1000,
        ))
    }

    fn interpret(emu: &mut AotEmulatorCore) -> Result<(), String> {
        emu.run_blocks(|_| None)
    }

    fn unknown_syscall(emu: &mut AotEmulatorCore) -> Result<(), String> {
        emu.execute_syscall(0x77, 0, 0).map(|_| ())
    }

    fn untyped_failure(_: &mut AotEmulatorCore) -> Result<(), String> {
        Err("commit word_idx index out of range: 8 >= 8".to_string())
    }

    fn opts(max_cycles: Option<u64>) -> EmulatorOpts {
        EmulatorOpts {
            max_cycles,
            ..EmulatorOpts::test_opts()
        }
    }

    /// Hands the batch's memories back to the pool, as the replay workers do.
    fn recycle(segments: Vec<(RiscvEmulationState, u64)>) {
        for (snapshot, _) in segments {
            let _ = GLOBAL_MEMORY_RECYCLER.send((snapshot.memory, true));
        }
    }

    #[test]
    fn a_failed_dispatch_returns_the_typed_error_behind_its_message() {
        let mut emu = AotEmulatorCore::new(program(), Vec::new());
        let err = emu
            .next_state_batch_segments(opts(None), unknown_syscall, 1)
            .expect_err("the syscall fails the batch");
        assert!(
            matches!(err, EmulationError::UnsupportedSyscall(0x77)),
            "{err:?}"
        );
        assert!(emu.fault.is_none(), "the batch took the fault it returned");

        let err = AotEmulatorCore::new(program(), Vec::new())
            .next_state_batch_segments(opts(None), untyped_failure, 1)
            .expect_err("the dispatch fails the batch");
        assert!(
            matches!(&err, EmulationError::AotExecutionFailed(message) if message.contains("8 >= 8")),
            "an error no syscall typed keeps its message: {err:?}"
        );
    }

    /// The interpreter checks the limit after every instruction, so a run of exactly `max_cycles`
    /// is refused and one cycle more is room enough.
    #[test]
    fn a_batch_that_reaches_max_cycles_is_refused() {
        let err = AotEmulatorCore::new(program(), Vec::new())
            .next_state_batch_segments(opts(Some(3)), interpret, 1)
            .expect_err("three cycles reach a limit of three");
        assert!(
            matches!(err, EmulationError::ExceededCycleLimit(3)),
            "{err:?}"
        );

        for max_cycles in [Some(4), None] {
            let (segments, report) = AotEmulatorCore::new(program(), Vec::new())
                .next_state_batch_segments(opts(max_cycles), interpret, 1)
                .expect("the run fits");
            assert!(report.done);
            assert_eq!(report.current_cycle, 3);
            recycle(segments);
        }
    }

    /// The pool never replaces a memory, so refusing more batches than it holds waits on an empty
    /// pool for good unless every refusal handed back the memory its batch took.
    #[test]
    fn a_refused_batch_returns_its_memory_to_the_pool() {
        let (results, refusals) = mpsc::channel();
        thread::spawn(move || {
            // Halted at the limit, it refuses every later batch as well.
            let mut emu = AotEmulatorCore::new(program(), Vec::new());
            loop {
                let refused = emu
                    .next_state_batch_segments(opts(Some(3)), interpret, 1)
                    .map(|(segments, _)| recycle(segments));
                if results.send(refused).is_err() {
                    break;
                }
            }
        });
        for batch in 0..=memory_pool_size() {
            let refused = refusals
                .recv_timeout(Duration::from_secs(60))
                .unwrap_or_else(|err| panic!("batch {batch} never came back ({err})"));
            assert!(
                matches!(refused, Err(EmulationError::ExceededCycleLimit(3))),
                "batch {batch}: {refused:?}"
            );
        }
    }
}
