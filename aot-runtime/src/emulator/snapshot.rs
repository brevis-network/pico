use super::AotEmulatorCore;
use hashbrown::HashMap;
use pico_vm::{
    emulator::{
        opts::EmulatorOpts,
        riscv::{
            chunk_split::ChunkSplitConfig,
            memory::{Memory, GLOBAL_MEMORY_POOL},
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

    #[allow(dead_code)]
    pub(crate) fn next_state_batch(
        &mut self,
        opts: EmulatorOpts,
        run_dispatch: fn(&mut AotEmulatorCore) -> Result<(), String>,
    ) -> Result<(RiscvEmulationState, EmulationReport), String> {
        let (start_chunk, start_cycle) = self.initialize_batch(opts);
        let mut snapshot = self.build_snapshot_state();

        run_dispatch(self)?;

        let done = self.is_program_done();

        if !done {
            self.current_batch = self.current_batch.wrapping_add(1);
        }

        if done {
            self.fill_snapshot_memory_full_prestate(&mut snapshot);
        } else {
            self.fill_snapshot_memory_delta(&mut snapshot);
        }

        if !done && self.insn_count == start_cycle && self.batch_chunk_target > 0 {
            return Err(format!(
                "AOT next_state_batch made no progress (start_cycle={}, chunk_batch_target={})",
                start_cycle, self.batch_chunk_target
            ));
        }

        Ok((
            snapshot,
            EmulationReport {
                current_cycle: self.insn_count,
                start_chunk,
                done,
                cycle_tracker: None,
                host_cycle_estimator: None,
            },
        ))
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
        let memory = GLOBAL_MEMORY_POOL
            .1
            .recv()
            .expect("Global memory pool channel closed");
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

        RiscvEmulationState {
            global_clk: self.insn_count,
            current_batch: self.current_batch,
            current_chunk: self.current_chunk,
            clk: self.clk as u64,
            pc: self.pc,
            registers,
            uninitialized_memory: Memory::default(),
            input_stream: self.input_stream.clone(),
            input_stream_ptr: self.input_stream_ptr,
            public_values_stream: self.public_values_stream.clone(),
            memory,
            syscall_counts: HashMap::default(),
        }
    }

    /// Fill snapshot with memory delta (old values of accessed locations).
    ///
    /// Only includes registers and memory addresses that were accessed during the batch.
    pub fn fill_snapshot_memory_delta(&mut self, snapshot: &mut RiscvEmulationState) {
        // Swap the accessed snapshot memory into the outgoing snapshot to avoid
        // iterating the full bitmap every batch (matches simple-mode strategy).
        std::mem::swap(&mut snapshot.memory, &mut self.memory_snapshot);
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
    }
}
