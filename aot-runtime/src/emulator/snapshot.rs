use hashbrown::HashMap;
use pico_vm::{
    chips::chips::riscv_memory::event::MemoryRecord,
    emulator::riscv::{
        memory::{Memory, GLOBAL_MEMORY_POOL},
        state::RiscvEmulationState,
    },
};

use super::AotEmulatorCore;

impl AotEmulatorCore {
    // ========================================================================
    // Snapshot Building
    // ========================================================================

    /// Internal helper to fill snapshot with register state.
    ///
    /// Fills registers into the snapshot based on whether to include all registers
    /// or only accessed ones.
    ///
    /// Note: Uses simple array iteration instead of bitmap bit manipulation.
    /// While bitmap iteration (trailing_zeros + bit clearing) can be faster
    /// for sparse access patterns on some architectures (e.g., Apple Silicon),
    /// the simple linear scan performs better on AMD EPYC (AWS r7a instances)
    /// and for dense register access patterns (common in real programs).
    fn fill_snapshot_registers(&self, snapshot: &mut RiscvEmulationState, include_all: bool) {
        let regs = &self.batch_start_registers;
        let reg_present = &self.batch_start_reg_present;
        let reg_records = &self.batch_start_register_records;

        for i in 0..32 {
            let should_include = if include_all {
                reg_present[i]
            } else {
                self.accessed_regs[i] && reg_present[i]
            };

            if should_include {
                let old_rec = reg_records[i];
                snapshot.memory.insert(
                    i as u32,
                    MemoryRecord {
                        chunk: old_rec.chunk,
                        timestamp: old_rec.timestamp,
                        value: regs[i],
                    },
                );
            }
        }
    }

    /// Build snapshot state header.
    ///
    /// Note: We only include fields essential for trace-mode integration. Fields like `input_stream_ptr`, and
    /// `public_values_stream_ptr` are not essential and are omitted to reduce overhead.
    pub fn build_snapshot_state(&self) -> RiscvEmulationState {
        let memory = GLOBAL_MEMORY_POOL
            .1
            .recv()
            .expect("Global memory pool channel closed");

        RiscvEmulationState {
            global_clk: self.insn_count,
            current_batch: self.current_batch,
            current_chunk: self.current_chunk,
            current_execution_chunk: self.current_chunk,
            clk: self.clk,
            pc: self.pc,
            uninitialized_memory: Memory::default(),
            input_stream: self.input_stream.clone(),
            input_stream_ptr: self.input_stream_ptr,
            public_values_stream: self.public_values_stream.clone(),
            public_values_stream_ptr: self.public_values_stream_ptr,
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
        // Add register prestates after the swap so we don't clobber them.
        self.fill_snapshot_registers(snapshot, false);
    }

    /// Fill snapshot with full prestate (complete batch-start state).
    ///
    /// Includes all registers and memory addresses present at batch start, regardless
    /// of whether they were accessed during the batch.
    pub fn fill_snapshot_memory_full_prestate(&mut self, snapshot: &mut RiscvEmulationState) {
        std::mem::swap(
            &mut snapshot.uninitialized_memory,
            &mut self.uninitialized_memory,
        );
        std::mem::swap(&mut snapshot.memory, &mut self.memory);
        snapshot.memory.par_restore_from(&self.memory_snapshot);
        self.fill_snapshot_registers(snapshot, true);
    }
}
