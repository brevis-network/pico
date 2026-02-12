use hashbrown::HashMap;
use pico_vm::chips::chips::riscv_memory::event::MemoryRecord;

use super::{state::UnconstrainedState, AotEmulatorCore};

impl AotEmulatorCore {
    // ========================================================================
    // Unconstrained Mode
    // ========================================================================

    /// Check if the emulator is currently in unconstrained execution mode.
    #[inline(always)]
    pub fn is_unconstrained_mode(&self) -> bool {
        self.unconstrained_state.is_some()
    }

    /// Enter unconstrained execution mode.
    ///
    /// Saves current state (registers, timing, memory diff) for later restoration.
    /// Nested unconstrained mode is not supported and will panic.
    pub(crate) fn enter_unconstrained_mode(&mut self) {
        if self.unconstrained_state.is_some() {
            panic!("Nested ENTER_UNCONSTRAINED is not supported in AOT emulation");
        }

        self.unconstrained_state = Some(UnconstrainedState {
            pc: self.pc,
            clk: self.clk,
            insn_count: self.insn_count,
            current_chunk: self.current_chunk,
            batch_chunks_emulated: self.batch_chunks_emulated,
            batch_stop: self.batch_stop,
            registers: self.registers,
            reg_present: self.reg_present,
            register_records: self.register_records,
            // Note: accessed_regs is NOT saved - it persists
            // across unconstrained mode to match baseline behavior.
            memory_diff: HashMap::default(),
            committed_value_digest: self.committed_value_digest,
            deferred_proofs_digest: self.deferred_proofs_digest,
        });
    }

    /// Exit unconstrained execution mode and restore previous state.
    ///
    /// Restores all saved state (registers, timing, memory) to pre-unconstrained values.
    /// Returns the next PC to execute after unconstrained mode, or None if not in unconstrained mode.
    pub(crate) fn exit_unconstrained_mode(&mut self) -> Option<u32> {
        let mut state = self.unconstrained_state.take()?;

        // Restore timing/chunk state (matches baseline behavior)
        self.pc = state.pc;
        self.clk = state.clk;
        self.insn_count = state.insn_count;
        self.current_chunk = state.current_chunk;
        self.batch_chunks_emulated = state.batch_chunks_emulated;
        self.batch_stop = state.batch_stop;

        // Restore registers to pre-unconstrained state.
        // In baseline, registers are stored at memory addresses 0-31, so they are
        // restored as part of memory_diff. In AOT, we store them separately, so we
        // need to explicitly restore them here.
        self.registers = state.registers;
        self.reg_present = state.reg_present;
        self.register_records = state.register_records;

        // Note: We do NOT restore accessed_regs.
        // Baseline's memory_snapshot persists across unconstrained mode boundaries,
        // capturing old values of all addresses accessed during the batch (including
        // during unconstrained mode). By keeping our current accessed_* state instead
        // of restoring it, we match baseline's behavior of tracking all accesses.
        self.committed_value_digest = state.committed_value_digest;
        self.deferred_proofs_digest = state.deferred_proofs_digest;

        // Restore memory to pre-unconstrained state (consolidated value + metadata).
        // Use default record for uninitialized memory.
        for (addr, record) in state.memory_diff.drain() {
            self.memory.insert(addr, record);
        }

        Some(self.pc.wrapping_add(4))
    }

    /// Record a memory access during unconstrained mode for later restoration.
    ///
    /// Captures the pre-unconstrained value of the memory address so it can be
    /// restored when exiting unconstrained mode.
    #[inline(always)]
    pub(crate) fn record_unconstrained_memory_access(
        &mut self,
        addr: u32,
        prev_record: MemoryRecord,
    ) {
        let Some(state) = self.unconstrained_state.as_mut() else {
            return;
        };

        // Record memory state (consolidated value + metadata).
        state.memory_diff.entry(addr).or_insert(prev_record);
    }
}
