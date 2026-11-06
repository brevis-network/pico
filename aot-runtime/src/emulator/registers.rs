use pico_vm::chips::chips::riscv_memory::event::MemoryAccessPosition;

use super::{
    sink::{by_sink, LentSink},
    types::RegisterRecord,
    AotEmulatorCore,
};

impl AotEmulatorCore {
    // ========================================================================
    // Syscall Tracking
    // ========================================================================

    #[inline(always)]
    pub(crate) fn enter_syscall(&mut self) {
        self.chunk_split_state.enter_syscall();
    }

    #[inline(always)]
    pub(crate) fn exit_syscall(&mut self) {
        self.chunk_split_state.exit_syscall();
    }

    #[inline(always)]
    pub(crate) fn in_syscall(&self) -> bool {
        self.chunk_split_state.in_syscall()
    }

    // ========================================================================
    // Register Operations
    // ========================================================================

    /// Mark a register as accessed: a byte per register makes the mark one store, where a bit mask
    /// would cost a load and a test on every access.
    #[inline(always)]
    fn mark_reg_accessed(&mut self, reg: usize) {
        self.touched_registers[reg] = true;
    }

    /// Single write site for the per-access register record.
    #[inline(always)]
    fn set_reg_record(&mut self, reg: usize, value: u64, timestamp: u32) {
        self.registers[reg] = RegisterRecord {
            chunk: self.current_chunk,
            timestamp,
            value,
        };
    }

    #[inline(always)]
    pub(crate) fn track_chunk_split_address(&mut self, addr: u64) {
        self.chunk_split_state.track_address(addr);
    }

    /// Clear all accessed register tracking.
    #[inline(always)]
    pub(crate) fn clear_touched_registers(&mut self) {
        self.touched_registers = [false; 32];
    }

    /// Read a register value at position C (for operand C in instruction encoding).
    #[inline(always)]
    pub fn read_reg_c(&mut self, reg: usize) -> u64 {
        self.read_reg_pos(reg, MemoryAccessPosition::C)
    }

    /// Read a register value at position B (for operand B in instruction encoding).
    #[inline(always)]
    pub fn read_reg_b(&mut self, reg: usize) -> u64 {
        self.read_reg_pos(reg, MemoryAccessPosition::B)
    }

    /// Read a register value at position A (for operand A/write position in instruction encoding).
    #[inline(always)]
    pub fn read_reg_a(&mut self, reg: usize) -> u64 {
        self.read_reg_pos(reg, MemoryAccessPosition::A)
    }

    #[inline(always)]
    fn read_reg_pos(&mut self, reg: usize, position: MemoryAccessPosition) -> u64 {
        by_sink!(self.read_reg_at(reg, position))
    }

    /// The read of `reg` in operand `position`, its access written into `sink` when `EMIT`.
    #[inline(always)]
    pub(crate) fn read_reg_at<const EMIT: bool>(
        &mut self,
        sink: LentSink<'_>,
        reg: usize,
        position: MemoryAccessPosition,
    ) -> u64 {
        self.mark_reg_accessed(reg);
        let prev = self.registers[reg];
        let timestamp = self.clk.wrapping_add(position as u32);
        self.set_reg_record(reg, prev.value, timestamp);
        let value = if reg == 0 { 0 } else { prev.value };
        if EMIT {
            self.record_reg_read(sink, reg, position, value, prev, timestamp);
        }
        value
    }

    /// Read a register value without access tracking.
    #[inline(always)]
    pub fn read_reg_unsafe(&self, reg: usize) -> u64 {
        if reg == 0 {
            return 0;
        }
        self.registers[reg].value
    }

    /// Read a register value for snapshot compatibility without updating metadata.
    #[inline(always)]
    pub fn read_reg_snapshot(&mut self, reg: usize) -> u64 {
        self.mark_reg_accessed(reg);
        self.read_reg_unsafe(reg)
    }

    /// Writes `value` to `reg` at operand `a`'s timestamp, `x0` keeping 0, its access written
    /// into `sink` when `EMIT`: what every write variant below does before its event counting.
    #[inline(always)]
    pub(crate) fn set_reg<const EMIT: bool>(&mut self, sink: LentSink<'_>, reg: usize, value: u64) {
        self.track_chunk_split_address(reg as u64);
        let prev_value = self.read_reg_unsafe(reg);
        let prev = self.registers[reg];
        let written = if reg == 0 { 0 } else { value };
        self.mark_reg_accessed(reg);
        let timestamp = self.clk.wrapping_add(MemoryAccessPosition::A as u32);
        self.set_reg_record(reg, written, timestamp);
        if EMIT {
            self.record_reg_write(sink, reg, written, prev_value, prev, timestamp);
        }
    }

    /// Write to a register (writes to x0 are ignored).
    #[inline(always)]
    pub fn write_reg(&mut self, reg: usize, value: u64) {
        self.write_reg_no_count(reg, value);

        // Account for register write event to match simple-mode behavior.
        // Simple-mode: rw_simple() calls mw_cpu_simple() which always increments.
        // Unconstrained: rw_unconstrained() doesn't increment (uses write_and_capture_prev_no_mark).
        // We increment only when NOT in unconstrained mode to match this.
        if !self.is_unconstrained_mode() {
            self.chunk_split_state.add_memory_rw_events(1);
        }
    }

    /// Write to a register without incrementing event counter (for block-level batching).
    ///
    /// Event counting is deferred to block end via `add_memory_rw_events()`.
    /// Only use this when the block tracks static event counts.
    #[inline(always)]
    pub fn write_reg_no_count(&mut self, reg: usize, value: u64) {
        by_sink!(self.set_reg(reg, value));
        // NO increment - deferred to block end
    }

    /// Batch update memory RW event counter.
    ///
    /// Called at block end to add the statically computed event count
    /// when using `_no_count` instruction variants.
    #[inline(always)]
    pub fn add_memory_rw_events(&mut self, count: usize) {
        self.chunk_split_state.add_memory_rw_events(count);
    }
}
