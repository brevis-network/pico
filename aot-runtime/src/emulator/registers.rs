use pico_vm::chips::chips::riscv_memory::event::MemoryAccessPosition;

use super::{types::RegisterRecord, AotEmulatorCore};

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

    /// Mark a register as accessed.
    #[inline(always)]
    fn mark_reg_accessed(&mut self, reg: usize) {
        self.accessed_regs[reg] = true;
    }

    #[inline(always)]
    pub(crate) fn track_chunk_split_address(&mut self, addr: u32) {
        self.chunk_split_state.insert_memory_address(addr);
    }

    /// Clear all accessed register tracking.
    #[inline(always)]
    pub(crate) fn clear_accessed_regs(&mut self) {
        self.accessed_regs = [false; 32];
    }

    /// Read a register value with lazy materialization and access tracking.
    #[inline(always)]
    pub fn read_reg(&mut self, reg: usize) -> u32 {
        self.read_reg_pos(reg, MemoryAccessPosition::B)
    }

    /// Read a register value at position C (for operand C in instruction encoding).
    #[inline(always)]
    pub fn read_reg_c(&mut self, reg: usize) -> u32 {
        self.read_reg_pos(reg, MemoryAccessPosition::C)
    }

    /// Read a register value at position B (for operand B in instruction encoding).
    #[inline(always)]
    pub fn read_reg_b(&mut self, reg: usize) -> u32 {
        self.read_reg_pos(reg, MemoryAccessPosition::B)
    }

    /// Read a register value at position A (for operand A/write position in instruction encoding).
    #[inline(always)]
    pub fn read_reg_a(&mut self, reg: usize) -> u32 {
        self.read_reg_pos(reg, MemoryAccessPosition::A)
    }

    #[inline(always)]
    fn read_reg_pos(&mut self, reg: usize, position: MemoryAccessPosition) -> u32 {
        self.mark_reg_accessed(reg);
        if !self.reg_present[reg] {
            self.reg_present[reg] = true;
            self.registers[reg] = 0;
        }
        self.register_records[reg] = RegisterRecord {
            chunk: self.current_chunk,
            timestamp: self.clk.wrapping_add(position as u32),
        };
        if reg == 0 {
            0
        } else {
            self.registers[reg]
        }
    }

    /// Read a register value without materialization or access tracking.
    #[inline(always)]
    pub fn read_reg_unsafe(&self, reg: usize) -> u32 {
        if reg == 0 {
            return 0;
        }
        if self.reg_present[reg] {
            self.registers[reg]
        } else {
            0
        }
    }

    /// Read a register value for snapshot compatibility without updating metadata.
    #[inline(always)]
    pub fn read_reg_snapshot(&mut self, reg: usize) -> u32 {
        self.mark_reg_accessed(reg);
        if reg == 0 {
            return 0;
        }
        if self.reg_present[reg] {
            self.registers[reg]
        } else {
            0
        }
    }

    /// Write to a register (writes to x0 are ignored).
    #[inline(always)]
    pub fn write_reg(&mut self, reg: usize, value: u32) {
        self.track_chunk_split_address(reg as u32);
        if reg != 0 {
            self.reg_present[reg] = true;
            self.registers[reg] = value;
        } else {
            self.reg_present[reg] = true;
        }

        self.mark_reg_accessed(reg);
        // Update register metadata for snapshot compatibility
        self.register_records[reg] = RegisterRecord {
            chunk: self.current_chunk,
            timestamp: self.clk.wrapping_add(MemoryAccessPosition::A as u32),
        };

        // Account for register write event to match simple-mode behavior.
        // Simple-mode: rw_simple() calls mw_cpu_simple() which always increments.
        // Unconstrained: rw_unconstrained() doesn't increment (uses write_and_capture_prev_no_mark).
        // We increment only when NOT in unconstrained mode to match this.
        if !self.is_unconstrained_mode() {
            self.chunk_split_state.num_memory_read_write_events += 1;
        }
    }

    /// Read a register value at position A with unconditional tracking (batch-mode optimized).
    ///
    /// This variant uses unconditional tracking for better performance.
    #[inline(always)]
    pub fn read_reg_a_tracked(&mut self, reg: usize) -> u32 {
        self.mark_reg_accessed(reg);
        if !self.reg_present[reg] {
            self.reg_present[reg] = true;
            self.registers[reg] = 0;
        }
        self.register_records[reg] = RegisterRecord {
            chunk: self.current_chunk,
            timestamp: self.clk.wrapping_add(MemoryAccessPosition::A as u32),
        };
        if reg == 0 {
            0
        } else {
            self.registers[reg]
        }
    }

    /// Read a register value at position B with unconditional tracking (batch-mode optimized).
    #[inline(always)]
    pub fn read_reg_b_tracked(&mut self, reg: usize) -> u32 {
        self.mark_reg_accessed(reg);
        if !self.reg_present[reg] {
            self.reg_present[reg] = true;
            self.registers[reg] = 0;
        }
        self.register_records[reg] = RegisterRecord {
            chunk: self.current_chunk,
            timestamp: self.clk.wrapping_add(MemoryAccessPosition::B as u32),
        };
        if reg == 0 {
            0
        } else {
            self.registers[reg]
        }
    }

    /// Read a register value at position C with unconditional tracking (batch-mode optimized).
    #[inline(always)]
    pub fn read_reg_c_tracked(&mut self, reg: usize) -> u32 {
        self.mark_reg_accessed(reg);
        if !self.reg_present[reg] {
            self.reg_present[reg] = true;
            self.registers[reg] = 0;
        }
        self.register_records[reg] = RegisterRecord {
            chunk: self.current_chunk,
            timestamp: self.clk.wrapping_add(MemoryAccessPosition::C as u32),
        };
        if reg == 0 {
            0
        } else {
            self.registers[reg]
        }
    }

    /// Write to a register with unconditional tracking (batch-mode optimized).
    #[inline(always)]
    pub fn write_reg_tracked(&mut self, reg: usize, value: u32) {
        self.track_chunk_split_address(reg as u32);
        if reg != 0 {
            self.reg_present[reg] = true;
            self.registers[reg] = value;
        } else {
            self.reg_present[reg] = true;
        }
        self.mark_reg_accessed(reg);
        self.register_records[reg] = RegisterRecord {
            chunk: self.current_chunk,
            timestamp: self.clk.wrapping_add(MemoryAccessPosition::A as u32),
        };

        // Account for register write event to match simple-mode behavior (same as write_reg).
        if !self.is_unconstrained_mode() {
            self.chunk_split_state.num_memory_read_write_events += 1;
        }
    }

    /// Write to a register in constrained mode (block-level unconstrained check already done).
    ///
    /// This variant skips the per-operation is_unconstrained_mode() check because the
    /// generated block has already verified we're not in unconstrained mode at entry.
    /// Always increments the memory RW event counter.
    #[inline(always)]
    pub fn write_reg_constrained(&mut self, reg: usize, value: u32) {
        self.track_chunk_split_address(reg as u32);
        if reg != 0 {
            self.reg_present[reg] = true;
            self.registers[reg] = value;
        } else {
            self.reg_present[reg] = true;
        }
        self.mark_reg_accessed(reg);
        self.register_records[reg] = RegisterRecord {
            chunk: self.current_chunk,
            timestamp: self.clk.wrapping_add(MemoryAccessPosition::A as u32),
        };
        // Unconditionally increment - we know we're not in unconstrained mode
        self.chunk_split_state.num_memory_read_write_events += 1;
    }

    /// Write to a register without incrementing event counter (for block-level batching).
    ///
    /// Event counting is deferred to block end via `add_memory_rw_events()`.
    /// Only use this when the block tracks static event counts.
    #[inline(always)]
    pub fn write_reg_no_count(&mut self, reg: usize, value: u32) {
        self.track_chunk_split_address(reg as u32);
        if reg != 0 {
            self.reg_present[reg] = true;
            self.registers[reg] = value;
        } else {
            self.reg_present[reg] = true;
        }
        self.mark_reg_accessed(reg);
        self.register_records[reg] = RegisterRecord {
            chunk: self.current_chunk,
            timestamp: self.clk.wrapping_add(MemoryAccessPosition::A as u32),
        };
        // NO increment - deferred to block end
    }

    /// Batch update memory RW event counter.
    ///
    /// Called at block end to add the statically computed event count
    /// when using `_no_count` instruction variants.
    #[inline(always)]
    pub fn add_memory_rw_events(&mut self, count: usize) {
        self.chunk_split_state.num_memory_read_write_events += count;
    }
}
