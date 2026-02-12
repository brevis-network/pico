use pico_vm::chips::chips::riscv_memory::event::MemoryRecord;

use super::{constants::BYTES_PER_WORD, AotEmulatorCore};

impl AotEmulatorCore {
    // ========================================================================
    // Memory Operations
    // ========================================================================

    #[inline(always)]
    fn snapshot_addr_if_needed(&mut self, addr: u32, prev_record: &MemoryRecord) {
        if addr < 32 {
            let bit = 1u32 << addr;
            if (self.snapshot_registers_bitmap & bit) == 0 {
                self.snapshot_registers_bitmap |= bit;
            }
            return;
        }

        if !self.memory_snapshot.has_accessed(addr) {
            self.memory_snapshot.insert(addr, *prev_record);
        }
    }

    #[inline(always)]
    pub(crate) fn capture_snapshot_for_hint(&mut self, addr: u32) {
        let zero_record = MemoryRecord {
            value: 0,
            chunk: 0,
            timestamp: 0,
        };
        self.snapshot_addr_if_needed(addr, &zero_record);
    }

    #[inline(always)]
    fn account_memory_access(&mut self, _addr: u32) {
        // NOTE: Simple-mode tracks unique addresses via chunk_split_state.memory_access_addrs.
        // AOT must mirror this to keep chunk boundary detection consistent with gpu-base.
        if self.in_syscall() {
            self.chunk_split_state.num_syscall_memory_events += 1;
        } else {
            self.chunk_split_state.num_memory_read_write_events += 1;
        }
    }

    #[inline(always)]
    fn account_syscall_memory_access(&mut self, _addr: u32) {
        // NOTE: Simple-mode tracks unique addresses via chunk_split_state.memory_access_addrs.
        self.chunk_split_state.num_syscall_memory_events += 1;
    }

    /// Internal helper for reading memory with metadata update.
    ///
    /// Handles unconstrained mode tracking, memory materialization, and access tracking.
    /// Both `read_mem` and `read_mem_fast` use this shared implementation.
    #[inline(always)]
    fn read_mem_internal(&mut self, addr: u32) -> u32 {
        self.track_chunk_split_address(addr);
        // NOTE: Simple-mode tracks unique addresses via chunk_split_state.memory_access_addrs.
        // It still only increments num_memory_read_write_events on writes.
        // Syscall memory reads still need to track num_syscall_memory_events.
        if self.in_syscall() {
            self.chunk_split_state.num_syscall_memory_events += 1;
        }
        let is_unconstrained = self.is_unconstrained_mode();

        let (value, prev_chunk, prev_timestamp) = if is_unconstrained {
            self.memory
                .read_and_update_metadata_no_mark(addr, self.current_chunk, self.clk)
        } else {
            self.memory
                .read_and_update_metadata(addr, self.current_chunk, self.clk)
        };

        let prev_record = MemoryRecord {
            value,
            chunk: prev_chunk,
            timestamp: prev_timestamp,
        };

        if is_unconstrained {
            self.record_unconstrained_memory_access(addr, prev_record);
        }
        self.snapshot_addr_if_needed(addr, &prev_record);

        value
    }

    /// Read a word from memory (aligned to 4-byte boundary).
    ///
    /// Materializes memory if needed, updates metadata, and tracks access.
    /// Returns the value read from memory.
    #[inline(always)]
    pub fn read_mem(&mut self, addr: u32) -> u32 {
        self.read_mem_internal(addr)
    }

    /// Read a word from memory without memory-record bookkeeping.
    ///
    /// Still updates chunk/timestamp to match baseline behavior.
    /// This is a performance-optimized version that shares the same implementation
    /// as `read_mem` but is provided for clarity in generated code.
    #[inline(always)]
    pub fn read_mem_fast(&mut self, addr: u32) -> u32 {
        self.read_mem_internal(addr)
    }

    /// Read a word from memory without materialization or access tracking.
    ///
    /// This is a read-only operation that does not update metadata or track accesses.
    /// Use only when you know the memory address is already materialized.
    #[inline(always)]
    pub fn read_mem_unsafe(&self, addr: u32) -> u32 {
        let record = self.memory.get(addr);
        if record.value != 0 || record.chunk != 0 || record.timestamp != 0 {
            record.value
        } else if let Some(&value) = self.uninitialized_memory.get(addr) {
            value
        } else {
            0
        }
    }

    /// Read a word from memory for snapshot compatibility without updating metadata.
    #[inline(always)]
    pub fn read_mem_snapshot(&mut self, addr: u32) -> u32 {
        let record = self.memory.get(addr);
        self.snapshot_addr_if_needed(addr, &record);

        if record.value != 0 || record.chunk != 0 || record.timestamp != 0 {
            record.value
        } else if let Some(&value) = self.uninitialized_memory.get(addr) {
            value
        } else {
            0
        }
    }

    /// Read a span of memory words for snapshot compatibility without updating metadata.
    #[inline(always)]
    pub fn read_mem_span_snapshot(&mut self, addr: u32, out: &mut [u32]) {
        for (i, slot) in out.iter_mut().enumerate() {
            let word_addr = addr + (i as u32) * BYTES_PER_WORD;
            *slot = self.read_mem_snapshot(word_addr);
        }
    }

    /// Internal helper for writing memory with metadata update.
    ///
    /// Handles unconstrained mode tracking, memory updates, and access tracking.
    /// Both `write_mem` and `write_mem_fast` use this shared implementation.
    #[inline(always)]
    fn write_mem_internal(&mut self, addr: u32, value: u32) {
        self.track_chunk_split_address(addr);
        self.account_memory_access(addr);
        let is_unconstrained = self.is_unconstrained_mode();

        let (prev_value, prev_chunk, prev_timestamp) = if is_unconstrained {
            self.memory
                .write_and_capture_prev_no_mark(addr, value, self.current_chunk, self.clk)
        } else {
            self.memory
                .write_and_capture_prev(addr, value, self.current_chunk, self.clk)
        };

        let prev_record = MemoryRecord {
            value: prev_value,
            chunk: prev_chunk,
            timestamp: prev_timestamp,
        };

        if is_unconstrained {
            self.record_unconstrained_memory_access(addr, prev_record);
        }
        self.snapshot_addr_if_needed(addr, &prev_record);
    }

    /// Write a word to memory (aligned to 4-byte boundary).
    ///
    /// Updates or creates a memory record with the new value and current metadata.
    #[inline(always)]
    pub fn write_mem(&mut self, addr: u32, value: u32) {
        self.write_mem_internal(addr, value)
    }

    /// Write a word to memory without memory-record bookkeeping.
    ///
    /// Still updates chunk/timestamp to match baseline behavior.
    /// This is a performance-optimized version that shares the same implementation
    /// as `write_mem` but is provided for clarity in generated code.
    #[inline(always)]
    pub fn write_mem_fast(&mut self, addr: u32, value: u32) {
        self.write_mem_internal(addr, value)
    }

    /// Read a word from memory in constrained mode (block-level unconstrained check already done).
    ///
    /// This variant skips the per-operation is_unconstrained_mode() check because the
    /// generated block has already verified we're not in unconstrained mode at entry.
    #[inline(always)]
    pub fn read_mem_constrained(&mut self, addr: u32) -> u32 {
        self.track_chunk_split_address(addr);
        // No in_syscall check - this variant is for normal block execution only

        let (value, prev_chunk, prev_timestamp) =
            self.memory
                .read_and_update_metadata(addr, self.current_chunk, self.clk);

        let prev_record = MemoryRecord {
            value,
            chunk: prev_chunk,
            timestamp: prev_timestamp,
        };
        self.snapshot_addr_if_needed(addr, &prev_record);

        value
    }

    /// Read a word from memory in syscall mode (syscall path only).
    ///
    /// This variant skips the in_syscall() check and always accounts syscall memory events.
    #[inline(always)]
    pub fn read_mem_syscall(&mut self, addr: u32) -> u32 {
        self.track_chunk_split_address(addr);
        self.account_syscall_memory_access(addr);
        let is_unconstrained = self.is_unconstrained_mode();

        let (value, prev_chunk, prev_timestamp) = if is_unconstrained {
            self.memory
                .read_and_update_metadata_no_mark(addr, self.current_chunk, self.clk)
        } else {
            self.memory
                .read_and_update_metadata(addr, self.current_chunk, self.clk)
        };

        let prev_record = MemoryRecord {
            value,
            chunk: prev_chunk,
            timestamp: prev_timestamp,
        };

        if is_unconstrained {
            self.record_unconstrained_memory_access(addr, prev_record);
        }
        self.snapshot_addr_if_needed(addr, &prev_record);

        value
    }

    /// Write a word to memory in constrained mode (block-level unconstrained check already done).
    ///
    /// This variant skips the per-operation is_unconstrained_mode() check because the
    /// generated block has already verified we're not in unconstrained mode at entry.
    /// Always increments the memory RW event counter.
    #[inline(always)]
    pub fn write_mem_constrained(&mut self, addr: u32, value: u32) {
        self.track_chunk_split_address(addr);
        // Unconditionally increment - we know we're not in unconstrained mode or syscall
        self.chunk_split_state.num_memory_read_write_events += 1;

        let (prev_value, prev_chunk, prev_timestamp) =
            self.memory
                .write_and_capture_prev(addr, value, self.current_chunk, self.clk);

        let prev_record = MemoryRecord {
            value: prev_value,
            chunk: prev_chunk,
            timestamp: prev_timestamp,
        };
        self.snapshot_addr_if_needed(addr, &prev_record);
    }

    /// Write a word to memory in syscall mode (syscall path only).
    ///
    /// This variant skips the in_syscall() check and always accounts syscall memory events.
    #[inline(always)]
    pub fn write_mem_syscall(&mut self, addr: u32, value: u32) {
        self.track_chunk_split_address(addr);
        self.account_syscall_memory_access(addr);
        let is_unconstrained = self.is_unconstrained_mode();

        let (prev_value, prev_chunk, prev_timestamp) = if is_unconstrained {
            self.memory
                .write_and_capture_prev_no_mark(addr, value, self.current_chunk, self.clk)
        } else {
            self.memory
                .write_and_capture_prev(addr, value, self.current_chunk, self.clk)
        };

        let prev_record = MemoryRecord {
            value: prev_value,
            chunk: prev_chunk,
            timestamp: prev_timestamp,
        };

        if is_unconstrained {
            self.record_unconstrained_memory_access(addr, prev_record);
        }
        self.snapshot_addr_if_needed(addr, &prev_record);
    }

    /// Write a word to memory without incrementing event counter (for block-level batching).
    ///
    /// Event counting is deferred to block end via `add_memory_rw_events()`.
    /// Only use this when the block tracks static event counts.
    #[inline(always)]
    pub fn write_mem_no_count(&mut self, addr: u32, value: u32) {
        self.track_chunk_split_address(addr);
        // NO increment - deferred to block end

        let (prev_value, prev_chunk, prev_timestamp) =
            self.memory
                .write_and_capture_prev(addr, value, self.current_chunk, self.clk);

        let prev_record = MemoryRecord {
            value: prev_value,
            chunk: prev_chunk,
            timestamp: prev_timestamp,
        };
        self.snapshot_addr_if_needed(addr, &prev_record);
    }

    /// Read memory at a specific clock cycle (used by precompiles).
    ///
    /// Temporarily sets clk to the specified value, reads memory, then restores clk.
    /// This allows precompiles to read memory as it appeared at a different point in time.
    #[inline(always)]
    pub fn read_mem_fast_at_clk(&mut self, addr: u32, clk: u32) -> u32 {
        let prev_clk = self.clk;
        self.clk = clk;
        let value = self.read_mem_syscall(addr);
        self.clk = prev_clk;
        value
    }

    /// Write memory at a specific clock cycle (used by precompiles).
    ///
    /// Temporarily sets clk to the specified value, writes memory, then restores clk.
    /// This allows precompiles to write memory with metadata for a different point in time.
    #[inline(always)]
    pub fn write_mem_fast_at_clk(&mut self, addr: u32, value: u32, clk: u32) {
        let prev_clk = self.clk;
        self.clk = clk;
        self.write_mem_syscall(addr, value);
        self.clk = prev_clk;
    }

    /// Read a slice of memory words at a specific clock cycle.
    #[inline(always)]
    pub fn read_mem_slice_at_clk(&mut self, addr: u32, len: usize, clk: u32) -> Vec<u32> {
        let mut values = Vec::with_capacity(len);
        for i in 0..len {
            values.push(self.read_mem_fast_at_clk(addr + i as u32 * BYTES_PER_WORD, clk));
        }
        values
    }

    /// Write a slice of memory words at a specific clock cycle.
    #[inline(always)]
    pub fn write_mem_slice_at_clk(&mut self, addr: u32, values: &[u32], clk: u32) {
        for (i, &value) in values.iter().enumerate() {
            self.write_mem_fast_at_clk(addr + i as u32 * BYTES_PER_WORD, value, clk);
        }
    }

    // ========================================================================
    // Span Memory Operations
    // ========================================================================

    /// Read a span of memory words at a specific clock cycle into a preallocated buffer.
    #[inline]
    pub fn read_mem_span_at_clk(&mut self, addr: u32, out: &mut [u32], clk: u32) {
        for (i, slot) in out.iter_mut().enumerate() {
            let word_addr = addr + (i as u32) * BYTES_PER_WORD;
            *slot = self.read_mem_fast_at_clk(word_addr, clk);
        }
    }

    /// Write a span of memory words at a specific clock cycle from a buffer.
    #[inline]
    pub fn write_mem_span_at_clk(&mut self, addr: u32, values: &[u32], clk: u32) {
        for (i, &value) in values.iter().enumerate() {
            let word_addr = addr + (i as u32) * BYTES_PER_WORD;
            self.write_mem_fast_at_clk(word_addr, value, clk);
        }
    }

    /// Read a byte from memory (handles unaligned access).
    ///
    /// Extracts the appropriate byte from the word containing the address.
    #[inline(always)]
    pub fn read_byte(&mut self, addr: u32) -> u8 {
        let word_addr = addr & !(BYTES_PER_WORD - 1);
        let word = self.read_mem(word_addr);
        let byte_offset = (addr % BYTES_PER_WORD) as usize;
        ((word >> (byte_offset * 8)) & 0xff) as u8
    }

    /// Read a byte from memory without materialization or access tracking.
    #[inline(always)]
    pub fn read_byte_unsafe(&self, addr: u32) -> u8 {
        let word_addr = addr & !(BYTES_PER_WORD - 1);
        let word = self.read_mem_unsafe(word_addr);
        let byte_offset = (addr % BYTES_PER_WORD) as usize;
        ((word >> (byte_offset * 8)) & 0xff) as u8
    }
}
