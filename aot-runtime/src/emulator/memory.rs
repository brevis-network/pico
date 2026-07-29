use super::{constants::BYTES_PER_WORD, AotEmulatorCore};
use pico_vm::chips::chips::riscv_memory::event::MemoryRecord;

impl AotEmulatorCore {
    #[inline(always)]
    fn backing_word(value: u64) -> u32 {
        value as u32
    }

    #[inline(always)]
    pub(crate) fn dword_addr(addr: u64) -> u64 {
        addr & !7
    }

    #[inline(always)]
    fn word_shift(addr: u64) -> u32 {
        (((addr / u64::from(BYTES_PER_WORD)) % 2) * 32) as u32
    }

    // ========================================================================
    // Memory Operations
    // ========================================================================

    #[inline(always)]
    fn snapshot_addr_if_needed(&mut self, addr: u64, prev_record: &MemoryRecord) {
        if addr < 32 {
            let bit = 1u32 << (addr as u32);
            if (self.snapshot_registers_bitmap & bit) == 0 {
                self.snapshot_registers_bitmap |= bit;
            }
            return;
        }

        if !self.memory_snapshot.has_accessed(addr) {
            self.memory_snapshot.insert_u64(addr, *prev_record);
            // This is the single site that writes into `memory_snapshot`, so mark it dirty
            // here (first-touch slow path only) instead of relying on callers to do it.
            self.memory_snapshot_clean = false;
        }
    }

    #[inline(always)]
    pub(crate) fn capture_snapshot_for_hint(&mut self, addr: u64) {
        let zero_record = MemoryRecord {
            value: 0,
            chunk: 0,
            timestamp: 0,
        };
        self.snapshot_addr_if_needed(addr, &zero_record);
    }

    #[inline(always)]
    fn account_memory_access(&mut self, _addr: u64) {
        // NOTE: Simple-mode tracks unique addresses via chunk_split_state.memory_access_addrs.
        // AOT must mirror this to keep chunk boundary detection consistent.
        if self.in_syscall() {
            self.chunk_split_state.add_syscall_memory_events(1);
        } else {
            self.chunk_split_state.add_memory_rw_events(1);
        }
    }

    #[inline(always)]
    fn account_syscall_memory_access(&mut self, _addr: u64) {
        // NOTE: Simple-mode tracks unique addresses via chunk_split_state.memory_access_addrs.
        self.chunk_split_state.add_syscall_memory_events(1);
    }

    /// Internal helper for reading an aligned dword with metadata update.
    ///
    /// Handles unconstrained mode tracking, memory materialization, and access tracking.
    /// Both `read_mem` and `read_mem_fast` use this shared implementation.
    #[inline(always)]
    fn read_mem_dword_internal(&mut self, addr: u64) -> u64 {
        self.track_chunk_split_address(addr);
        // NOTE: Simple-mode tracks unique addresses via chunk_split_state.memory_access_addrs.
        // It still only increments num_memory_read_write_events on writes.
        // Syscall memory reads still need to track num_syscall_memory_events.
        if self.in_syscall() {
            self.chunk_split_state.add_syscall_memory_events(1);
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

    #[inline(always)]
    fn read_mem_dword_fast_internal(&mut self, addr: u64) -> u64 {
        self.read_mem_dword_internal(addr)
    }

    #[inline(always)]
    fn extract_word(dword: u64, addr: u64) -> u64 {
        (dword >> Self::word_shift(addr)) & 0xffff_ffff
    }

    #[inline(always)]
    fn insert_word(dword: u64, addr: u64, value: u64) -> u64 {
        let shift = Self::word_shift(addr);
        let mask = !(0xffff_ffff_u64 << shift);
        (dword & mask) | ((value & 0xffff_ffff) << shift)
    }

    /// Read a word from memory (aligned to 4-byte boundary).
    #[inline(always)]
    pub fn read_mem_word(&mut self, addr: u64) -> u64 {
        Self::extract_word(self.read_mem_dword_internal(Self::dword_addr(addr)), addr)
    }

    /// Read a word from memory without memory-record bookkeeping.
    #[inline(always)]
    pub fn read_mem_word_fast(&mut self, addr: u64) -> u64 {
        Self::extract_word(
            self.read_mem_dword_fast_internal(Self::dword_addr(addr)),
            addr,
        )
    }

    /// Read a word from memory without materialization or access tracking.
    #[inline(always)]
    pub fn read_mem_word_unsafe(&self, addr: u64) -> u64 {
        Self::extract_word(self.read_mem_dword_unsafe(Self::dword_addr(addr)), addr)
    }

    /// Read a dword from memory without materialization or access tracking.
    #[inline(always)]
    pub fn read_mem_dword_unsafe(&self, addr: u64) -> u64 {
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
    pub fn read_mem_word_snapshot(&mut self, addr: u64) -> u64 {
        Self::extract_word(self.read_mem_dword_snapshot(Self::dword_addr(addr)), addr)
    }

    /// Read a dword from memory for snapshot compatibility without updating metadata.
    #[inline(always)]
    pub fn read_mem_dword_snapshot(&mut self, addr: u64) -> u64 {
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
        self.read_mem_word_span_snapshot(u64::from(addr), out);
    }

    /// Read a span of 4-byte logical words for snapshot compatibility without updating metadata.
    #[inline(always)]
    pub fn read_mem_word_span_snapshot(&mut self, addr: u64, out: &mut [u32]) {
        for (i, slot) in out.iter_mut().enumerate() {
            let word_addr = addr + (i as u64) * u64::from(BYTES_PER_WORD);
            *slot = Self::backing_word(self.read_mem_word_snapshot(word_addr));
        }
    }

    /// Read a span of 4-byte logical words without snapshotting or updating metadata.
    #[inline(always)]
    pub fn read_mem_word_span_unsafe(&self, addr: u64, out: &mut [u32]) {
        for (i, slot) in out.iter_mut().enumerate() {
            let word_addr = addr + (i as u64) * u64::from(BYTES_PER_WORD);
            *slot = Self::backing_word(self.read_mem_word_unsafe(word_addr));
        }
    }

    /// Read a span of aligned dwords for snapshot compatibility without updating metadata.
    #[inline(always)]
    pub fn read_mem_dword_span_snapshot(&mut self, addr: u64, out: &mut [u64]) {
        for (i, slot) in out.iter_mut().enumerate() {
            let dword_addr = addr + (i as u64) * 8;
            *slot = self.read_mem_dword_snapshot(dword_addr);
        }
    }

    /// Read a span of aligned dwords without snapshotting or updating metadata.
    #[inline(always)]
    pub fn read_mem_dword_span_unsafe(&self, addr: u64, out: &mut [u64]) {
        for (i, slot) in out.iter_mut().enumerate() {
            let dword_addr = addr + (i as u64) * 8;
            *slot = self.read_mem_dword_unsafe(dword_addr);
        }
    }

    /// Read low 32-bit values stored in 8-byte RV64 slots for snapshot compatibility.
    #[inline(always)]
    pub fn read_mem_low32_slot_span_snapshot(&mut self, addr: u64, out: &mut [u32]) {
        for (i, slot) in out.iter_mut().enumerate() {
            let slot_addr = addr + (i as u64) * 8;
            *slot = Self::backing_word(self.read_mem_dword_snapshot(slot_addr));
        }
    }

    /// Internal helper for writing an aligned dword with metadata update.
    ///
    /// Handles unconstrained mode tracking, memory updates, and access tracking.
    /// Both `write_mem` and `write_mem_fast` use this shared implementation.
    #[inline(always)]
    fn write_mem_dword_internal(&mut self, addr: u64, value: u64) {
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

    #[inline(always)]
    fn write_mem_dword_fast_internal(&mut self, addr: u64, value: u64) {
        self.write_mem_dword_internal(addr, value)
    }

    /// Write a word to memory (aligned to 4-byte boundary).
    #[inline(always)]
    pub fn write_mem_word(&mut self, addr: u64, value: u64) {
        let dword_addr = Self::dword_addr(addr);
        let current = self.read_mem_dword_internal(dword_addr);
        self.write_mem_dword_internal(dword_addr, Self::insert_word(current, addr, value));
    }

    /// Write a word to memory without memory-record bookkeeping.
    #[inline(always)]
    pub fn write_mem_word_fast(&mut self, addr: u64, value: u64) {
        let dword_addr = Self::dword_addr(addr);
        let current = self.read_mem_dword_fast_internal(dword_addr);
        self.write_mem_dword_fast_internal(dword_addr, Self::insert_word(current, addr, value));
    }

    /// Read a word from memory in constrained mode (block-level unconstrained check already done).
    ///
    /// This variant skips the per-operation is_unconstrained_mode() check because the
    /// generated block has already verified we're not in unconstrained mode at entry.
    #[inline(always)]
    pub fn read_mem_word_constrained(&mut self, addr: u64) -> u64 {
        Self::extract_word(
            self.read_mem_dword_constrained_impl(Self::dword_addr(addr)),
            addr,
        )
    }

    /// Read a word from memory in syscall mode (syscall path only).
    ///
    /// This variant skips the in_syscall() check and always accounts syscall memory events.
    #[inline(always)]
    pub fn read_mem_word_syscall(&mut self, addr: u64) -> u64 {
        Self::extract_word(
            self.read_mem_dword_syscall_impl(Self::dword_addr(addr)),
            addr,
        )
    }

    /// Read an aligned dword from memory in constrained mode.
    #[inline(always)]
    fn read_mem_dword_constrained_impl(&mut self, addr: u64) -> u64 {
        self.track_chunk_split_address(addr);
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

    /// Read an aligned dword from memory in syscall mode.
    #[inline(always)]
    fn read_mem_dword_syscall_impl(&mut self, addr: u64) -> u64 {
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
    ///
    /// Fused read-modify-write: a 32-bit store into a 64-bit dword slot needs the current dword
    /// to merge the word in. The previous two-step path (`read_mem_dword_constrained_impl` then
    /// `write_mem_dword_constrained`) ran the per-access bookkeeping TWICE for the same dword —
    /// `track_chunk_split_address`, `snapshot_addr_if_needed`, the metadata update and the
    /// accessed-bit mark were all duplicated. Fuse them so each runs once. Semantics are identical:
    /// same final value+metadata; same snapshot pre-state (the read half never mutated the value);
    /// same event counts (the read half added no memory_rw_event, and the second `track_address`
    /// was a no-op once the dword's bit was already set).
    #[inline(always)]
    pub fn write_mem_word_constrained(&mut self, addr: u64, value: u64) {
        let dword_addr = Self::dword_addr(addr);
        self.track_chunk_split_address(dword_addr);
        self.chunk_split_state.add_memory_rw_events(1);
        // Pre-write dword (used both to merge in the 32-bit word and as the snapshot pre-value).
        let current = self.memory.peek_dword(dword_addr);
        let merged = Self::insert_word(current, addr, value);
        let (_prev_value, prev_chunk, prev_timestamp) =
            self.memory
                .write_and_capture_prev(dword_addr, merged, self.current_chunk, self.clk);
        let prev_record = MemoryRecord {
            value: current,
            chunk: prev_chunk,
            timestamp: prev_timestamp,
        };
        self.snapshot_addr_if_needed(dword_addr, &prev_record);
    }

    /// Write a word to memory in syscall mode (syscall path only).
    ///
    /// This variant skips the in_syscall() check and always accounts syscall memory events.
    #[inline(always)]
    pub fn write_mem_word_syscall(&mut self, addr: u64, value: u64) {
        let dword_addr = Self::dword_addr(addr);
        let current = self.read_mem_dword_unsafe(dword_addr);
        self.write_mem_dword_syscall(dword_addr, Self::insert_word(current, addr, value));
    }

    /// Write a word to memory without incrementing event counter (for block-level batching).
    ///
    /// Event counting is deferred to block end via `add_memory_rw_events()`.
    /// Only use this when the block tracks static event counts.
    #[inline(always)]
    pub fn write_mem_word_no_count(&mut self, addr: u64, value: u64) {
        let dword_addr = Self::dword_addr(addr);
        let current = self.read_mem_dword_constrained_impl(dword_addr);
        self.write_mem_dword_no_count(dword_addr, Self::insert_word(current, addr, value));
    }

    #[inline(always)]
    pub(crate) fn byte_shift(addr: u64) -> u32 {
        ((addr % 8) * 8) as u32
    }

    #[inline(always)]
    pub(crate) fn read_u8_from_word(word: u64, addr: u64) -> u8 {
        ((word >> Self::byte_shift(addr)) & 0xff) as u8
    }

    #[inline(always)]
    pub(crate) fn read_u16_from_word(word: u64, addr: u64) -> u16 {
        ((word >> (((addr >> 1) % 4) * 16)) & 0xffff) as u16
    }

    #[inline(always)]
    pub(crate) fn write_u8_into_word(word: u64, addr: u64, value: u64) -> u64 {
        let shift = Self::byte_shift(addr);
        let mask = !(0xff_u64 << shift);
        (word & mask) | ((value & 0xff) << shift)
    }

    #[inline(always)]
    pub(crate) fn write_u16_into_word(word: u64, addr: u64, value: u64) -> u64 {
        let shift = ((addr >> 1) % 4) * 16;
        let mask = !(0xffff_u64 << shift);
        (word & mask) | ((value & 0xffff) << shift)
    }

    #[inline(always)]
    pub fn read_mem_dword(&mut self, addr: u64) -> u64 {
        self.read_mem_dword_internal(addr)
    }

    #[inline(always)]
    pub fn read_mem_dword_constrained(&mut self, addr: u64) -> u64 {
        self.read_mem_dword_constrained_impl(addr)
    }

    #[inline(always)]
    pub fn read_mem_dword_syscall(&mut self, addr: u64) -> u64 {
        self.read_mem_dword_syscall_impl(addr)
    }

    #[inline(always)]
    pub fn write_mem_dword(&mut self, addr: u64, value: u64) {
        self.write_mem_dword_internal(addr, value);
    }

    #[inline(always)]
    pub fn write_mem_dword_constrained(&mut self, addr: u64, value: u64) {
        self.track_chunk_split_address(addr);
        self.chunk_split_state.add_memory_rw_events(1);
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

    #[inline(always)]
    pub fn write_mem_dword_syscall(&mut self, addr: u64, value: u64) {
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

    #[inline(always)]
    pub fn write_mem_dword_no_count(&mut self, addr: u64, value: u64) {
        self.track_chunk_split_address(addr);
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

    #[inline(always)]
    pub fn read_mem(&mut self, addr: u32) -> u32 {
        Self::backing_word(self.read_mem_word(u64::from(addr)))
    }

    #[inline(always)]
    pub fn read_mem_fast(&mut self, addr: u32) -> u32 {
        Self::backing_word(self.read_mem_word_fast(u64::from(addr)))
    }

    #[inline(always)]
    pub fn read_mem_unsafe(&self, addr: u32) -> u32 {
        Self::backing_word(self.read_mem_word_unsafe(u64::from(addr)))
    }

    #[inline(always)]
    pub fn read_mem_snapshot(&mut self, addr: u32) -> u32 {
        Self::backing_word(self.read_mem_word_snapshot(u64::from(addr)))
    }

    #[inline(always)]
    pub fn write_mem(&mut self, addr: u32, value: u32) {
        self.write_mem_word(u64::from(addr), u64::from(value))
    }

    #[inline(always)]
    pub fn write_mem_fast(&mut self, addr: u32, value: u32) {
        self.write_mem_word_fast(u64::from(addr), u64::from(value))
    }

    #[inline(always)]
    pub fn read_mem_constrained(&mut self, addr: u32) -> u32 {
        Self::backing_word(self.read_mem_word_constrained(u64::from(addr)))
    }

    #[inline(always)]
    pub fn read_mem_syscall(&mut self, addr: u32) -> u32 {
        Self::backing_word(self.read_mem_word_syscall(u64::from(addr)))
    }

    #[inline(always)]
    pub fn write_mem_constrained(&mut self, addr: u32, value: u32) {
        self.write_mem_word_constrained(u64::from(addr), u64::from(value))
    }

    #[inline(always)]
    pub fn write_mem_syscall(&mut self, addr: u32, value: u32) {
        self.write_mem_word_syscall(u64::from(addr), u64::from(value))
    }

    #[inline(always)]
    pub fn write_mem_no_count(&mut self, addr: u32, value: u32) {
        self.write_mem_word_no_count(u64::from(addr), u64::from(value))
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
        self.read_mem_word_slice_at_clk(u64::from(addr), len, clk)
    }

    /// Read a slice of 4-byte logical words at a specific clock cycle.
    #[inline(always)]
    pub fn read_mem_word_slice_at_clk(&mut self, addr: u64, len: usize, clk: u32) -> Vec<u32> {
        let mut values = Vec::with_capacity(len);
        for i in 0..len {
            let word_addr = addr + (i as u64) * u64::from(BYTES_PER_WORD);
            values.push(Self::backing_word(
                self.read_mem_word_at_clk(word_addr, clk),
            ));
        }
        values
    }

    /// Write a slice of memory words at a specific clock cycle.
    #[inline(always)]
    pub fn write_mem_slice_at_clk(&mut self, addr: u32, values: &[u32], clk: u32) {
        self.write_mem_word_slice_at_clk(u64::from(addr), values, clk);
    }

    /// Write a slice of 4-byte logical words at a specific clock cycle.
    #[inline(always)]
    pub fn write_mem_word_slice_at_clk(&mut self, addr: u64, values: &[u32], clk: u32) {
        for (i, &value) in values.iter().enumerate() {
            let word_addr = addr + (i as u64) * u64::from(BYTES_PER_WORD);
            self.write_mem_word_at_clk(word_addr, u64::from(value), clk);
        }
    }

    // ========================================================================
    // Span Memory Operations
    // ========================================================================

    /// Read a span of memory words at a specific clock cycle into a preallocated buffer.
    #[inline]
    pub fn read_mem_span_at_clk(&mut self, addr: u32, out: &mut [u32], clk: u32) {
        self.read_mem_word_span_at_clk(u64::from(addr), out, clk);
    }

    /// Read a span of 4-byte logical words at a specific clock cycle into a preallocated buffer.
    #[inline]
    pub fn read_mem_word_span_at_clk(&mut self, addr: u64, out: &mut [u32], clk: u32) {
        for (i, slot) in out.iter_mut().enumerate() {
            let word_addr = addr + (i as u64) * u64::from(BYTES_PER_WORD);
            *slot = Self::backing_word(self.read_mem_word_at_clk(word_addr, clk));
        }
    }

    /// Write a span of memory words at a specific clock cycle from a buffer.
    #[inline]
    pub fn write_mem_span_at_clk(&mut self, addr: u32, values: &[u32], clk: u32) {
        self.write_mem_word_span_at_clk(u64::from(addr), values, clk);
    }

    /// Write a span of 4-byte logical words at a specific clock cycle from a buffer.
    #[inline]
    pub fn write_mem_word_span_at_clk(&mut self, addr: u64, values: &[u32], clk: u32) {
        for (i, &value) in values.iter().enumerate() {
            let word_addr = addr + (i as u64) * u64::from(BYTES_PER_WORD);
            self.write_mem_word_at_clk(word_addr, u64::from(value), clk);
        }
    }

    /// Read a span of 8-byte dwords at a specific clock cycle into a preallocated buffer.
    #[inline]
    pub fn read_mem_dword_span_at_clk(&mut self, addr: u64, out: &mut [u64], clk: u32) {
        for (i, slot) in out.iter_mut().enumerate() {
            let dword_addr = addr + (i as u64) * 8;
            *slot = self.read_mem_dword_value_at_clk(dword_addr, clk);
        }
    }

    /// Write a span of 8-byte dwords at a specific clock cycle from a buffer.
    #[inline]
    pub fn write_mem_dword_span_at_clk(&mut self, addr: u64, values: &[u64], clk: u32) {
        for (i, &value) in values.iter().enumerate() {
            let dword_addr = addr + (i as u64) * 8;
            self.write_mem_dword_value_at_clk(dword_addr, value, clk);
        }
    }

    /// Read low 32-bit values stored in 8-byte RV64 slots at a specific clock cycle.
    #[inline]
    pub fn read_mem_low32_slot_span_at_clk(&mut self, addr: u64, out: &mut [u32], clk: u32) {
        for (i, slot) in out.iter_mut().enumerate() {
            let slot_addr = addr + (i as u64) * 8;
            *slot = self.read_mem_low32_slot_at_clk(slot_addr, clk);
        }
    }

    /// Write low 32-bit values into 8-byte RV64 slots at a specific clock cycle.
    #[inline]
    pub fn write_mem_low32_slot_span_at_clk(&mut self, addr: u64, values: &[u32], clk: u32) {
        for (i, &value) in values.iter().enumerate() {
            let slot_addr = addr + (i as u64) * 8;
            self.write_mem_low32_slot_at_clk(slot_addr, value, clk);
        }
    }

    #[inline(always)]
    pub fn read_mem_low32_slot_at_clk(&mut self, addr: u64, clk: u32) -> u32 {
        Self::backing_word(self.read_mem_dword_value_at_clk(addr, clk))
    }

    #[inline(always)]
    pub fn write_mem_low32_slot_at_clk(&mut self, addr: u64, value: u32, clk: u32) {
        self.write_mem_dword_value_at_clk(addr, u64::from(value), clk);
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

    #[inline(always)]
    fn read_mem_word_at_clk(&mut self, addr: u64, clk: u32) -> u64 {
        let prev_clk = self.clk;
        self.clk = clk;
        let value = self.read_mem_word_syscall(addr);
        self.clk = prev_clk;
        value
    }

    #[inline(always)]
    fn write_mem_word_at_clk(&mut self, addr: u64, value: u64, clk: u32) {
        let prev_clk = self.clk;
        self.clk = clk;
        self.write_mem_word_syscall(addr, value);
        self.clk = prev_clk;
    }

    #[inline(always)]
    fn read_mem_dword_value_at_clk(&mut self, addr: u64, clk: u32) -> u64 {
        let prev_clk = self.clk;
        self.clk = clk;
        let value = self.read_mem_dword_syscall(addr);
        self.clk = prev_clk;
        value
    }

    #[inline(always)]
    fn write_mem_dword_value_at_clk(&mut self, addr: u64, value: u64, clk: u32) {
        let prev_clk = self.clk;
        self.clk = clk;
        self.write_mem_dword_syscall(addr, value);
        self.clk = prev_clk;
    }
}

#[cfg(test)]
mod tests {
    use super::AotEmulatorCore;
    use pico_vm::compiler::riscv::program::Program;
    use std::{collections::BTreeMap, sync::Arc};

    fn test_program() -> Arc<Program> {
        let mut program = Program::new(Vec::new(), 0x1000, 0x1000);
        program.memory_image = Arc::new(BTreeMap::new());
        Arc::new(program)
    }

    #[test]
    fn phase5_low32_slot_helpers_use_eight_byte_spacing() {
        let mut emu = AotEmulatorCore::new(test_program(), Vec::new());

        emu.write_mem_low32_slot_span_at_clk(0x100, &[0x1122_3344, 0x5566_7788], 0);

        let mut slots = [0u32; 2];
        emu.read_mem_low32_slot_span_snapshot(0x100, &mut slots);

        assert_eq!(slots, [0x1122_3344, 0x5566_7788]);
        assert_eq!(emu.memory.get(0x100).value, 0x1122_3344);
        assert_eq!(emu.memory.get(0x108).value, 0x5566_7788);
    }

    #[test]
    fn phase5_contiguous_word_span_read_reuses_single_backing_dword() {
        let mut emu = AotEmulatorCore::new(test_program(), Vec::new());
        emu.write_mem_dword(0x100, 0x5566_7788_1122_3344);

        let mut words = [0u32; 2];
        emu.read_mem_word_span_at_clk(0x100, &mut words, 7);

        assert_eq!(words, [0x1122_3344, 0x5566_7788]);
    }

    #[test]
    fn phase5_contiguous_word_span_write_reuses_single_backing_dword() {
        let mut emu = AotEmulatorCore::new(test_program(), Vec::new());
        emu.write_mem_dword(0x100, 0);

        emu.write_mem_word_span_at_clk(0x100, &[0x1122_3344, 0x5566_7788], 9);

        assert_eq!(emu.memory.get(0x100).value, 0x5566_7788_1122_3344);
    }

    #[test]
    fn syscall_word_write_counts_one_chunk_split_event_per_logical_word() {
        let mut emu = AotEmulatorCore::new(test_program(), Vec::new());
        emu.write_mem_dword(0x100, 0);
        emu.enter_syscall();

        emu.write_mem_word_syscall(0x104, 0x1122_3344);

        assert_eq!(emu.chunk_split_state.num_syscall_memory_events, 1);
    }

    #[test]
    fn syscall_word_span_counts_one_event_per_logical_word() {
        let mut emu = AotEmulatorCore::new(test_program(), Vec::new());
        emu.write_mem_dword(0x100, 0);
        emu.enter_syscall();

        let mut words = [0u32; 2];
        emu.read_mem_word_span_at_clk(0x100, &mut words, 7);
        assert_eq!(emu.chunk_split_state.num_syscall_memory_events, 2);

        emu.chunk_split_state.clear();
        emu.write_mem_word_span_at_clk(0x100, &[0x1122_3344, 0x5566_7788], 9);
        assert_eq!(emu.chunk_split_state.num_syscall_memory_events, 2);
    }
}
