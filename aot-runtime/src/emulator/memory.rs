use super::{
    constants::BYTES_PER_WORD,
    sink::{by_sink, LentSink},
    state::Touch,
    AotEmulatorCore,
};
use pico_vm::{
    chips::chips::riscv_memory::event::MemoryRecord,
    compiler::riscv::opcode::Opcode,
    emulator::riscv::riscv_emulator::util::{dword_bytes, splice_dword, straddling_bytes},
};

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
    fn snapshot_addr_if_needed(&mut self, addr: u64, prev_record: &MemoryRecord, touch: Touch) {
        // A register's prestate is the batch-start register file, restored by
        // `restore_touched_snapshot_registers`; `memory_snapshot` holds memory cells only. Only
        // the snapshot thread reads the tracker, and only it clears it: a replay worker, re-armed
        // for batch after batch, would come to hold every page the run touched.
        if addr < 32 || self.is_replay_worker() {
            return;
        }

        if !self.memory_snapshot.has_accessed(addr) {
            self.memory_snapshot.insert_u64(addr, *prev_record);
            // This is the single site that writes into `memory_snapshot`, so mark it dirty
            // here (first-touch slow path only) instead of relying on callers to do it.
            self.memory_snapshot_clean = false;
            let counts = &mut self.snapshot_counts;
            match touch {
                Touch::Load => counts.first_touch_loads += 1,
                Touch::PartialStore => counts.first_touch_partial_stores += 1,
                Touch::FullStore => counts.first_touch_full_stores += 1,
            }
        }
    }

    #[inline(always)]
    pub(crate) fn capture_snapshot_for_hint(&mut self, addr: u64) {
        let zero_record = MemoryRecord {
            value: 0,
            chunk: 0,
            timestamp: 0,
        };
        self.snapshot_addr_if_needed(addr, &zero_record, Touch::FullStore);
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
    /// Handles unconstrained mode tracking, memory materialization, and access tracking. `touch`
    /// is [`Touch::PartialStore`] when the read is the first half of a store narrower than the
    /// dword.
    #[inline(always)]
    fn read_mem_dword_internal(&mut self, addr: u64, touch: Touch) -> u64 {
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
        self.snapshot_addr_if_needed(addr, &prev_record, touch);
        self.emit_mem_read(addr, value, prev_record);

        value
    }

    #[inline(always)]
    pub(crate) fn extract_word(dword: u64, addr: u64) -> u64 {
        (dword >> Self::word_shift(addr)) & 0xffff_ffff
    }

    #[inline(always)]
    pub(crate) fn insert_word(dword: u64, addr: u64, value: u64) -> u64 {
        let shift = Self::word_shift(addr);
        let mask = !(0xffff_ffff_u64 << shift);
        (dword & mask) | ((value & 0xffff_ffff) << shift)
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

    /// Read a dword from memory for snapshot compatibility without updating metadata.
    #[inline(always)]
    pub fn read_mem_dword_snapshot(&mut self, addr: u64) -> u64 {
        let record = self.memory.get(addr);
        self.snapshot_addr_if_needed(addr, &record, Touch::Load);
        if record.value != 0 || record.chunk != 0 || record.timestamp != 0 {
            record.value
        } else if let Some(&value) = self.uninitialized_memory.get(addr) {
            value
        } else {
            0
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
        self.snapshot_addr_if_needed(addr, &prev_record, Touch::FullStore);
        self.emit_mem_write(addr, value, prev_record);
    }

    /// [`Self::write_mem_dword_merged_no_count`] for the fallback interpreter: counted, and inside
    /// unconstrained mode kept for the rollback.
    #[inline(always)]
    pub(crate) fn write_mem_dword_merged(
        &mut self,
        addr: u64,
        merge: impl FnOnce(u64) -> u64,
    ) -> u64 {
        self.track_chunk_split_address(addr);
        self.account_memory_access(addr);
        let current = self.memory.peek_dword(addr);
        let value = merge(current);
        let is_unconstrained = self.is_unconstrained_mode();
        let (_, prev_chunk, prev_timestamp) = if is_unconstrained {
            self.memory
                .write_and_capture_prev_no_mark(addr, value, self.current_chunk, self.clk)
        } else {
            self.memory
                .write_and_capture_prev(addr, value, self.current_chunk, self.clk)
        };
        let prev_record = MemoryRecord {
            value: current,
            chunk: prev_chunk,
            timestamp: prev_timestamp,
        };
        if is_unconstrained {
            self.record_unconstrained_memory_access(addr, prev_record);
        }
        self.snapshot_addr_if_needed(addr, &prev_record, Touch::PartialStore);
        self.emit_mem_write(addr, value, prev_record);
        value
    }

    /// Write a word to memory (aligned to 4-byte boundary).
    #[inline(always)]
    pub fn write_mem_word(&mut self, addr: u64, value: u64) {
        let dword_addr = Self::dword_addr(addr);
        let current = self.read_mem_dword_internal(dword_addr, Touch::PartialStore);
        self.write_mem_dword_internal(dword_addr, Self::insert_word(current, addr, value));
    }

    /// Read a word from memory in syscall mode (syscall path only).
    ///
    /// This variant skips the in_syscall() check and always accounts syscall memory events.
    #[inline(always)]
    pub fn read_mem_word_syscall(&mut self, addr: u64) -> u64 {
        if !self.syscall_access_allowed(addr, 4, false) {
            return 0;
        }
        Self::extract_word(
            self.read_mem_dword_syscall_impl(Self::dword_addr(addr)),
            addr,
        )
    }

    /// Read an aligned dword from memory in constrained mode, the access written into `sink` when
    /// `EMIT`.
    #[inline(always)]
    pub(crate) fn read_mem_dword_constrained_impl<const EMIT: bool>(
        &mut self,
        sink: LentSink<'_>,
        addr: u64,
        touch: Touch,
    ) -> u64 {
        self.track_chunk_split_address(addr);
        let (value, prev_chunk, prev_timestamp) =
            self.memory
                .read_and_update_metadata(addr, self.current_chunk, self.clk);
        let prev_record = MemoryRecord {
            value,
            chunk: prev_chunk,
            timestamp: prev_timestamp,
        };
        self.snapshot_addr_if_needed(addr, &prev_record, touch);
        if EMIT {
            self.record_mem_read(sink, addr, value, prev_record);
        }
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
        self.snapshot_addr_if_needed(addr, &prev_record, Touch::Load);
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
        self.chunk_split_state.add_memory_rw_events(1);
        self.write_mem_word_no_count(addr, value);
    }

    /// Write a word to memory in syscall mode (syscall path only).
    ///
    /// This variant skips the in_syscall() check and always accounts syscall memory events.
    #[inline(always)]
    pub fn write_mem_word_syscall(&mut self, addr: u64, value: u64) {
        if !self.syscall_access_allowed(addr, 4, true) {
            return;
        }
        let dword_addr = Self::dword_addr(addr);
        let current = self.read_mem_dword_unsafe(dword_addr);
        self.write_mem_dword_syscall_impl(
            dword_addr,
            Self::insert_word(current, addr, value),
            Touch::PartialStore,
        );
    }

    /// Write a word to memory without incrementing event counter (for block-level batching), and
    /// return the dword written.
    ///
    /// Event counting is deferred to block end via `add_memory_rw_events()`.
    /// Only use this when the block tracks static event counts.
    #[inline(always)]
    pub fn write_mem_word_no_count(&mut self, addr: u64, value: u64) -> u64 {
        by_sink!(self.write_mem_word_no_count_impl(addr, value))
    }

    /// [`Self::write_mem_word_no_count`], the access written into `sink` when `EMIT`.
    #[inline(always)]
    pub(crate) fn write_mem_word_no_count_impl<const EMIT: bool>(
        &mut self,
        sink: LentSink<'_>,
        addr: u64,
        value: u64,
    ) -> u64 {
        self.write_mem_dword_merged_no_count::<EMIT>(sink, Self::dword_addr(addr), |current| {
            Self::insert_word(current, addr, value)
        })
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
        self.read_mem_dword_internal(addr, Touch::Load)
    }

    /// [`Self::read_mem_dword`] as the first half of a byte or halfword store, which writes the
    /// dword back with the bytes it does not store kept.
    #[inline(always)]
    pub fn read_mem_dword_for_store(&mut self, addr: u64) -> u64 {
        self.read_mem_dword_internal(addr, Touch::PartialStore)
    }

    #[inline(always)]
    pub fn read_mem_dword_syscall(&mut self, addr: u64) -> u64 {
        if !self.syscall_access_allowed(addr, 8, false) {
            return 0;
        }
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
        self.snapshot_addr_if_needed(addr, &prev_record, Touch::FullStore);
        self.emit_mem_write(addr, value, prev_record);
    }

    #[inline(always)]
    pub fn write_mem_dword_syscall(&mut self, addr: u64, value: u64) {
        if !self.syscall_access_allowed(addr, 8, true) {
            return;
        }
        self.write_mem_dword_syscall_impl(addr, value, Touch::FullStore);
    }

    #[inline(always)]
    fn write_mem_dword_syscall_impl(&mut self, addr: u64, value: u64, touch: Touch) {
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
        self.snapshot_addr_if_needed(addr, &prev_record, touch);
    }

    #[inline(always)]
    pub fn write_mem_dword_no_count(&mut self, addr: u64, value: u64) {
        by_sink!(self.write_mem_dword_no_count_impl(addr, value));
    }

    /// [`Self::write_mem_dword_no_count`], the access written into `sink` when `EMIT`.
    #[inline(always)]
    pub(crate) fn write_mem_dword_no_count_impl<const EMIT: bool>(
        &mut self,
        sink: LentSink<'_>,
        addr: u64,
        value: u64,
    ) {
        self.track_chunk_split_address(addr);
        let (prev_value, prev_chunk, prev_timestamp) =
            self.memory
                .write_and_capture_prev(addr, value, self.current_chunk, self.clk);
        let prev_record = MemoryRecord {
            value: prev_value,
            chunk: prev_chunk,
            timestamp: prev_timestamp,
        };
        self.snapshot_addr_if_needed(addr, &prev_record, Touch::FullStore);
        if EMIT {
            self.record_mem_write(sink, addr, value, prev_record);
        }
    }

    /// Stores into part of the dword at `addr`, `merge` turning the dword into what is written,
    /// and returns that. The dword is read without an access of its own and written once: the
    /// interpreter's one write access, whose record carries the dword's state before the store,
    /// written into `sink` when `EMIT`.
    #[inline(always)]
    pub(crate) fn write_mem_dword_merged_no_count<const EMIT: bool>(
        &mut self,
        sink: LentSink<'_>,
        addr: u64,
        merge: impl FnOnce(u64) -> u64,
    ) -> u64 {
        self.track_chunk_split_address(addr);
        let current = self.memory.peek_dword(addr);
        let value = merge(current);
        let (_, prev_chunk, prev_timestamp) =
            self.memory
                .write_and_capture_prev(addr, value, self.current_chunk, self.clk);
        let prev_record = MemoryRecord {
            value: current,
            chunk: prev_chunk,
            timestamp: prev_timestamp,
        };
        self.snapshot_addr_if_needed(addr, &prev_record, Touch::PartialStore);
        if EMIT {
            self.record_mem_write(sink, addr, value, prev_record);
        }
        value
    }

    // ========================================================================
    // Misaligned Accesses (Zicclsm)
    // ========================================================================
    //
    // A load or store whose address is not a multiple of its width reads or writes the dword at
    // the aligned address, as an aligned one does, and, when it runs into the next dword, that one
    // too, at the C position (`clk + 1`), which a load or a store leaves free: the interpreter's
    // `RiscvEmulator::loaded` and `stored`. The aligned dword's access is the instruction's memory
    // access; the next dword's is written as a local memory event and the step's next-dword
    // access, which fills no slot (`ExecutionSink::next_dword`), into the sink the instruction
    // writes into: lent to a compiled block's emitting body, the core's for the fallback (through
    // `by_sink!`). The `_no_count` pair is the compiled blocks', which run in constrained mode
    // only and count the instruction's own write at the block's end; the other pair is the
    // fallback interpreter's, counted as it goes and kept for the rollback in unconstrained mode.
    // The next dword's write is counted where it happens in both, as the interpreter counts it; a
    // block's static counts assume aligned accesses, and its loads and stores bound what these
    // add (`chunk_split::can_fit_block`).

    /// Counts a misaligned access, as the interpreter does, for the run and for the chunk
    /// split: the `MemoryUnaligned` chip proves it, and its height caps how many a chunk holds. An
    /// unconstrained block's accesses are not proven, so they are not counted.
    #[cold]
    pub(crate) fn misaligned(&mut self, _opcode: Opcode, _addr: u64) -> Result<(), String> {
        if !self.is_unconstrained_mode() {
            self.misaligned_accesses += 1;
            self.chunk_split_state.num_misaligned += 1;
        }
        Ok(())
    }

    /// A misaligned load at `addr` in a compiled block: the `width` bytes it reads, in the low
    /// bytes, and the aligned dword, the instruction's memory access, its accesses written into
    /// `sink` when `EMIT`.
    #[cold]
    pub(crate) fn misaligned_load_no_count<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        opcode: Opcode,
        addr: u64,
        width: u64,
    ) -> Result<(u64, u64), String> {
        self.misaligned(opcode, addr)?;
        let dword = self.read_mem_dword_constrained_impl::<EMIT>(
            sink.as_deref_mut(),
            Self::dword_addr(addr),
            Touch::Load,
        );
        Ok((
            self.misaligned_bytes::<EMIT>(sink, dword, addr, width),
            dword,
        ))
    }

    /// [`Self::misaligned_load_no_count`] for the fallback interpreter.
    #[cold]
    pub(crate) fn misaligned_load(
        &mut self,
        opcode: Opcode,
        addr: u64,
        width: u64,
    ) -> Result<(u64, u64), String> {
        self.misaligned(opcode, addr)?;
        let dword = self.read_mem_dword(Self::dword_addr(addr));
        let bytes = by_sink!(self.misaligned_bytes(dword, addr, width));
        Ok((bytes, dword))
    }

    /// The `width` bytes at `addr`, `dword` being the dword at the aligned address: the next dword
    /// is read too when they run into it, its access written into `sink` when `EMIT`.
    fn misaligned_bytes<const EMIT: bool>(
        &mut self,
        sink: LentSink<'_>,
        dword: u64,
        addr: u64,
        width: u64,
    ) -> u64 {
        let offset = addr % 8;
        if offset + width <= 8 {
            return dword_bytes(dword, offset, width);
        }
        let next = self.read_next_dword::<EMIT>(sink, Self::dword_addr(addr) + 8);
        straddling_bytes(dword, next, offset, width)
    }

    /// Writes the low `width` bytes of `value` at a misaligned `addr` in a compiled block, and
    /// returns what the aligned dword, the instruction's memory access, holds after it, its
    /// accesses written into `sink` when `EMIT`.
    #[cold]
    pub(crate) fn misaligned_store_no_count<const EMIT: bool>(
        &mut self,
        mut sink: LentSink<'_>,
        opcode: Opcode,
        addr: u64,
        value: u64,
        width: u64,
    ) -> Result<u64, String> {
        self.misaligned(opcode, addr)?;
        let (offset, low) = Self::misaligned_split(addr, width);
        let dword = self.write_mem_dword_merged_no_count::<EMIT>(
            sink.as_deref_mut(),
            Self::dword_addr(addr),
            |dword| splice_dword(dword, offset, low, value),
        );
        if low < width {
            let (next, high) = (Self::dword_addr(addr) + 8, value >> (8 * low));
            self.write_next_dword::<EMIT>(sink, next, width - low, high);
        }
        Ok(dword)
    }

    /// [`Self::misaligned_store_no_count`] for the fallback interpreter.
    #[cold]
    pub(crate) fn misaligned_store(
        &mut self,
        opcode: Opcode,
        addr: u64,
        value: u64,
        width: u64,
    ) -> Result<u64, String> {
        self.misaligned(opcode, addr)?;
        let (offset, low) = Self::misaligned_split(addr, width);
        let dword = self.write_mem_dword_merged(Self::dword_addr(addr), |dword| {
            splice_dword(dword, offset, low, value)
        });
        if low < width {
            let (next, high) = (Self::dword_addr(addr) + 8, value >> (8 * low));
            by_sink!(self.write_next_dword(next, width - low, high));
        }
        Ok(dword)
    }

    /// An access's byte offset in its aligned dword, and how many of its `width` bytes land there.
    #[inline(always)]
    fn misaligned_split(addr: u64, width: u64) -> (u64, u64) {
        let offset = addr % 8;
        (offset, width.min(8 - offset))
    }

    /// Reads the dword at `addr`, the one after a misaligned load's aligned dword, at the C
    /// position, its access written into `sink` when `EMIT`.
    fn read_next_dword<const EMIT: bool>(&mut self, sink: LentSink<'_>, addr: u64) -> u64 {
        self.track_chunk_split_address(addr);
        let clk = self.clk + 1;
        let is_unconstrained = self.is_unconstrained_mode();
        let (value, prev_chunk, prev_timestamp) = if is_unconstrained {
            self.memory
                .read_and_update_metadata_no_mark(addr, self.current_chunk, clk)
        } else {
            self.memory
                .read_and_update_metadata(addr, self.current_chunk, clk)
        };
        let prev_record = MemoryRecord {
            value,
            chunk: prev_chunk,
            timestamp: prev_timestamp,
        };
        if is_unconstrained {
            self.record_unconstrained_memory_access(addr, prev_record);
        }
        self.snapshot_addr_if_needed(addr, &prev_record, Touch::Load);
        if EMIT {
            self.record_next_dword(sink, addr, value, prev_record, clk, false);
        }
        value
    }

    /// Replaces the low `width` bytes of the dword at `addr`, the one after a misaligned store's
    /// aligned dword, with those of `value`, at the C position, its access written into `sink`
    /// when `EMIT`.
    fn write_next_dword<const EMIT: bool>(
        &mut self,
        sink: LentSink<'_>,
        addr: u64,
        width: u64,
        value: u64,
    ) {
        self.track_chunk_split_address(addr);
        self.account_memory_access(addr);
        let current = self.memory.peek_dword(addr);
        let new = splice_dword(current, 0, width, value);
        let clk = self.clk + 1;
        let is_unconstrained = self.is_unconstrained_mode();
        let (_, prev_chunk, prev_timestamp) = if is_unconstrained {
            self.memory
                .write_and_capture_prev_no_mark(addr, new, self.current_chunk, clk)
        } else {
            self.memory
                .write_and_capture_prev(addr, new, self.current_chunk, clk)
        };
        let prev_record = MemoryRecord {
            value: current,
            chunk: prev_chunk,
            timestamp: prev_timestamp,
        };
        if is_unconstrained {
            self.record_unconstrained_memory_access(addr, prev_record);
        }
        self.snapshot_addr_if_needed(addr, &prev_record, Touch::PartialStore);
        if EMIT {
            self.record_next_dword(sink, addr, new, prev_record, clk, true);
        }
    }

    // ========================================================================
    // Span Memory Operations
    // ========================================================================

    /// Read a span of 4-byte logical words at a specific clock cycle into a preallocated buffer.
    #[inline]
    pub fn read_mem_word_span_at_clk(&mut self, addr: u64, out: &mut [u32], clk: u32) {
        for (i, slot) in out.iter_mut().enumerate() {
            let word_addr = addr + (i as u64) * u64::from(BYTES_PER_WORD);
            *slot = Self::backing_word(self.read_mem_word_at_clk(word_addr, clk));
        }
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

    // ========================================================================
    // Span-Checked Precompile Reads
    // ========================================================================
    //
    // The interpreter's precompiles read their first operand as one access (`dword_slice_unsafe`),
    // so an operand that runs into a forbidden range faults at its start; every other access is
    // checked dword by dword, as `read_mem_dword_syscall` / `write_mem_dword_syscall` check it.

    /// [`Self::read_mem_dword_span_snapshot`], the span checked as one load first.
    #[inline]
    pub fn read_mem_dword_span_snapshot_syscall(&mut self, addr: u64, out: &mut [u64]) {
        if self.load_span_allowed(addr, out.len()) {
            self.read_mem_dword_span_snapshot(addr, out);
        } else {
            out.fill(0);
        }
    }

    /// Whether `dwords` 8-byte slots at `addr` may be loaded as one access, recording the fault if
    /// not; an empty span always may.
    #[inline(always)]
    pub(crate) fn load_span_allowed(&mut self, addr: u64, dwords: usize) -> bool {
        dwords == 0 || self.syscall_access_allowed(addr, 8 * dwords as u64, false)
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
    use super::{AotEmulatorCore, Touch};
    use pico_vm::{
        chips::{chips::riscv_memory::event::MemoryRecordEnum, ffi::FfiOption},
        compiler::riscv::{instruction::Instruction, opcode::Opcode, program::Program},
        emulator::riscv::record_slots::hold_records_unbounded,
    };
    use std::{collections::BTreeMap, sync::Arc};

    fn test_program() -> Arc<Program> {
        let mut program = Program::new(Vec::new(), 0x1000, 0x1000);
        program.memory_image = Arc::new(BTreeMap::new());
        Arc::new(program)
    }

    /// Everything a store leaves behind that a snapshot, a later access or the chunk split reads:
    /// each cell's value and metadata, which cells are marked accessed, the batch's prestate and its
    /// counts, the split counters, and the unconstrained rollback.
    fn store_state(emu: &AotEmulatorCore, addrs: &[u64]) -> String {
        let cells: Vec<_> = addrs
            .iter()
            .map(|&addr| {
                (
                    emu.memory.get(addr),
                    emu.memory_snapshot.has_accessed(addr),
                    emu.memory_snapshot.get(addr),
                )
            })
            .collect();
        let mut accessed: Vec<_> = emu.memory.accessed_keys().collect();
        accessed.sort_unstable();
        let mut rollback: Vec<_> = emu
            .unconstrained_state
            .iter()
            .flat_map(|state| {
                state
                    .memory_diff
                    .iter()
                    .map(|(addr, record)| (*addr, *record))
            })
            .collect();
        rollback.sort_unstable_by_key(|(addr, _)| *addr);
        format!(
            "{cells:?} {accessed:?} {:?} {:?} {} {rollback:?}",
            emu.snapshot_counts, emu.chunk_split_state, emu.memory_snapshot_clean
        )
    }

    /// The single-access partial stores leave the state the read-then-write they replaced left:
    /// a dword touched before the batch and one never touched, a second store to the same dword,
    /// and, for the fallback's, a store inside an unconstrained region.
    #[test]
    fn a_partial_store_leaves_the_state_the_read_then_write_left() {
        type Merge = fn(u64) -> u64;
        type Store = fn(&mut AotEmulatorCore, u64, Merge);
        let stores: [(&str, Store, Store); 2] = [
            (
                "generated",
                |emu, addr, merge| {
                    let current = emu.read_mem_dword_constrained_impl::<false>(
                        None,
                        addr,
                        Touch::PartialStore,
                    );
                    emu.write_mem_dword_no_count(addr, merge(current));
                },
                |emu, addr, merge| {
                    emu.write_mem_dword_merged_no_count::<false>(None, addr, merge);
                },
            ),
            (
                "fallback",
                |emu, addr, merge| {
                    let current = emu.read_mem_dword_for_store(addr);
                    emu.write_mem_dword(addr, merge(current));
                },
                |emu, addr, merge| {
                    emu.write_mem_dword_merged(addr, merge);
                },
            ),
        ];
        let steps: [(u64, Merge); 3] = [
            (0x200, |dword| {
                AotEmulatorCore::write_u8_into_word(dword, 0x203, 0xab)
            }),
            (0x208, |dword| {
                AotEmulatorCore::write_u16_into_word(dword, 0x20a, 0xbeef)
            }),
            (0x200, |dword| {
                AotEmulatorCore::insert_word(dword, 0x204, 0x1234_5678)
            }),
        ];
        let addrs = [0x200, 0x208, 0x210];
        for (name, read_then_write, merged) in stores {
            let run = |store: Store, unconstrained: bool| {
                let mut emu = AotEmulatorCore::new(test_program(), Vec::new());
                emu.write_mem_dword(0x200, 0x1122_3344_5566_7788);
                emu.update_insn_clock();
                emu.save_batch_start_state();
                if unconstrained {
                    emu.enter_unconstrained_mode();
                }
                for (addr, merge) in steps {
                    store(&mut emu, addr, merge);
                    emu.update_insn_clock();
                }
                store_state(&emu, &addrs)
            };
            assert_eq!(run(merged, false), run(read_then_write, false), "{name}");
            if name == "fallback" {
                assert_eq!(
                    run(merged, true),
                    run(read_then_write, true),
                    "{name}, unconstrained"
                );
            }
        }
    }

    /// Every full-dword store writes the same access into the store's CPU event and the chunk's
    /// window on the dword, the counted constrained one included.
    #[test]
    fn every_full_dword_store_writes_its_access() {
        hold_records_unbounded();
        let program = Arc::new(Program::new(
            vec![Instruction::new(Opcode::SD, 1, 2, 0, false, true)],
            0x1000,
            0x1000,
        ));
        let emitted = |store: fn(&mut AotEmulatorCore, u64, u64)| {
            let mut emu = AotEmulatorCore::new(program.clone(), Vec::new());
            emu.write_reg_no_count(1, 7);
            emu.write_reg_no_count(2, 0x2000);
            emu.update_insn_clock();
            emu.emit_records();
            let base = emu.read_reg_b(2);
            let value = emu.read_reg_a(1);
            assert_eq!((base, value), (0x2000, 7));
            store(&mut emu, base, value);
            emu.emit_memory(0x1000, value, base, 0, value);
            emu.pc = 0x1004;
            emu.update_insn_clock();
            emu.finish_emitted_chunk();
            let mut record = emu.take_emitted_chunks().pop().expect("a chunk").record;
            record
                .cpu_local_memory_access
                .sort_unstable_by_key(|event| event.addr);
            let steps = record.cpu_steps();
            assert_eq!(steps.len(), 1);
            let event = steps.get(0);
            let held = |slot: FfiOption<MemoryRecordEnum>| match slot {
                FfiOption::Some(access) => Some(access.value()),
                FfiOption::None => None,
            };
            assert_eq!(held(event.a_record), Some(value));
            assert_eq!(held(event.b_record), Some(base));
            assert_eq!(held(event.memory_record), Some(value));
            let window = record
                .cpu_local_memory_access
                .iter()
                .find(|window| window.addr == base)
                .expect("store window");
            assert_eq!(window.final_mem_access.value, value);
            format!("{event:?} {:?}", record.cpu_local_memory_access)
        };

        let full = emitted(AotEmulatorCore::write_mem_dword);
        assert!(full.contains("memory_record: Some"), "{full}");
        assert_eq!(emitted(AotEmulatorCore::write_mem_dword_no_count), full);
        assert_eq!(emitted(AotEmulatorCore::write_mem_dword_constrained), full);
    }

    #[test]
    fn phase5_low32_slot_helpers_use_eight_byte_spacing() {
        let mut emu = AotEmulatorCore::new(test_program(), Vec::new());

        emu.write_mem_low32_slot_span_at_clk(0x1_0100, &[0x1122_3344, 0x5566_7788], 0);

        let mut slots = [0u32; 2];
        emu.read_mem_low32_slot_span_snapshot(0x1_0100, &mut slots);

        assert_eq!(slots, [0x1122_3344, 0x5566_7788]);
        assert_eq!(emu.memory.get(0x1_0100).value, 0x1122_3344);
        assert_eq!(emu.memory.get(0x1_0108).value, 0x5566_7788);
    }

    #[test]
    fn phase5_contiguous_word_span_read_reuses_single_backing_dword() {
        let mut emu = AotEmulatorCore::new(test_program(), Vec::new());
        emu.write_mem_dword(0x1_0100, 0x5566_7788_1122_3344);

        let mut words = [0u32; 2];
        emu.read_mem_word_span_at_clk(0x1_0100, &mut words, 7);

        assert_eq!(words, [0x1122_3344, 0x5566_7788]);
    }

    #[test]
    fn phase5_contiguous_word_span_write_reuses_single_backing_dword() {
        let mut emu = AotEmulatorCore::new(test_program(), Vec::new());
        emu.write_mem_dword(0x1_0100, 0);

        emu.write_mem_word_span_at_clk(0x1_0100, &[0x1122_3344, 0x5566_7788], 9);

        assert_eq!(emu.memory.get(0x1_0100).value, 0x5566_7788_1122_3344);
    }

    #[test]
    fn syscall_word_write_counts_one_chunk_split_event_per_logical_word() {
        let mut emu = AotEmulatorCore::new(test_program(), Vec::new());
        emu.write_mem_dword(0x1_0100, 0);
        emu.enter_syscall();

        emu.write_mem_word_syscall(0x1_0104, 0x1122_3344);

        assert_eq!(emu.chunk_split_state.num_syscall_memory_events, 1);
    }

    #[test]
    fn syscall_word_span_counts_one_event_per_logical_word() {
        let mut emu = AotEmulatorCore::new(test_program(), Vec::new());
        emu.write_mem_dword(0x1_0100, 0);
        emu.enter_syscall();

        let mut words = [0u32; 2];
        emu.read_mem_word_span_at_clk(0x1_0100, &mut words, 7);
        assert_eq!(emu.chunk_split_state.num_syscall_memory_events, 2);

        emu.chunk_split_state.clear();
        emu.write_mem_word_span_at_clk(0x1_0100, &[0x1122_3344, 0x5566_7788], 9);
        assert_eq!(emu.chunk_split_state.num_syscall_memory_events, 2);
    }
}
