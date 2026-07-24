use p3_maybe_rayon::prelude::{IndexedParallelIterator, ParallelIterator, ParallelSlice};

use crate::{
    chips::chips::riscv_memory::event::MemoryRecord,
    emulator::riscv::event_types::{RvAddr, RvChunk, RvTimestamp, RvValue},
};

use super::{
    constants::{METADATA_SIZE, VALUES_SIZE},
    contiguous::ContiguousRiscvMemory,
};

impl ContiguousRiscvMemory {
    #[inline(always)]
    fn guest_addr_to_usize(addr: RvAddr) -> usize {
        let idx = usize::try_from(addr).expect("guest address does not fit in usize");
        assert!(idx < VALUES_SIZE, "guest address out of range: {addr:#x}");
        idx
    }

    #[inline(always)]
    fn guest_addr_to_dword_index(addr: RvAddr) -> usize {
        let dword_idx = addr >> 3;
        let idx = usize::try_from(dword_idx).expect("dword index does not fit in usize");
        assert!(
            idx < METADATA_SIZE,
            "guest dword index out of range: {dword_idx:#x}"
        );
        idx
    }

    #[inline(always)]
    fn guest_addr_to_usize_for_dword(addr: RvAddr) -> usize {
        assert!(
            addr <= (VALUES_SIZE - 8) as u64,
            "dword address out of range: {addr:#x}"
        );
        usize::try_from(addr).expect("guest address does not fit in usize")
    }

    #[inline(always)]
    fn guest_addr_to_usize_for_word(addr: RvAddr) -> usize {
        assert!(
            addr <= (VALUES_SIZE - 4) as u64,
            "word address out of range: {addr:#x}"
        );
        usize::try_from(addr).expect("guest address does not fit in usize")
    }

    // ------------------------------------------------------------------------
    // Packed metadata helpers
    //
    // `(chunk: u32, timestamp: u32)` is stored interleaved in one `u64`: chunk in the low
    // 32 bits, timestamp in the high 32 bits. This co-locates each dword's metadata on a
    // single cache line (vs the two formerly-separate parallel `u32` arrays).
    // ------------------------------------------------------------------------

    #[inline(always)]
    const fn pack_metadata(chunk: RvChunk, timestamp: RvTimestamp) -> u64 {
        (chunk as u64) | ((timestamp as u64) << 32)
    }

    #[inline(always)]
    const fn unpack_metadata(packed: u64) -> (RvChunk, RvTimestamp) {
        (packed as RvChunk, (packed >> 32) as RvTimestamp)
    }

    // ------------------------------------------------------------------------
    // Dword (8-byte) operations
    // ------------------------------------------------------------------------

    /// Read a dword (8 bytes) from the given 8-byte-aligned address without modifying metadata.
    #[inline(always)]
    pub fn peek_dword(&self, addr: RvAddr) -> RvValue {
        let addr = Self::guest_addr_to_usize_for_dword(addr);
        let ptr = self.backing.values.as_slice().as_ptr();
        unsafe { std::ptr::read_unaligned(ptr.add(addr) as *const u64) }
    }

    /// Write a dword (8 bytes) to the given 8-byte-aligned address and update metadata.
    #[inline(always)]
    pub fn write_dword(
        &mut self,
        addr: RvAddr,
        value: RvValue,
        chunk: RvChunk,
        timestamp: RvTimestamp,
    ) {
        let byte_addr = Self::guest_addr_to_usize_for_dword(addr);
        let ptr = self.backing.values.as_mut_ptr();
        unsafe {
            std::ptr::write_unaligned(ptr.add(byte_addr) as *mut u64, value);
        }
        let idx = byte_addr >> 3;
        let metadata = self.backing.metadata.as_mut_slice();
        unsafe {
            *metadata.get_unchecked_mut(idx) = Self::pack_metadata(chunk, timestamp);
        }
    }

    // ------------------------------------------------------------------------
    // Word (4-byte) operations — peek only, metadata uses dword index
    // ------------------------------------------------------------------------

    /// Read a word (4 bytes) from the given address without modifying metadata.
    /// Uses Little Endian byte order.
    #[inline(always)]
    pub fn peek_word(&self, addr: RvAddr) -> u32 {
        let addr = Self::guest_addr_to_usize_for_word(addr);
        let ptr = self.backing.values.as_slice().as_ptr();
        unsafe { std::ptr::read_unaligned(ptr.add(addr) as *const u32) }
    }

    /// Read a word and update the containing dword's metadata.
    /// Returns the word value (Little Endian).
    #[inline(always)]
    pub fn read_word(
        &mut self,
        addr: RvAddr,
        new_chunk: RvChunk,
        new_timestamp: RvTimestamp,
    ) -> u32 {
        let value = self.peek_word(addr);
        let idx = Self::guest_addr_to_dword_index(addr);
        let metadata = self.backing.metadata.as_mut_slice();
        unsafe {
            *metadata.get_unchecked_mut(idx) = Self::pack_metadata(new_chunk, new_timestamp);
        }
        value
    }

    /// Read metadata for the dword containing the given address.
    /// Returns (chunk, timestamp).
    #[inline(always)]
    pub fn peek_metadata(&self, addr: RvAddr) -> (RvChunk, RvTimestamp) {
        let idx = Self::guest_addr_to_dword_index(addr);
        let metadata = self.backing.metadata.as_slice();
        unsafe { Self::unpack_metadata(*metadata.get_unchecked(idx)) }
    }

    /// Write a word (4 bytes) to the given address and update the containing dword's metadata.
    /// Uses Little Endian byte order.
    #[inline(always)]
    pub fn write_word(&mut self, addr: RvAddr, value: u32, chunk: RvChunk, timestamp: RvTimestamp) {
        let byte_addr = Self::guest_addr_to_usize_for_word(addr);
        let ptr = self.backing.values.as_mut_ptr();
        unsafe {
            std::ptr::write_unaligned(ptr.add(byte_addr) as *mut u32, value);
        }
        let idx = byte_addr >> 3;
        let metadata = self.backing.metadata.as_mut_slice();
        unsafe {
            *metadata.get_unchecked_mut(idx) = Self::pack_metadata(chunk, timestamp);
        }
    }

    // ------------------------------------------------------------------------
    // Byte operations
    // ------------------------------------------------------------------------

    /// Read a single byte without modifying metadata.
    #[inline(always)]
    pub fn peek_byte(&self, addr: RvAddr) -> u8 {
        let addr = Self::guest_addr_to_usize(addr);
        let values = self.backing.values.as_slice();
        // SAFETY: Address range is validated separately for SDK limit.
        unsafe { *values.get_unchecked(addr) }
    }

    /// Read a single byte and update the containing dword's metadata.
    #[inline(always)]
    pub fn read_byte(
        &mut self,
        addr: RvAddr,
        new_chunk: RvChunk,
        new_timestamp: RvTimestamp,
    ) -> u8 {
        let value = self.peek_byte(addr);
        // Update metadata for the containing dword (addr >> 3).
        let idx = Self::guest_addr_to_dword_index(addr);
        let metadata = self.backing.metadata.as_mut_slice();
        // SAFETY: idx is at most 2^30 - 1, which is within bounds.
        unsafe {
            *metadata.get_unchecked_mut(idx) = Self::pack_metadata(new_chunk, new_timestamp);
        }
        value
    }

    /// Write a single byte and update the containing dword's metadata.
    #[inline(always)]
    pub fn write_byte(&mut self, addr: RvAddr, value: u8, chunk: RvChunk, timestamp: RvTimestamp) {
        let addr = Self::guest_addr_to_usize(addr);
        let values = self.backing.values.as_mut_slice();
        unsafe {
            *values.get_unchecked_mut(addr) = value;
        }
        // Update metadata for the containing dword.
        let idx = addr >> 3;
        let metadata = self.backing.metadata.as_mut_slice();
        // SAFETY: idx is at most 2^30 - 1, which is within bounds.
        unsafe {
            *metadata.get_unchecked_mut(idx) = Self::pack_metadata(chunk, timestamp);
        }
    }

    // ------------------------------------------------------------------------
    // Compatibility helpers for MemoryRecord-based API
    // ------------------------------------------------------------------------

    /// Read a word and return full previous metadata.
    /// Returns (value, prev_chunk, prev_timestamp).
    /// Also updates metadata to (new_chunk, new_timestamp).
    #[inline(always)]
    pub fn read_word_full(
        &mut self,
        addr: RvAddr,
        new_chunk: RvChunk,
        new_timestamp: RvTimestamp,
    ) -> (u32, RvChunk, RvTimestamp) {
        let value = self.peek_word(addr);
        let (prev_chunk, prev_timestamp) = self.peek_metadata(addr);
        let idx = Self::guest_addr_to_dword_index(addr);
        let metadata = self.backing.metadata.as_mut_slice();
        unsafe {
            *metadata.get_unchecked_mut(idx) = Self::pack_metadata(new_chunk, new_timestamp);
        }
        (value, prev_chunk, prev_timestamp)
    }

    /// Write a word and return previous value and metadata.
    /// Returns (prev_value, prev_chunk, prev_timestamp).
    #[inline(always)]
    pub fn write_word_full(
        &mut self,
        addr: RvAddr,
        value: u32,
        new_chunk: RvChunk,
        new_timestamp: RvTimestamp,
    ) -> (u32, RvChunk, RvTimestamp) {
        let prev_value = self.peek_word(addr);
        let (prev_chunk, prev_timestamp) = self.peek_metadata(addr);
        self.write_word(addr, value, new_chunk, new_timestamp);
        (prev_value, prev_chunk, prev_timestamp)
    }

    /// Check if the dword at addr is uninitialized (value=0, chunk=0, timestamp=0).
    #[inline(always)]
    pub fn is_uninitialized(&self, addr: RvAddr) -> bool {
        let value = self.peek_dword(addr);
        let (chunk, timestamp) = self.peek_metadata(addr);
        value == 0 && chunk == 0 && timestamp == 0
    }

    /// Set just the dword value at addr without modifying metadata.
    #[inline(always)]
    pub fn set_value(&mut self, addr: RvAddr, value: RvValue) {
        let addr = Self::guest_addr_to_usize_for_dword(addr);
        let ptr = self.backing.values.as_mut_ptr();
        unsafe {
            std::ptr::write_unaligned(ptr.add(addr) as *mut u64, value);
        }
    }

    /// Set just the metadata at addr (uses dword index: addr >> 3).
    #[inline(always)]
    pub fn set_metadata(&mut self, addr: RvAddr, chunk: RvChunk, timestamp: RvTimestamp) {
        let idx = Self::guest_addr_to_dword_index(addr);
        let metadata = self.backing.metadata.as_mut_slice();
        unsafe {
            *metadata.get_unchecked_mut(idx) = Self::pack_metadata(chunk, timestamp);
        }
    }

    // ------------------------------------------------------------------------
    // Compatibility methods for MemoryRecord-based API (byte-address based).
    // ------------------------------------------------------------------------

    // Kaiwei: Three core api for RiscvEmulator, get, insert, get_mut_or_create
    // TODO: rename get to peek
    /// Get a MemoryRecord at the given 8-byte-aligned address.
    #[inline(always)]
    pub fn get(&self, addr: RvAddr) -> MemoryRecord {
        let value = self.peek_dword(addr);
        let (chunk, timestamp) = self.peek_metadata(addr);

        MemoryRecord {
            value,
            chunk,
            timestamp,
        }
    }

    /// Insert a MemoryRecord at the given 8-byte-aligned address.
    /// Returns the previous record.
    #[inline(always)]
    pub fn insert(&mut self, addr: RvAddr, record: MemoryRecord) -> MemoryRecord {
        debug_assert!(
            addr.is_multiple_of(8),
            "insert requires 8-byte-aligned address, got 0x{addr:08x}"
        );
        let (chunk, timestamp) = self.peek_metadata(addr);
        let prev = MemoryRecord {
            value: self.peek_dword(addr),
            chunk,
            timestamp,
        };
        self.write_dword(addr, record.value, record.chunk, record.timestamp);
        self.mark_accessed(addr);
        prev
    }

    #[inline(always)]
    pub fn insert_u64(&mut self, addr: RvAddr, record: MemoryRecord) -> MemoryRecord {
        self.insert(addr, record)
    }

    /// Bulk-load the program's initial memory image (8-byte-aligned addr → dword value).
    ///
    /// This is the initial load into a **freshly-allocated, zeroed** backing
    /// (`ContiguousRiscvMemory::new()` allocates `vec![0u8; …]` values + `vec![0u32; …]`
    /// metadata; chunk 0 is reserved for this load). Two redundancies are elided vs `insert`:
    /// 1. The `prev` record `insert` computes (`peek_metadata` + `peek_dword`) is discarded
    ///    by the caller — so those reads are skipped.
    /// 2. The metadata it would write is `chunk=0, timestamp=0` (packed `0u64`), which already
    ///    holds in the zeroed backing — so the metadata store is skipped, leaving the large
    ///    packed `metadata` array untouched (no first-touch page faults).
    ///
    /// We still write the value dword and set the accessed bit. The resulting state is
    /// identical to `insert(addr, MemoryRecord { value, chunk: 0, timestamp: 0 })` on a
    /// zeroed backing.
    #[inline]
    pub fn load_memory_image<'a, I>(&mut self, image: I)
    where
        I: IntoIterator<Item = (&'a RvAddr, &'a RvValue)>,
    {
        for (&addr, &value) in image {
            // Value-only write: metadata is left at its zeroed initial state.
            let byte_addr = Self::guest_addr_to_usize_for_dword(addr);
            let ptr = self.backing.values.as_mut_ptr();
            unsafe {
                std::ptr::write_unaligned(ptr.add(byte_addr) as *mut u64, value);
            }
            self.mark_accessed(addr);
        }
    }

    #[inline(always)]
    pub fn peek_insert(&mut self, addr: RvAddr, record: MemoryRecord) -> MemoryRecord {
        let (chunk, timestamp) = self.peek_metadata(addr);
        let prev = MemoryRecord {
            value: self.peek_dword(addr),
            chunk,
            timestamp,
        };
        self.write_dword(addr, record.value, record.chunk, record.timestamp);
        prev
    }

    // Kaiwei: replace entry (checked: all entry in pico should mark_accessed in original code)
    // Kaiwei: in snapshot_addr_if_needed, snapshot_record_if_needed, HintReadSyscall, we do not use get_mut_or_create (original use entry)
    /// Get or create a mutable-like access to memory at the given 8-byte-aligned address.
    #[inline(always)]
    pub fn get_mut_or_create(&mut self, addr: RvAddr) -> MemoryRecordRef<'_> {
        let value = self.peek_dword(addr);
        let (chunk, timestamp) = self.peek_metadata(addr);
        self.mark_accessed(addr);
        MemoryRecordRef {
            memory: self,
            addr,
            value,
            chunk,
            timestamp,
        }
    }

    #[inline(always)]
    pub fn read_and_update_metadata(
        &mut self,
        addr: RvAddr,
        new_chunk: RvChunk,
        new_timestamp: RvTimestamp,
    ) -> (RvValue, RvChunk, RvTimestamp) {
        let value = self.peek_dword(addr);
        let (old_chunk, old_timestamp) = self.peek_metadata(addr);

        // Update ONLY the metadata.
        self.set_metadata(addr, new_chunk, new_timestamp);

        self.mark_accessed(addr);

        // Return the state as it was BEFORE this update (for snapshots/records).
        (value, old_chunk, old_timestamp)
    }

    /// Writes a dword to memory and returns the previous value and metadata.
    #[inline(always)]
    pub fn write_and_capture_prev(
        &mut self,
        addr: RvAddr,
        value: RvValue,
        chunk: RvChunk,
        timestamp: RvTimestamp,
    ) -> (RvValue, RvChunk, RvTimestamp) {
        // 1. Read previous state (Peek)
        let prev_val = self.peek_dword(addr);
        let (prev_chunk, prev_ts) = self.peek_metadata(addr);

        // 2. Write new state (Value + Metadata)
        self.write_dword(addr, value, chunk, timestamp);

        // 3. Mark as accessed
        self.mark_accessed(addr);

        (prev_val, prev_chunk, prev_ts)
    }

    /// Like read_and_update_metadata but does NOT mark as accessed.
    /// Used for unconstrained mode where we don't want bitmap side effects.
    #[inline(always)]
    pub fn read_and_update_metadata_no_mark(
        &mut self,
        addr: RvAddr,
        new_chunk: RvChunk,
        new_timestamp: RvTimestamp,
    ) -> (RvValue, RvChunk, RvTimestamp) {
        let value = self.peek_dword(addr);
        let (old_chunk, old_timestamp) = self.peek_metadata(addr);
        self.set_metadata(addr, new_chunk, new_timestamp);
        (value, old_chunk, old_timestamp)
    }

    /// Like write_and_capture_prev but does NOT mark as accessed.
    /// Used for unconstrained mode where we don't want bitmap side effects.
    #[inline(always)]
    pub fn write_and_capture_prev_no_mark(
        &mut self,
        addr: RvAddr,
        value: RvValue,
        chunk: RvChunk,
        timestamp: RvTimestamp,
    ) -> (RvValue, RvChunk, RvTimestamp) {
        let prev_val = self.peek_dword(addr);
        let (prev_chunk, prev_ts) = self.peek_metadata(addr);
        self.write_dword(addr, value, chunk, timestamp);
        (prev_val, prev_chunk, prev_ts)
    }

    /// Returns an iterator over all accessed 8-byte-aligned addresses.
    /// This efficiently scans the bitmap, skipping blocks of zeros.
    pub fn accessed_keys(&self) -> impl Iterator<Item = RvAddr> + '_ {
        self.accessed_bitmap
            .iter()
            .enumerate()
            .filter(|(_, &bits)| bits != 0)
            .flat_map(|(vec_idx, &bits)| {
                let mut temp_bits = bits;
                // Base address for this u64 chunk: vec_idx * 64 dwords * 8 bytes/dword
                let chunk_base_addr = (vec_idx as u64) << 9;

                std::iter::from_fn(move || {
                    if temp_bits == 0 {
                        return None;
                    }

                    let bit_offset = temp_bits.trailing_zeros();

                    // Addr = ChunkBase + (BitOffset * 8)
                    let byte_addr = chunk_base_addr + ((bit_offset as u64) << 3);

                    temp_bits &= !(1 << bit_offset);

                    Some(byte_addr)
                })
            })
    }

    /// Marks the address as accessed (equivalent to `HashSet::insert`).
    /// Uses 8-byte dword granularity: one bit per 8-byte dword.
    #[inline(always)]
    fn mark_accessed(&mut self, addr: RvAddr) {
        let addr = Self::guest_addr_to_usize(addr);
        // Dword Index (index of the 8-byte dword)
        let dword_idx = addr >> 3;

        // Index within the u64 array (dword_idx / 64)
        let vec_idx = dword_idx >> 6;

        // Bit offset within the u64 (dword_idx % 64)
        let bit_offset = dword_idx & 63;

        unsafe {
            *self.accessed_bitmap.get_unchecked_mut(vec_idx) |= 1 << bit_offset;
        }
    }

    /// Checks if the dword containing the byte address has been accessed.
    #[inline(always)]
    pub fn has_accessed(&self, addr: RvAddr) -> bool {
        let dword_idx = Self::guest_addr_to_dword_index(addr);
        let vec_idx = dword_idx >> 6;
        let bit_offset = dword_idx & 63;

        unsafe { (*self.accessed_bitmap.get_unchecked(vec_idx) & (1 << bit_offset)) != 0 }
    }

    /// Restore values from another memory instance in parallel (using rayon).
    /// Note: do not restore the accessed_bitmap.
    pub fn par_restore_from(&mut self, source: &Self) {
        let self_values_ptr = self.backing.values.as_mut_ptr() as usize;
        let self_metadata_ptr = self.backing.metadata.as_mut_ptr() as usize;

        let num_cpus = num_cpus::get();
        let chunk_size = source.accessed_bitmap.len().div_ceil(num_cpus);

        source
            .accessed_bitmap
            .par_chunks(chunk_size)
            .enumerate()
            .for_each(|(chunk_idx, chunk)| {
                let chunk_start = chunk_idx * chunk_size;

                for (i, &bits) in chunk.iter().enumerate() {
                    if bits == 0 {
                        continue;
                    }

                    let vec_idx = chunk_start + i;
                    let mut temp_bits = bits;
                    // Base address: vec_idx * 64 dwords * 8 bytes/dword
                    let base_addr = (vec_idx as u64) << 9;

                    while temp_bits != 0 {
                        let bit_offset = temp_bits.trailing_zeros();
                        let byte_addr = base_addr + ((bit_offset << 3) as u64);
                        temp_bits &= !(1 << bit_offset);

                        // Read dword from source
                        let val = source.peek_dword(byte_addr);
                        let (chunk, ts) = source.peek_metadata(byte_addr);

                        // Write to self (safe because addresses are disjoint)
                        unsafe {
                            let v_ptr = (self_values_ptr as *mut u8)
                                .add(Self::guest_addr_to_usize_for_dword(byte_addr))
                                as *mut u64;
                            std::ptr::write_unaligned(v_ptr, val);

                            let m_idx = Self::guest_addr_to_dword_index(byte_addr);
                            let meta_ptr = (self_metadata_ptr as *mut u64).add(m_idx);
                            *meta_ptr = Self::pack_metadata(chunk, ts);
                        }
                    }
                }
            });
    }

    /// Returns an iterator over all accessed entries.
    /// Yields (addr, dword_value, chunk, timestamp) at 8-byte-aligned addresses.
    pub fn iter_accessed_entries(
        &self,
    ) -> impl Iterator<Item = (RvAddr, RvValue, RvChunk, RvTimestamp)> + '_ {
        self.accessed_bitmap
            .iter()
            .enumerate()
            .filter(|(_, &bits)| bits != 0)
            .flat_map(move |(vec_idx, &bits)| {
                let base_addr = (vec_idx as u64) << 9;
                BitIterator { bits, base_addr }
            })
            .map(move |addr| {
                let value = self.peek_dword(addr);
                let (chunk, timestamp) = self.peek_metadata(addr);
                (addr, value, chunk, timestamp)
            })
    }
}

struct BitIterator {
    bits: u64,
    base_addr: RvAddr,
}

impl Iterator for BitIterator {
    type Item = RvAddr;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bits == 0 {
            return None;
        }
        let bit_offset = self.bits.trailing_zeros();
        self.bits &= !(1 << bit_offset);

        Some(self.base_addr + u64::from(bit_offset << 3))
    }
}

/// A temporary reference to a memory record that allows mutation.
/// Changes are committed when the struct is dropped or when `commit()` is called.
pub struct MemoryRecordRef<'a> {
    pub(super) memory: &'a mut ContiguousRiscvMemory,
    addr: RvAddr,
    pub value: RvValue,
    pub chunk: RvChunk,
    pub timestamp: RvTimestamp,
}

impl<'a> MemoryRecordRef<'a> {
    /// Commit changes back to memory.
    #[inline(always)]
    pub fn commit(self) {
        // Drop will handle the commit
    }
}

impl<'a> Drop for MemoryRecordRef<'a> {
    fn drop(&mut self) {
        self.memory
            .write_dword(self.addr, self.value, self.chunk, self.timestamp);
    }
}

impl<'a> MemoryRecordRef<'a> {
    /// Convert to a MemoryRecord (snapshot of current state).
    #[inline(always)]
    pub fn to_record(&self) -> MemoryRecord {
        MemoryRecord {
            value: self.value,
            chunk: self.chunk,
            timestamp: self.timestamp,
        }
    }
}

impl FromIterator<(u64, MemoryRecord)> for ContiguousRiscvMemory {
    fn from_iter<T: IntoIterator<Item = (u64, MemoryRecord)>>(iter: T) -> Self {
        let mut memory = Self::new();
        for (addr, record) in iter {
            memory.write_dword(addr, record.value, record.chunk, record.timestamp);
            memory.mark_accessed(addr);
        }
        memory
    }
}

impl FromIterator<(u32, MemoryRecord)> for ContiguousRiscvMemory {
    fn from_iter<T: IntoIterator<Item = (u32, MemoryRecord)>>(iter: T) -> Self {
        iter.into_iter()
            .map(|(addr, record)| (u64::from(addr), record))
            .collect()
    }
}
