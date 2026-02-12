use p3_maybe_rayon::prelude::{IndexedParallelIterator, ParallelIterator, ParallelSlice};
use serde::{
    de::{DeserializeOwned, SeqAccess, Visitor},
    ser::SerializeSeq,
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::fmt;
use vec_map::VecMap;

use crate::chips::chips::riscv_memory::event::MemoryRecord;

// ============================================================================
// Storage Backend Abstraction
// ============================================================================

/// Storage backend for values (u8 array).
/// Provides two implementations:
/// - Box-based (default): Uses `Box<[u8]>` for heap allocation
/// - Mmap-based (feature "mmap-memory"): Uses anonymous mmap with fast reset via madvise
pub mod storage {
    /// Box-based storage for values (default implementation).
    #[cfg(not(feature = "mmap-memory"))]
    pub struct ValuesStorage {
        data: Box<[u8]>,
    }

    #[cfg(not(feature = "mmap-memory"))]
    impl ValuesStorage {
        /// Create a new storage with the given size, initialized to zero.
        pub fn new(size: usize) -> Self {
            Self {
                data: vec![0u8; size].into_boxed_slice(),
            }
        }

        /// Reset all bytes to zero.
        #[inline]
        pub fn reset(&mut self) {
            self.data.fill(0);
        }

        /// Get a raw mutable pointer to the data.
        #[inline(always)]
        pub fn as_mut_ptr(&mut self) -> *mut u8 {
            self.data.as_mut_ptr()
        }

        /// Get the length of the storage.
        #[inline(always)]
        pub fn len(&self) -> usize {
            self.data.len()
        }

        /// Returns true if the storage contains no elements.
        #[inline(always)]
        pub fn is_empty(&self) -> bool {
            self.data.is_empty()
        }

        /// Get the underlying slice.
        #[inline(always)]
        pub fn as_slice(&self) -> &[u8] {
            &self.data
        }

        /// Get the underlying mutable slice.
        #[inline(always)]
        pub fn as_mut_slice(&mut self) -> &mut [u8] {
            &mut self.data
        }
    }

    #[cfg(not(feature = "mmap-memory"))]
    impl Clone for ValuesStorage {
        fn clone(&self) -> Self {
            Self {
                data: self.data.clone(),
            }
        }
    }

    /// Box-based storage for metadata (default implementation).
    #[cfg(not(feature = "mmap-memory"))]
    pub struct MetadataStorage {
        data: Box<[u64]>,
    }

    #[cfg(not(feature = "mmap-memory"))]
    impl MetadataStorage {
        /// Create a new storage with the given size, initialized to zero.
        pub fn new(size: usize) -> Self {
            Self {
                data: vec![0u64; size].into_boxed_slice(),
            }
        }

        /// Reset all entries to zero.
        #[inline]
        pub fn reset(&mut self) {
            self.data.fill(0);
        }

        /// Get a raw mutable pointer to the data.
        #[inline(always)]
        pub fn as_mut_ptr(&mut self) -> *mut u64 {
            self.data.as_mut_ptr()
        }

        /// Get the length of the storage.
        #[inline(always)]
        pub fn len(&self) -> usize {
            self.data.len()
        }

        /// Returns true if the storage contains no elements.
        #[inline(always)]
        pub fn is_empty(&self) -> bool {
            self.data.is_empty()
        }

        /// Get the underlying slice.
        #[inline(always)]
        pub fn as_slice(&self) -> &[u64] {
            &self.data
        }

        /// Get the underlying mutable slice.
        #[inline(always)]
        pub fn as_mut_slice(&mut self) -> &mut [u64] {
            &mut self.data
        }
    }

    #[cfg(not(feature = "mmap-memory"))]
    impl Clone for MetadataStorage {
        fn clone(&self) -> Self {
            Self {
                data: self.data.clone(),
            }
        }
    }

    // ========================================================================
    // Mmap-based storage (Unix only, enabled with "mmap-memory" feature)
    // ========================================================================

    #[cfg(feature = "mmap-memory")]
    use memmap2::MmapMut;

    /// Mmap-based storage for values.
    /// Uses anonymous mmap and supports fast reset via madvise(MADV_DONTNEED).
    #[cfg(feature = "mmap-memory")]
    pub struct ValuesStorage {
        mmap: MmapMut,
    }

    #[cfg(feature = "mmap-memory")]
    impl ValuesStorage {
        /// Create a new mmap-backed storage with the given size.
        pub fn new(size: usize) -> Self {
            let mmap = MmapMut::map_anon(size).expect("Failed to create anonymous mmap for values");
            Self { mmap }
        }

        /// Reset all bytes to zero using madvise(MADV_DONTNEED).
        /// This is much faster than filling with zeros as it just discards the pages.
        #[inline]
        pub fn reset(&mut self) {
            unsafe {
                libc::madvise(
                    self.mmap.as_mut_ptr() as *mut libc::c_void,
                    self.mmap.len(),
                    libc::MADV_DONTNEED,
                );
            }
        }

        /// Get a raw mutable pointer to the data.
        #[inline(always)]
        pub fn as_mut_ptr(&mut self) -> *mut u8 {
            self.mmap.as_mut_ptr()
        }

        /// Get the length of the storage.
        #[inline(always)]
        pub fn len(&self) -> usize {
            self.mmap.len()
        }

        /// Returns true if the storage contains no elements.
        #[inline(always)]
        pub fn is_empty(&self) -> bool {
            self.mmap.is_empty()
        }

        /// Get the underlying slice.
        #[inline(always)]
        pub fn as_slice(&self) -> &[u8] {
            &self.mmap
        }

        /// Get the underlying mutable slice.
        #[inline(always)]
        pub fn as_mut_slice(&mut self) -> &mut [u8] {
            &mut self.mmap
        }
    }

    #[cfg(feature = "mmap-memory")]
    impl Clone for ValuesStorage {
        fn clone(&self) -> Self {
            let mut new_mmap = MmapMut::map_anon(self.mmap.len())
                .expect("Failed to create anonymous mmap for clone");
            new_mmap.copy_from_slice(&self.mmap);
            Self { mmap: new_mmap }
        }
    }

    /// Mmap-based storage for metadata.
    /// Note: Metadata is stored as u64, but mmap gives us bytes, so we need
    /// to handle the conversion carefully.
    #[cfg(feature = "mmap-memory")]
    pub struct MetadataStorage {
        mmap: MmapMut,
        /// Number of u64 entries (mmap.len() / 8).
        len: usize,
    }

    #[cfg(feature = "mmap-memory")]
    impl MetadataStorage {
        /// Create a new mmap-backed storage with the given number of u64 entries.
        pub fn new(size: usize) -> Self {
            let byte_size = size * std::mem::size_of::<u64>();
            let mmap =
                MmapMut::map_anon(byte_size).expect("Failed to create anonymous mmap for metadata");
            Self { mmap, len: size }
        }

        /// Reset all entries to zero using madvise(MADV_DONTNEED).
        #[inline]
        pub fn reset(&mut self) {
            unsafe {
                libc::madvise(
                    self.mmap.as_mut_ptr() as *mut libc::c_void,
                    self.mmap.len(),
                    libc::MADV_DONTNEED,
                );
            }
        }

        /// Get a raw mutable pointer to the data as u64.
        #[inline(always)]
        pub fn as_mut_ptr(&mut self) -> *mut u64 {
            self.mmap.as_mut_ptr() as *mut u64
        }

        /// Get the number of u64 entries.
        #[inline(always)]
        pub fn len(&self) -> usize {
            self.len
        }

        /// Returns true if the storage contains no elements.
        #[inline(always)]
        pub fn is_empty(&self) -> bool {
            self.len == 0
        }

        /// Get the underlying slice as u64.
        #[inline(always)]
        pub fn as_slice(&self) -> &[u64] {
            unsafe { std::slice::from_raw_parts(self.mmap.as_ptr() as *const u64, self.len) }
        }

        /// Get the underlying mutable slice as u64.
        #[inline(always)]
        pub fn as_mut_slice(&mut self) -> &mut [u64] {
            unsafe { std::slice::from_raw_parts_mut(self.mmap.as_mut_ptr() as *mut u64, self.len) }
        }
    }

    #[cfg(feature = "mmap-memory")]
    impl Clone for MetadataStorage {
        fn clone(&self) -> Self {
            let mut new_mmap = MmapMut::map_anon(self.mmap.len())
                .expect("Failed to create anonymous mmap for clone");
            new_mmap.copy_from_slice(&self.mmap);
            Self {
                mmap: new_mmap,
                len: self.len,
            }
        }
    }
}

use storage::{MetadataStorage, ValuesStorage};

// ============================================================================
// ContiguousRiscvMemory - High-performance unified memory model
// ============================================================================

// Bitmap size calculation:
// SDK max memory (0x7800_0000 bytes) / 4 (bytes per word) / 64 (bits per u64).
// This yields 8,192,512 (0x7D0000) u64 entries (~64MB).
const BITMAP_SIZE_U64: usize = (VALUES_SIZE >> 2) >> 6;

/// A contiguous SDK-limited memory model for high-performance RISC-V emulation.
///
/// This memory model uses a flat SDK-limited address space where:
/// - `values`: A contiguous storage of size 0x7800_0000 (~2GB) for storing actual data.
///   - Addresses 0-127 map to 32 registers (each 4 bytes).
///   - Addresses >= 128 are main memory.
/// - `metadata`: A contiguous storage of size (VALUES_SIZE >> 2) entries for storing
///   per-word metadata (chunk + timestamp packed into u64).
///
/// Metadata mapping: Each 4-byte word at address `addr` has metadata at index `addr >> 2`.
/// The u64 metadata contains `(chunk: u32, timestamp: u32)` packed together.
///
/// ## Storage Backend
///
/// The storage backend is selected at compile time via feature flags:
/// - **Default**: Uses `Box<[u8]>` / `Box<[u64]>` for heap allocation.
/// - **`mmap-memory` feature (Unix only)**: Uses anonymous mmap with fast reset
///   via `madvise(MADV_DONTNEED)`.
///
/// To enable mmap-based storage, compile with:
/// ```bash
/// cargo build --features mmap-memory
/// ```
pub struct ContiguousRiscvMemory {
    /// Raw byte storage for the SDK-limited address space.
    /// Registers occupy addresses 0-127 (32 registers × 4 bytes each).
    values: ValuesStorage,

    /// Metadata storage: one u64 per 4-byte word.
    /// Each u64 packs (chunk: u32, timestamp: u32).
    /// Index = addr >> 2.
    metadata: MetadataStorage,

    /// Tracks accessed non-register addresses for iteration in postprocess.
    /// This is a compatibility feature to support existing code patterns.
    accessed_bitmap: Box<[u64]>,
}

/// Size of the values array (SDK limit, ~2GB).
pub const VALUES_SIZE: usize = 0x7800_0000;

/// Size of the metadata array (one per 4-byte word).
pub const METADATA_SIZE: usize = VALUES_SIZE >> 2;

/// Number of registers.
pub const NUM_REGISTERS: u32 = 32;

impl ContiguousRiscvMemory {
    /// Create a new ContiguousRiscvMemory with zeroed values and metadata.
    ///
    /// This allocates ~2GB for values and ~4GB for metadata.
    ///
    /// - **Default backend**: Uses `vec![0; size].into_boxed_slice()` for contiguous heap memory.
    /// - **Mmap backend**: Uses anonymous mmap for zero-copy allocation.
    #[must_use]
    pub fn new() -> Self {
        Self {
            values: ValuesStorage::new(VALUES_SIZE),
            metadata: MetadataStorage::new(METADATA_SIZE),
            accessed_bitmap: vec![0u64; BITMAP_SIZE_U64].into_boxed_slice(),
        }
    }

    /// Reset the memory by zeroing all values and metadata.
    ///
    /// - **Default backend**: Uses `slice::fill(0)` to zero memory.
    /// - **Mmap backend**: Uses `madvise(MADV_DONTNEED)` for instant reset
    ///   (the kernel discards the pages and returns zeros on next access).
    #[inline]
    pub fn reset(&mut self) {
        if Self::is_mmap_backed() {
            self.values.reset();
            self.metadata.reset();
            self.accessed_bitmap.fill(0);
        } else {
            // Smart Reset: Only clear accessed pages
            // 1. Clear registers (always potentially dirty)
            let reg_size = NUM_REGISTERS as usize * 4;
            self.values.as_mut_slice()[..reg_size].fill(0);
            self.metadata.as_mut_slice()[..NUM_REGISTERS as usize].fill(0);

            // 2. Clear accessed memory ranges
            for (vec_idx, &bits) in self.accessed_bitmap.iter().enumerate() {
                if bits == 0 {
                    continue;
                }

                // Each bits (u64) covers 64 * 4 = 256 bytes
                let base_addr = vec_idx << 8;
                let values_slice = self.values.as_mut_slice();
                let metadata_slice = self.metadata.as_mut_slice();

                // Optimization: just zero the whole block covered by the u64 bitmap entry (256 bytes)
                // This is faster than bit-twiddling for individual words when resetting.
                // 256 bytes is small enough.
                let end_addr = base_addr + 256;

                // Safety bound check (though logic guarantees bounds)
                if end_addr <= values_slice.len() {
                    values_slice[base_addr..end_addr].fill(0);
                }

                // Metadata: 1 u64 per 4 bytes -> 64 u64s per 256 bytes
                // Index = addr >> 2
                let meta_start = base_addr >> 2;
                let meta_end = meta_start + 64;
                if meta_end <= metadata_slice.len() {
                    metadata_slice[meta_start..meta_end].fill(0);
                }
            }

            // 3. Clear the bitmap itself
            self.accessed_bitmap.fill(0);
        }
    }

    /// Clear the memory (alias for reset for compatibility).
    #[inline]
    pub fn clear(&mut self) {
        self.reset();
    }

    /// Clear only the accessed bitmap, leaving values/metadata untouched.
    #[inline]
    pub fn clear_accessed_bitmap(&mut self) {
        self.accessed_bitmap.fill(0);
    }

    /// Get a raw pointer to the values array.
    #[inline(always)]
    pub fn values_ptr(&mut self) -> *mut u8 {
        self.values.as_mut_ptr()
    }
}

// Global Memory Pool
use crossbeam::channel::{Receiver, Sender};
use once_cell::sync::Lazy;

// Pool as a channel for blocking support
pub static GLOBAL_MEMORY_POOL: Lazy<(
    Sender<ContiguousRiscvMemory>,
    Receiver<ContiguousRiscvMemory>,
)> = Lazy::new(|| {
    let (tx, rx) = crossbeam::channel::bounded(3);
    // Initialize with 3 items to avoid immediate blocking
    for _ in 0..3 {
        let _ = tx.send(ContiguousRiscvMemory::new());
    }
    (tx, rx)
});

// Recycler accepts (Memory, needs_reset)
pub static GLOBAL_MEMORY_RECYCLER: Lazy<Sender<(ContiguousRiscvMemory, bool)>> = Lazy::new(|| {
    let (tx, rx) = crossbeam::channel::unbounded::<(ContiguousRiscvMemory, bool)>();
    std::thread::Builder::new()
        .name("MemoryRecycler".to_string())
        .spawn(move || {
            while let Ok((mut mem, needs_reset)) = rx.recv() {
                if needs_reset {
                    mem.reset();
                }
                // Push to pool (blocking or non-blocking? Blocking is fine as long as there is consumer)
                // But Recycler shouldn't block indefinitely if pool is full (shouldn't happen if initialized correctly and 1-in-1-out).
                // Actually, bounded channel send blocks if full.
                let _ = GLOBAL_MEMORY_POOL.0.send(mem);
            }
        })
        .expect("Failed to spawn memory recycler thread");
    tx
});

impl ContiguousRiscvMemory {
    /// Get a raw pointer to the metadata array.
    #[inline(always)]
    pub fn metadata_ptr(&mut self) -> *mut u64 {
        self.metadata.as_mut_ptr()
    }

    /// Returns true if this memory instance uses mmap-based storage.
    #[inline(always)]
    pub const fn is_mmap_backed() -> bool {
        cfg!(feature = "mmap-memory")
    }

    /// Pack chunk and timestamp into a single u64.
    /// Layout: lower 32 bits = chunk, upper 32 bits = timestamp.
    #[inline(always)]
    pub const fn pack_metadata(chunk: u32, timestamp: u32) -> u64 {
        (chunk as u64) | ((timestamp as u64) << 32)
    }

    /// Unpack a u64 into (chunk, timestamp).
    #[inline(always)]
    pub const fn unpack_metadata(packed: u64) -> (u32, u32) {
        let chunk = packed as u32;
        let timestamp = (packed >> 32) as u32;
        (chunk, timestamp)
    }
}

// Implement Debug manually to avoid printing large memory buffers
impl std::fmt::Debug for ContiguousRiscvMemory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContiguousRiscvMemory")
            .field("values_size", &self.values.len())
            .field("metadata_size", &self.metadata.len())
            .field(
                "accessed_bitmap_size_bytes",
                &(self.accessed_bitmap.len() * 8),
            )
            .field("is_mmap_backed", &Self::is_mmap_backed())
            .finish()
    }
}

// Implement Clone manually - this is expensive but needed for compatibility
impl Clone for ContiguousRiscvMemory {
    fn clone(&self) -> Self {
        Self {
            values: self.values.clone(),
            metadata: self.metadata.clone(),
            accessed_bitmap: self.accessed_bitmap.clone(),
        }
    }
}

impl Serialize for ContiguousRiscvMemory {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut non_zero_entries = Vec::new();

        // 1. Serialize Registers (Addresses 0-127)
        // This part remains unchanged.
        for reg_idx in 0..NUM_REGISTERS {
            let byte_addr = reg_idx * 4;
            let value = self.peek_word(byte_addr);
            let (chunk, timestamp) = self.peek_metadata(byte_addr);
            if value != 0 || chunk != 0 || timestamp != 0 {
                non_zero_entries.push((reg_idx, value, chunk, timestamp));
            }
        }

        // 2. Serialize Main Memory (Scan the Bitmap)
        // CHANGED: We iterate over the u64 array.
        // If a u64 is 0, it means none of the 64 words it represents have been accessed.
        for (vec_idx, &bits) in self.accessed_bitmap.iter().enumerate() {
            if bits == 0 {
                continue; // Optimization: Skip 64 words at once if untouched
            }

            // Calculation:
            // vec_idx = index in u64 array.
            // Each vec_idx represents 64 words.
            // Each word is 4 bytes.
            // Base Address = vec_idx * 64 * 4 = vec_idx * 256 = vec_idx << 8
            let base_addr = (vec_idx as u32) << 8;

            let mut temp_bits = bits;
            while temp_bits != 0 {
                // 'trailing_zeros' maps directly to the TZCNT instruction on x86 (very fast).
                // It gives us the index of the next set bit (0-63).
                let bit_offset = temp_bits.trailing_zeros();

                // Calculate the actual memory address
                // Addr = Base + (Offset * 4)
                let addr = base_addr + (bit_offset << 2);

                let value = self.peek_word(addr);
                let (chunk, timestamp) = self.peek_metadata(addr);
                non_zero_entries.push((addr, value, chunk, timestamp));

                // Clear the lowest set bit to continue the loop
                // Example: 0011 -> 0010
                temp_bits &= !(1 << bit_offset);
            }
        }

        let mut seq = serializer.serialize_seq(Some(non_zero_entries.len()))?;
        for entry in non_zero_entries {
            seq.serialize_element(&entry)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for ContiguousRiscvMemory {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ContiguousRiscvMemoryVisitor;

        impl<'de> Visitor<'de> for ContiguousRiscvMemoryVisitor {
            type Value = ContiguousRiscvMemory;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a sequence of (addr, value, chunk, timestamp) tuples")
            }

            fn visit_seq<V>(self, mut seq: V) -> Result<Self::Value, V::Error>
            where
                V: SeqAccess<'de>,
            {
                let mut memory = ContiguousRiscvMemory::new();
                while let Some((addr, value, chunk, timestamp)) = seq.next_element()? {
                    memory.insert(
                        addr,
                        MemoryRecord {
                            value,
                            chunk,
                            timestamp,
                        },
                    );
                }
                Ok(memory)
            }
        }

        deserializer.deserialize_seq(ContiguousRiscvMemoryVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_serialization() {
        let mut memory = ContiguousRiscvMemory::new();

        // Insert some test data (both registers and main memory)
        memory.insert(
            0,
            MemoryRecord {
                value: 42,
                chunk: 1,
                timestamp: 2,
            },
        );
        memory.insert(
            32,
            MemoryRecord {
                value: 123,
                chunk: 3,
                timestamp: 4,
            },
        );
        memory.insert(
            64,
            MemoryRecord {
                value: 999,
                chunk: 5,
                timestamp: 6,
            },
        );

        // Serialize
        let serialized = bincode::serialize(&memory).unwrap();

        // Should be much smaller than the full memory size
        assert!(
            serialized.len() < 1000,
            "Serialized size: {} bytes",
            serialized.len()
        );

        // Deserialize
        let deserialized: ContiguousRiscvMemory = bincode::deserialize(&serialized).unwrap();

        // Check that data is preserved
        assert_eq!(
            deserialized.get(0),
            MemoryRecord {
                value: 42,
                chunk: 1,
                timestamp: 2
            }
        );
        assert_eq!(
            deserialized.get(32),
            MemoryRecord {
                value: 123,
                chunk: 3,
                timestamp: 4
            }
        );
        assert_eq!(
            deserialized.get(64),
            MemoryRecord {
                value: 999,
                chunk: 5,
                timestamp: 6
            }
        );

        // unified (0,0,0) and None
        assert_eq!(
            deserialized.get(100),
            MemoryRecord {
                value: 0,
                chunk: 0,
                timestamp: 0
            }
        );
    }

    #[test]
    fn test_mark_accessed_behavior() {
        let mut memory = ContiguousRiscvMemory::new();

        // insert with zero value should still mark as accessed
        memory.insert(
            0x1000,
            MemoryRecord {
                value: 0,
                chunk: 0,
                timestamp: 0,
            },
        );
        assert!(
            memory.has_accessed(0x1000),
            "insert with (0,0,0) should mark as accessed"
        );

        // get should NOT mark as accessed
        let _ = memory.get(0x2000);
        assert!(
            !memory.has_accessed(0x2000),
            "get() should NOT mark as accessed"
        );

        // get_mut_or_create should mark as accessed
        let _ = memory.get_mut_or_create(0x3000);
        assert!(
            memory.has_accessed(0x3000),
            "get_mut_or_create should mark as accessed"
        );

        // Verify registers (addr < 32) are NOT tracked in bitmap
        memory.insert(
            1,
            MemoryRecord {
                value: 42,
                chunk: 1,
                timestamp: 1,
            },
        );
        // has_accessed returns true for registers since they're always "accessible"
        assert!(
            memory.has_accessed(1),
            "registers should be considered accessible"
        );
    }
}

impl Default for ContiguousRiscvMemory {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Unchecked read/write methods for ContiguousRiscvMemory
// ============================================================================

impl ContiguousRiscvMemory {
    // ------------------------------------------------------------------------
    // Word operations
    // ------------------------------------------------------------------------

    /// Read a word (4 bytes) from the given address without modifying metadata.
    /// Uses Little Endian byte order.
    ///
    /// # Safety
    /// This method uses unchecked pointer access since we have allocated the SDK-limited space.
    /// We use `read_unaligned` to handle potentially unaligned addresses safely.
    #[inline(always)]
    pub fn peek_word(&self, addr: u32) -> u32 {
        let ptr = self.values.as_slice().as_ptr();
        // SAFETY: Address range is validated separately for SDK limit.
        // The value is stored in little-endian format, and read_unaligned handles
        // both aligned and unaligned accesses correctly.
        unsafe { std::ptr::read_unaligned(ptr.add(addr as usize) as *const u32) }
    }

    /// Read a word and update its metadata.
    /// Returns the word value (Little Endian).
    ///
    /// # Safety
    /// This method uses unchecked array access since we have allocated the SDK-limited space.
    #[inline(always)]
    pub fn read_word(&mut self, addr: u32, new_chunk: u32, new_timestamp: u32) -> u32 {
        let value = self.peek_word(addr);
        let idx = (addr >> 2) as usize;
        let metadata = self.metadata.as_mut_slice();
        // SAFETY: idx is derived from a validated address within SDK limit.
        unsafe {
            *metadata.get_unchecked_mut(idx) = Self::pack_metadata(new_chunk, new_timestamp);
        }
        value
    }

    /// Read metadata for the word at the given address.
    /// Returns (chunk, timestamp).
    #[inline(always)]
    pub fn peek_metadata(&self, addr: u32) -> (u32, u32) {
        let idx = (addr >> 2) as usize;
        let metadata = self.metadata.as_slice();
        // SAFETY: idx is derived from a validated address within SDK limit.
        unsafe { Self::unpack_metadata(*metadata.get_unchecked(idx)) }
    }

    /// Write a word (4 bytes) to the given address and update metadata.
    /// Uses Little Endian byte order.
    ///
    /// # Safety
    /// This method uses unchecked array access since we have allocated the SDK-limited space.
    #[inline(always)]
    pub fn write_word(&mut self, addr: u32, value: u32, chunk: u32, timestamp: u32) {
        let ptr = self.values.as_mut_ptr();
        // SAFETY: Address range is validated separately for SDK limit.
        // Using write_unaligned to handle potentially unaligned addresses.
        unsafe {
            std::ptr::write_unaligned(ptr.add(addr as usize) as *mut u32, value);
        }
        let idx = (addr >> 2) as usize;
        let metadata = self.metadata.as_mut_slice();
        // SAFETY: idx is derived from a validated address within SDK limit.
        unsafe {
            *metadata.get_unchecked_mut(idx) = Self::pack_metadata(chunk, timestamp);
        }
        // Note: write_word is a low-level primitive that does NOT call mark_accessed.
        // Callers (insert, get_mut_or_create) are responsible for calling mark_accessed.
    }

    // ------------------------------------------------------------------------
    // Byte operations
    // ------------------------------------------------------------------------

    /// Read a single byte without modifying metadata.
    #[inline(always)]
    pub fn peek_byte(&self, addr: u32) -> u8 {
        let values = self.values.as_slice();
        // SAFETY: Address range is validated separately for SDK limit.
        unsafe { *values.get_unchecked(addr as usize) }
    }

    /// Read a single byte and update the containing word's metadata.
    #[inline(always)]
    pub fn read_byte(&mut self, addr: u32, new_chunk: u32, new_timestamp: u32) -> u8 {
        let value = self.peek_byte(addr);
        // Update metadata for the containing word (addr >> 2).
        let idx = (addr >> 2) as usize;
        let metadata = self.metadata.as_mut_slice();
        // SAFETY: idx is at most 2^30 - 1, which is within bounds.
        unsafe {
            *metadata.get_unchecked_mut(idx) = Self::pack_metadata(new_chunk, new_timestamp);
        }
        value
    }

    /// Write a single byte and update the containing word's metadata.
    #[inline(always)]
    pub fn write_byte(&mut self, addr: u32, value: u8, chunk: u32, timestamp: u32) {
        let values = self.values.as_mut_slice();
        // SAFETY: We have allocated 4GB, so any u32 address is valid.
        unsafe {
            *values.get_unchecked_mut(addr as usize) = value;
        }
        // Update metadata for the containing word.
        let idx = (addr >> 2) as usize;
        let metadata = self.metadata.as_mut_slice();
        // SAFETY: idx is at most 2^30 - 1, which is within bounds.
        unsafe {
            *metadata.get_unchecked_mut(idx) = Self::pack_metadata(chunk, timestamp);
        }
    }

    // ------------------------------------------------------------------------
    // Register helper APIs (first 32 words, addresses 0-127)
    // ------------------------------------------------------------------------

    /// Get a register value and update its metadata.
    /// Registers are stored at addresses `idx * 4` for idx in 0..32.
    ///
    /// Note: This takes `&mut self` because reading a register updates its timestamp.
    #[inline(always)]
    pub fn get_reg(&mut self, idx: u32, chunk: u32, ts: u32) -> u32 {
        debug_assert!(idx < NUM_REGISTERS, "Register index out of bounds");
        self.read_word(idx * 4, chunk, ts)
    }

    /// Peek at a register value without modifying metadata.
    /// Useful for debugging or non-cycle-consuming reads.
    #[inline(always)]
    pub fn peek_reg(&self, idx: u32) -> u32 {
        debug_assert!(idx < NUM_REGISTERS, "Register index out of bounds");
        self.peek_word(idx * 4)
    }

    /// Set a register value and update its metadata.
    #[inline(always)]
    pub fn set_reg(&mut self, idx: u32, val: u32, chunk: u32, ts: u32) {
        debug_assert!(idx < NUM_REGISTERS, "Register index out of bounds");
        self.write_word(idx * 4, val, chunk, ts)
    }

    /// Returns an iterator over the first 32 registers (for debugging).
    /// Yields (index, value) pairs.
    pub fn registers_iter(&self) -> impl Iterator<Item = (u32, u32)> + '_ {
        (0..NUM_REGISTERS).map(|idx| (idx, self.peek_word(idx * 4)))
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
        addr: u32,
        new_chunk: u32,
        new_timestamp: u32,
    ) -> (u32, u32, u32) {
        let value = self.peek_word(addr);
        let (prev_chunk, prev_timestamp) = self.peek_metadata(addr);
        let idx = (addr >> 2) as usize;
        let metadata = self.metadata.as_mut_slice();
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
        addr: u32,
        value: u32,
        new_chunk: u32,
        new_timestamp: u32,
    ) -> (u32, u32, u32) {
        let prev_value = self.peek_word(addr);
        let (prev_chunk, prev_timestamp) = self.peek_metadata(addr);
        self.write_word(addr, value, new_chunk, new_timestamp);
        (prev_value, prev_chunk, prev_timestamp)
    }

    /// Check if the word at addr is uninitialized (value=0, chunk=0, timestamp=0).
    #[inline(always)]
    pub fn is_uninitialized(&self, addr: u32) -> bool {
        let value = self.peek_word(addr);
        let (chunk, timestamp) = self.peek_metadata(addr);
        value == 0 && chunk == 0 && timestamp == 0
    }

    /// Set just the value at addr without modifying metadata.
    #[inline(always)]
    pub fn set_value(&mut self, addr: u32, value: u32) {
        let ptr = self.values.as_mut_ptr();
        // SAFETY: We have allocated 4GB, so any u32 address is valid.
        unsafe {
            std::ptr::write_unaligned(ptr.add(addr as usize) as *mut u32, value);
        }
    }

    /// Set just the metadata at addr without modifying value.
    #[inline(always)]
    pub fn set_metadata(&mut self, addr: u32, chunk: u32, timestamp: u32) {
        let idx = (addr >> 2) as usize;
        let metadata = self.metadata.as_mut_slice();
        unsafe {
            *metadata.get_unchecked_mut(idx) = Self::pack_metadata(chunk, timestamp);
        }
    }

    // ------------------------------------------------------------------------
    // Compatibility methods for MemoryRecord-based API
    // These methods use the old address convention:
    // - Addresses 0-31 are register indices
    // - Addresses >= 32 are word-aligned byte addresses
    // ------------------------------------------------------------------------

    // Kaiwei: Three core api for RiscvEmulator, get, insert, get_mut_or_create
    // TODO: rename get to peek
    /// Get a MemoryRecord at the given address.
    /// Address convention: 0-31 are register indices, >= 32 are byte addresses.
    /// Returns None if the address has not been accessed.
    /// For registers: returns None only if all values are 0.
    /// For memory: returns None if address is not in accessed_bitmap AND all values are 0.
    #[inline(always)]
    pub fn get(&self, addr: u32) -> MemoryRecord {
        let byte_addr = to_byte_addr(addr);
        let value = self.peek_word(byte_addr);
        let (chunk, timestamp) = self.peek_metadata(byte_addr);

        MemoryRecord {
            value,
            chunk,
            timestamp,
        }
    }

    /// Insert a MemoryRecord at the given address.
    /// Address convention: 0-31 are register indices, >= 32 are byte addresses.
    /// Returns the previous record.
    #[inline(always)]
    pub fn insert(&mut self, addr: u32, record: MemoryRecord) -> MemoryRecord {
        let byte_addr = to_byte_addr(addr);
        let (chunk, timestamp) = self.peek_metadata(byte_addr);
        let prev = MemoryRecord {
            value: self.peek_word(byte_addr),
            chunk,
            timestamp,
        };
        self.write_word(byte_addr, record.value, record.chunk, record.timestamp);
        self.mark_accessed(byte_addr);
        prev
    }

    #[inline(always)]
    pub fn peek_insert(&mut self, addr: u32, record: MemoryRecord) -> MemoryRecord {
        let byte_addr = to_byte_addr(addr);
        let (chunk, timestamp) = self.peek_metadata(byte_addr);
        let prev = MemoryRecord {
            value: self.peek_word(byte_addr),
            chunk,
            timestamp,
        };
        self.write_word(byte_addr, record.value, record.chunk, record.timestamp);
        prev
    }

    // Kaiwei: replace entry (checked: all entry in pico should mark_accessed in original code)
    // Kaiwei: in snapshot_addr_if_needed, snapshot_record_if_needed, HintReadSyscall, we do not use get_mut_or_create (original use entry)
    /// Get or create a mutable-like access to memory at the given address.
    /// Address convention: 0-31 are register indices, >= 32 are byte addresses.
    ///
    /// For the new API, prefer using `read_word_full` + `write_word` directly.
    #[inline(always)]
    pub fn get_mut_or_create(&mut self, addr: u32) -> MemoryRecordRef<'_> {
        let byte_addr = to_byte_addr(addr);
        let value = self.peek_word(byte_addr);
        let (chunk, timestamp) = self.peek_metadata(byte_addr);
        self.mark_accessed(byte_addr);
        MemoryRecordRef {
            memory: self,
            addr: byte_addr, // Store the byte address for write-back
            value,
            chunk,
            timestamp,
        }
    }

    #[inline(always)]
    pub fn read_and_update_metadata(
        &mut self,
        addr: u32,
        new_chunk: u32,
        new_timestamp: u32,
    ) -> (u32, u32, u32) {
        let byte_addr = to_byte_addr(addr);

        //   We use `peek` to avoid triggering any side effects yet.
        let value = self.peek_word(byte_addr);
        let (old_chunk, old_timestamp) = self.peek_metadata(byte_addr);

        // Update ONLY the metadata.
        self.set_metadata(byte_addr, new_chunk, new_timestamp);

        self.mark_accessed(byte_addr);

        // Return the state as it was BEFORE this update (for snapshots/records).
        (value, old_chunk, old_timestamp)
    }

    /// Writes a word to memory and returns the previous value and metadata.
    #[inline(always)]
    pub fn write_and_capture_prev(
        &mut self,
        addr: u32,
        value: u32,
        chunk: u32,
        timestamp: u32,
    ) -> (u32, u32, u32) {
        let byte_addr = to_byte_addr(addr);

        // 1. Read previous state (Peek)
        let prev_val = self.peek_word(byte_addr);
        let (prev_chunk, prev_ts) = self.peek_metadata(byte_addr);

        // 2. Write new state (Value + Metadata)
        self.write_word(byte_addr, value, chunk, timestamp);

        // 3. Mark as accessed
        self.mark_accessed(byte_addr);

        (prev_val, prev_chunk, prev_ts)
    }

    /// Like read_and_update_metadata but does NOT mark as accessed.
    /// Used for unconstrained mode where we don't want bitmap side effects.
    #[inline(always)]
    pub fn read_and_update_metadata_no_mark(
        &mut self,
        addr: u32,
        new_chunk: u32,
        new_timestamp: u32,
    ) -> (u32, u32, u32) {
        let byte_addr = to_byte_addr(addr);
        let value = self.peek_word(byte_addr);
        let (old_chunk, old_timestamp) = self.peek_metadata(byte_addr);
        self.set_metadata(byte_addr, new_chunk, new_timestamp);
        // Note: No mark_accessed call - this is intentional for unconstrained mode
        (value, old_chunk, old_timestamp)
    }

    /// Like write_and_capture_prev but does NOT mark as accessed.
    /// Used for unconstrained mode where we don't want bitmap side effects.
    #[inline(always)]
    pub fn write_and_capture_prev_no_mark(
        &mut self,
        addr: u32,
        value: u32,
        chunk: u32,
        timestamp: u32,
    ) -> (u32, u32, u32) {
        let byte_addr = to_byte_addr(addr);
        let prev_val = self.peek_word(byte_addr);
        let (prev_chunk, prev_ts) = self.peek_metadata(byte_addr);
        self.write_word(byte_addr, value, chunk, timestamp);
        // Note: No mark_accessed call - this is intentional for unconstrained mode
        (prev_val, prev_chunk, prev_ts)
    }

    /// Returns an iterator over all accessed addresses (logical addresses).
    /// - For registers: returns register numbers (0-31)
    /// - For memory: returns the memory address (>= 128)
    ///
    /// This efficiently scans the bitmap, skipping blocks of zeros.
    pub fn accessed_keys(&self) -> impl Iterator<Item = u32> + '_ {
        self.accessed_bitmap
            .iter()
            .enumerate()
            // Optimization: Skip empty u64 chunks entirely
            .filter(|(_, &bits)| bits != 0)
            .flat_map(|(vec_idx, &bits)| {
                // State for the inner iterator (captured by move)
                let mut temp_bits = bits;
                // Base address for this u64 chunk: vec_idx * 64 words * 4 bytes/word
                let chunk_base_addr = (vec_idx as u32) << 8;

                // Create a generator that yields addresses for set bits
                std::iter::from_fn(move || {
                    if temp_bits == 0 {
                        return None; // No more bits set in this chunk
                    }

                    // Find the index of the lowest set bit (efficient hardware instruction TZCNT/BSF)
                    let bit_offset = temp_bits.trailing_zeros();

                    // Calculate the absolute byte address
                    // Addr = ChunkBase + (BitOffset * 4)
                    let byte_addr = chunk_base_addr + (bit_offset << 2);

                    // Clear the bit we just processed so we find the next one in the next iteration
                    temp_bits &= !(1 << bit_offset);

                    // Convert byte address back to logical address
                    // For registers (byte_addr < 128): returns 0-31
                    // For memory: returns the memory address unchanged
                    Some(from_byte_addr(byte_addr))
                })
            })
    }

    /// Marks the address as accessed (equivalent to `HashSet::insert`).
    ///
    /// Assembly Strategy (x86):
    ///   MOV RDI, base_addr
    ///   MOV RSI, addr
    ///   SHR RSI, 2        ; Convert to word index
    ///   BTS [RDI], RSI    ; Bit Test and Set, directly sets the corresponding bit
    #[inline(always)]
    fn mark_accessed(&mut self, addr: u32) {
        // Word Index (index of the 4-byte word)
        let word_idx = (addr >> 2) as usize;

        // Index within the u64 array (word_idx / 64)
        let vec_idx = word_idx >> 6;

        // Bit offset within the u64 (word_idx % 64)
        let bit_offset = word_idx & 63;

        // SAFETY: The mathematical derivation guarantees that `vec_idx` is at most
        // (2^32 / 4 / 64) = 2^24, which exactly matches `BITMAP_SIZE_U64`.
        // This ensures that the access is always within bounds.
        unsafe {
            *self.accessed_bitmap.get_unchecked_mut(vec_idx) |= 1 << bit_offset;
        }
    }

    /// Checks if the address has been accessed (equivalent to `HashSet::contains`).
    #[inline(always)]
    pub fn has_accessed(&self, addr: u32) -> bool {
        let byte_addr = to_byte_addr(addr);
        let word_idx = (byte_addr >> 2) as usize;
        let vec_idx = word_idx >> 6;
        let bit_offset = word_idx & 63;

        unsafe { (*self.accessed_bitmap.get_unchecked(vec_idx) & (1 << bit_offset)) != 0 }
    }

    /// Restore values from another memory instance in parallel (using rayon).
    /// Note: do not restore the accessed_bitmap.
    pub fn par_restore_from(&mut self, source: &Self) {
        // Extract raw pointers to allow parallel writes to disjoint locations
        let self_values_ptr = self.values.as_mut_ptr() as usize;
        let self_metadata_ptr = self.metadata.as_mut_ptr() as usize;
        // let self_bitmap_ptr = self.accessed_bitmap.as_mut_ptr() as usize;

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

                    // Update accessed_bitmap
                    // Safe because vec_idx is unique per task, so no race on *u64
                    // unsafe {
                    //     let b_ptr = (self_bitmap_ptr as *mut u64).add(vec_idx);
                    //     *b_ptr |= bits;
                    // }

                    let mut temp_bits = bits;
                    let base_addr = (vec_idx as u32) << 8;

                    while temp_bits != 0 {
                        let bit_offset = temp_bits.trailing_zeros();
                        let byte_addr = base_addr + (bit_offset << 2);
                        temp_bits &= !(1 << bit_offset);

                        // Read from source
                        let val = source.peek_word(byte_addr);
                        let (chunk, ts) = source.peek_metadata(byte_addr);

                        // Write to self (safe because addresses are disjoint)
                        unsafe {
                            let v_ptr =
                                (self_values_ptr as *mut u8).add(byte_addr as usize) as *mut u32;
                            std::ptr::write_unaligned(v_ptr, val);

                            let m_idx = (byte_addr >> 2) as usize;
                            let m_ptr = (self_metadata_ptr as *mut u64).add(m_idx);
                            *m_ptr = Self::pack_metadata(chunk, ts);
                        }
                    }
                }
            });
    }

    /// Returns an iterator over all accessed non-register entries (addresses >= 128).
    /// Yields (addr, value, chunk, timestamp).
    // TODO: merge fn accessed_keys & iter_accessed_entries
    pub fn iter_accessed_entries(&self) -> impl Iterator<Item = (u32, u32, u32, u32)> + '_ {
        self.accessed_bitmap
            .iter()
            .enumerate()
            .filter(|(_, &bits)| bits != 0)
            .flat_map(move |(vec_idx, &bits)| {
                let base_addr = (vec_idx as u32) << 8;
                BitIterator { bits, base_addr }
            })
            // Filter out register addresses (0-127) as they are handled separately.
            // Addresses >= 128 are main memory.
            .filter(|&addr| addr >= 128)
            .map(move |addr| {
                let value = self.peek_word(addr);
                let (chunk, timestamp) = self.peek_metadata(addr);
                (addr, value, chunk, timestamp)
            })
    }
}

struct BitIterator {
    bits: u64,
    base_addr: u32,
}

impl Iterator for BitIterator {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bits == 0 {
            return None;
        }
        let bit_offset = self.bits.trailing_zeros();
        // Clear the lowest set bit
        self.bits &= !(1 << bit_offset);

        Some(self.base_addr + (bit_offset << 2))
    }
}

/// A temporary reference to a memory record that allows mutation.
/// Changes are committed when the struct is dropped or when `commit()` is called.
pub struct MemoryRecordRef<'a> {
    memory: &'a mut ContiguousRiscvMemory,
    addr: u32,
    pub value: u32,
    pub chunk: u32,
    pub timestamp: u32,
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
            .write_word(self.addr, self.value, self.chunk, self.timestamp);
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

impl FromIterator<(u32, MemoryRecord)> for ContiguousRiscvMemory {
    fn from_iter<T: IntoIterator<Item = (u32, MemoryRecord)>>(iter: T) -> Self {
        let mut memory = Self::new();
        for (addr, record) in iter {
            let byte_addr = to_byte_addr(addr);

            memory.write_word(byte_addr, record.value, record.chunk, record.timestamp);
            memory.mark_accessed(byte_addr);
        }
        memory
    }
}

// TODO: remove contidion by hardcode * 4 in the higher lever, like rr_simple
/// Convert an old-style address to a byte address.
/// For addr < 32: register index -> byte address (addr * 4)
/// For addr >= 32: already a byte address
#[inline(always)]
const fn to_byte_addr(addr: u32) -> u32 {
    if addr < NUM_REGISTERS {
        addr * 4
    } else {
        addr
    }
}

/// Convert byte address back to logical address.
/// For registers (byte_addr < 128): returns register number (0-31)
/// For memory (byte_addr >= 128): returns the same address
#[inline(always)]
const fn from_byte_addr(byte_addr: u32) -> u32 {
    if byte_addr < NUM_REGISTERS * 4 {
        // This is a register byte address (0, 4, 8, ... 124)
        // Convert back to register number (0, 1, 2, ... 31)
        byte_addr / 4
    } else {
        byte_addr
    }
}
// ============================================================================
// Legacy paged memory implementation (used by uninitialized_memory)
// ============================================================================

/// A memory.
///
/// Consists of registers, as well as a page table for main memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "T: Serialize"))]
#[serde(bound(deserialize = "T: DeserializeOwned"))]
pub struct Memory<T: Copy + Default> {
    /// The registers.
    pub registers: Registers<T>,
    /// The page table.
    pub page_table: PagedMemory<T>,
}

impl<V: Copy + Default + 'static> IntoIterator for Memory<V> {
    type Item = (u32, V);

    type IntoIter = Box<dyn Iterator<Item = Self::Item>>;

    fn into_iter(self) -> Self::IntoIter {
        Box::new(self.registers.into_iter().chain(self.page_table))
    }
}

impl<T: Copy + Default> Default for Memory<T> {
    fn default() -> Self {
        Self {
            registers: Registers::default(),
            page_table: PagedMemory::default(),
        }
    }
}

impl<T: Copy + Default> Memory<T> {
    /// Initialize a new memory with preallocated page table.
    pub fn new_preallocated() -> Self {
        Self {
            registers: Registers::default(),
            page_table: PagedMemory::new_preallocated(),
        }
    }

    /// Insert a value into the memory.
    ///
    /// When possible, prefer directly accessing the `page_table` or `registers` fields.
    /// This method often incurs unnecessary branching.
    #[inline]
    pub fn insert(&mut self, addr: u32, value: T) -> T {
        if addr < 32 {
            self.registers.insert(addr, value)
        } else {
            self.page_table.insert(addr, value)
        }
    }

    // Kaiwei: register behavior changes
    /// Get a value from the memory.
    ///
    /// Returns None only if it's a page table address and the page doesn't exist.
    /// When possible, prefer directly accessing the `page_table` or `registers` fields.
    /// This method often incurs unnecessary branching.
    #[inline]
    pub fn get(&self, addr: u32) -> Option<&T> {
        if addr < 32 {
            Some(self.registers.get(addr))
        } else {
            self.page_table.get(addr)
        }
    }

    /// Get a mutable reference, creating the page if needed for page table addresses.
    ///
    /// When possible, prefer directly accessing the `page_table` or `registers` fields.
    /// This method often incurs unnecessary branching.
    #[inline]
    pub fn get_mut_or_create(&mut self, addr: u32) -> &mut T {
        if addr < 32 {
            self.registers.get_mut(addr)
        } else {
            self.page_table.get_mut_or_create(addr)
        }
    }

    /// Clear the memory.
    #[inline]
    pub fn clear(&mut self) {
        self.registers.clear();
        self.page_table.clear();
    }
}

impl<V: Copy + Default> FromIterator<(u32, V)> for Memory<V> {
    fn from_iter<T: IntoIterator<Item = (u32, V)>>(iter: T) -> Self {
        let mut memory = Self::new_preallocated();
        for (addr, value) in iter {
            memory.insert(addr, value);
        }
        memory
    }
}

/// An array of 32 registers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "T: Serialize"))]
#[serde(bound(deserialize = "T: DeserializeOwned"))]
pub struct Registers<T: Copy + Default> {
    pub registers: [T; 32],
}

impl<T: Copy + Default> Default for Registers<T> {
    fn default() -> Self {
        Self {
            registers: [T::default(); 32],
        }
    }
}

impl<T: Copy + Default> Registers<T> {
    /// Get a reference to the value at the given address.
    ///
    /// Assumes addr < 32.
    #[inline]
    pub fn get(&self, addr: u32) -> &T {
        &self.registers[addr as usize]
    }

    /// Get a mutable reference to the value at the given address.
    ///
    /// Assumes addr < 32.
    #[inline]
    pub fn get_mut(&mut self, addr: u32) -> &mut T {
        &mut self.registers[addr as usize]
    }

    /// Insert a value into the registers.
    ///
    /// Assumes addr < 32.
    #[inline]
    pub fn insert(&mut self, addr: u32, value: T) -> T {
        std::mem::replace(&mut self.registers[addr as usize], value)
    }

    /// Clear the registers (reset to default).
    #[inline]
    pub fn clear(&mut self) {
        self.registers = [T::default(); 32];
    }
}

impl<V: Copy + Default> FromIterator<(u32, V)> for Registers<V> {
    fn from_iter<T: IntoIterator<Item = (u32, V)>>(iter: T) -> Self {
        let mut mmu = Self::default();
        for (k, v) in iter {
            mmu.insert(k, v);
        }
        mmu
    }
}

impl<V: Copy + Default + 'static> IntoIterator for Registers<V> {
    type Item = (u32, V);

    type IntoIter = Box<dyn Iterator<Item = Self::Item>>;

    fn into_iter(self) -> Self::IntoIter {
        Box::new(
            self.registers
                .into_iter()
                .enumerate()
                .map(|(i, v)| (i as u32, v)),
        )
    }
}

/// A page of memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Page<V>(VecMap<V>);

impl<V> Default for Page<V> {
    fn default() -> Self {
        Self(VecMap::default())
    }
}

const LOG_PAGE_LEN: usize = 14;
const PAGE_LEN: usize = 1 << LOG_PAGE_LEN;
// TODO: MAX_PAGE_COUNT, kb or bb or u32?
const MAX_PAGE_COUNT: usize = ((1 << 31) - (1 << 24)) / 4 / PAGE_LEN + 1;
const NO_PAGE: u16 = u16::MAX;
const PAGE_MASK: usize = PAGE_LEN - 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "V: Serialize"))]
#[serde(bound(deserialize = "V: DeserializeOwned"))]
pub struct NewPage<V>(Vec<V>);

impl<V: Copy + Default> NewPage<V> {
    pub fn new() -> Self {
        Self(vec![V::default(); PAGE_LEN])
    }
}

impl<V: Copy + Default> Default for NewPage<V> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

/// Paged memory. Balances both memory locality and total memory usage.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "V: Serialize"))]
#[serde(bound(deserialize = "V: DeserializeOwned"))]
pub struct PagedMemory<V: Copy + Default> {
    /// The internal page table.
    pub page_table: Vec<NewPage<V>>,
    pub index: Vec<u16>,
}

impl<V: Copy + Default> PagedMemory<V> {
    /// The number of lower bits to ignore, since addresses (except registers) are a multiple of 4.
    const NUM_IGNORED_LOWER_BITS: usize = 2;

    /// Create a `PagedMemory` with capacity `MAX_PAGE_COUNT`.
    pub fn new_preallocated() -> Self {
        Self {
            page_table: Vec::new(),
            index: vec![NO_PAGE; MAX_PAGE_COUNT],
        }
    }

    /// Get a reference to the memory value at the given address.
    /// Returns None if the page doesn't exist.
    pub fn get(&self, addr: u32) -> Option<&V> {
        let (upper, lower) = Self::indices(addr);
        let index = self.index[upper];
        if index == NO_PAGE {
            None
        } else {
            Some(&self.page_table[index as usize].0[lower])
        }
    }

    /// Get a mutable reference to the memory value at the given address.
    /// Returns None if the page doesn't exist.
    pub fn get_mut(&mut self, addr: u32) -> Option<&mut V> {
        let (upper, lower) = Self::indices(addr);
        let index = self.index[upper];
        if index == NO_PAGE {
            None
        } else {
            Some(&mut self.page_table[index as usize].0[lower])
        }
    }

    /// Get a mutable reference to the memory value at the given address,
    /// creating the page if it doesn't exist.
    pub fn get_mut_or_create(&mut self, addr: u32) -> &mut V {
        let (upper, lower) = Self::indices(addr);
        let mut index = self.index[upper];
        if index == NO_PAGE {
            index = self.page_table.len() as u16;
            self.index[upper] = index;
            self.page_table.push(NewPage::new());
        }
        &mut self.page_table[index as usize].0[lower]
    }

    /// Insert a value at the given address. Returns the previous value.
    pub fn insert(&mut self, addr: u32, value: V) -> V {
        let (upper, lower) = Self::indices(addr);
        let mut index = self.index[upper];
        if index == NO_PAGE {
            index = self.page_table.len() as u16;
            self.index[upper] = index;
            self.page_table.push(NewPage::new());
        }
        std::mem::replace(&mut self.page_table[index as usize].0[lower], value)
    }

    /// Returns an iterator over addresses in allocated pages.
    pub fn keys(&self) -> impl Iterator<Item = u32> + '_ {
        self.index
            .iter()
            .enumerate()
            .filter(|(_, &i)| i != NO_PAGE)
            .flat_map(|(i, index)| {
                let upper = i << LOG_PAGE_LEN;
                self.page_table[*index as usize]
                    .0
                    .iter()
                    .enumerate()
                    .map(move |(lower, _)| Self::decompress_addr(upper + lower))
            })
    }

    /// Get the number of slots in allocated pages.
    pub fn exact_len(&self) -> usize {
        self.index
            .iter()
            .filter(|&&i| i != NO_PAGE)
            .map(|index| self.page_table[*index as usize].0.len())
            .sum()
    }

    /// Estimate the number of addresses in use.
    pub fn estimate_len(&self) -> usize {
        self.index.iter().filter(|&i| *i != NO_PAGE).count() * PAGE_LEN
    }

    /// Clears the page table. Drops all `Page`s, but retains the memory used by the table itself.
    pub fn clear(&mut self) {
        self.page_table.clear();
        self.index.fill(NO_PAGE);
    }

    /// Break apart an address into an upper and lower index.
    #[inline]
    const fn indices(addr: u32) -> (usize, usize) {
        let index = Self::compress_addr(addr);
        (index >> LOG_PAGE_LEN, index & PAGE_MASK)
    }

    /// Compress an address from the sparse address space to a contiguous space.
    #[inline]
    const fn compress_addr(addr: u32) -> usize {
        addr as usize >> Self::NUM_IGNORED_LOWER_BITS
    }

    /// Decompress an address from a contiguous space to the sparse address space.
    #[inline]
    const fn decompress_addr(addr: usize) -> u32 {
        (addr << Self::NUM_IGNORED_LOWER_BITS) as u32
    }
}

impl<V: Copy + Default> Default for PagedMemory<V> {
    fn default() -> Self {
        Self {
            page_table: Vec::new(),
            index: vec![NO_PAGE; MAX_PAGE_COUNT],
        }
    }
}

impl<V: Copy + Default> FromIterator<(u32, V)> for PagedMemory<V> {
    fn from_iter<T: IntoIterator<Item = (u32, V)>>(iter: T) -> Self {
        let mut mmu = Self::new_preallocated();
        for (k, v) in iter {
            mmu.insert(k, v);
        }
        mmu
    }
}

impl<V: Copy + Default + 'static> IntoIterator for PagedMemory<V> {
    type Item = (u32, V);

    type IntoIter = Box<dyn Iterator<Item = Self::Item>>;

    fn into_iter(mut self) -> Self::IntoIter {
        Box::new(
            self.index
                .into_iter()
                .enumerate()
                .filter(|(_, i)| *i != NO_PAGE)
                .flat_map(move |(i, index)| {
                    let upper = i << LOG_PAGE_LEN;
                    std::mem::take(&mut self.page_table[index as usize])
                        .0
                        .into_iter()
                        .enumerate()
                        .map(move |(lower, v)| (Self::decompress_addr(upper + lower), v))
                }),
        )
    }
}
