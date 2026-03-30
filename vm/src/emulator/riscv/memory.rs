use p3_maybe_rayon::prelude::{IndexedParallelIterator, ParallelIterator, ParallelSlice};
use serde::{
    de::{DeserializeOwned, SeqAccess, Visitor},
    ser::SerializeSeq,
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::{fmt, hash::Hash};
use vec_map::VecMap;

use crate::{
    chips::chips::riscv_memory::event::MemoryRecord,
    emulator::riscv::event_types::{RvAddr, RvChunk, RvTimestamp, RvValue},
};

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

    /// Box-based storage for metadata chunk values (default implementation).
    #[cfg(not(feature = "mmap-memory"))]
    pub struct MetadataChunkStorage {
        data: Box<[u32]>,
    }

    #[cfg(not(feature = "mmap-memory"))]
    impl MetadataChunkStorage {
        /// Create a new storage with the given size, initialized to zero.
        pub fn new(size: usize) -> Self {
            Self {
                data: vec![0u32; size].into_boxed_slice(),
            }
        }

        /// Reset all entries to zero.
        #[inline]
        pub fn reset(&mut self) {
            self.data.fill(0);
        }

        /// Get a raw mutable pointer to the data.
        #[inline(always)]
        pub fn as_mut_ptr(&mut self) -> *mut u32 {
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
        pub fn as_slice(&self) -> &[u32] {
            &self.data
        }

        /// Get the underlying mutable slice.
        #[inline(always)]
        pub fn as_mut_slice(&mut self) -> &mut [u32] {
            &mut self.data
        }
    }

    #[cfg(not(feature = "mmap-memory"))]
    impl Clone for MetadataChunkStorage {
        fn clone(&self) -> Self {
            Self {
                data: self.data.clone(),
            }
        }
    }

    /// Box-based storage for metadata timestamps (default implementation).
    #[cfg(not(feature = "mmap-memory"))]
    pub struct MetadataTimestampStorage {
        data: Box<[u32]>,
    }

    #[cfg(not(feature = "mmap-memory"))]
    impl MetadataTimestampStorage {
        /// Create a new storage with the given size, initialized to zero.
        pub fn new(size: usize) -> Self {
            Self {
                data: vec![0u32; size].into_boxed_slice(),
            }
        }

        /// Reset all entries to zero.
        #[inline]
        pub fn reset(&mut self) {
            self.data.fill(0);
        }

        /// Get a raw mutable pointer to the data.
        #[inline(always)]
        pub fn as_mut_ptr(&mut self) -> *mut u32 {
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
        pub fn as_slice(&self) -> &[u32] {
            &self.data
        }

        /// Get the underlying mutable slice.
        #[inline(always)]
        pub fn as_mut_slice(&mut self) -> &mut [u32] {
            &mut self.data
        }
    }

    #[cfg(not(feature = "mmap-memory"))]
    impl Clone for MetadataTimestampStorage {
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

    /// Mmap-based storage for metadata chunks.
    #[cfg(feature = "mmap-memory")]
    pub struct MetadataChunkStorage {
        mmap: MmapMut,
        /// Number of u32 entries (mmap.len() / 4).
        len: usize,
    }

    #[cfg(feature = "mmap-memory")]
    impl MetadataChunkStorage {
        /// Create a new mmap-backed storage with the given number of u32 entries.
        pub fn new(size: usize) -> Self {
            let byte_size = size * std::mem::size_of::<u32>();
            let mmap = MmapMut::map_anon(byte_size)
                .expect("Failed to create anonymous mmap for metadata chunks");
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

        /// Get a raw mutable pointer to the data as u32.
        #[inline(always)]
        pub fn as_mut_ptr(&mut self) -> *mut u32 {
            self.mmap.as_mut_ptr() as *mut u32
        }

        /// Get the number of u32 entries.
        #[inline(always)]
        pub fn len(&self) -> usize {
            self.len
        }

        /// Returns true if the storage contains no elements.
        #[inline(always)]
        pub fn is_empty(&self) -> bool {
            self.len == 0
        }

        /// Get the underlying slice as u32.
        #[inline(always)]
        pub fn as_slice(&self) -> &[u32] {
            unsafe { std::slice::from_raw_parts(self.mmap.as_ptr() as *const u32, self.len) }
        }

        /// Get the underlying mutable slice as u32.
        #[inline(always)]
        pub fn as_mut_slice(&mut self) -> &mut [u32] {
            unsafe { std::slice::from_raw_parts_mut(self.mmap.as_mut_ptr() as *mut u32, self.len) }
        }
    }

    #[cfg(feature = "mmap-memory")]
    impl Clone for MetadataChunkStorage {
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

    /// Mmap-based storage for metadata timestamps.
    #[cfg(feature = "mmap-memory")]
    pub struct MetadataTimestampStorage {
        mmap: MmapMut,
        /// Number of u32 entries (mmap.len() / 4).
        len: usize,
    }

    #[cfg(feature = "mmap-memory")]
    impl MetadataTimestampStorage {
        /// Create a new mmap-backed storage with the given number of u32 entries.
        pub fn new(size: usize) -> Self {
            let byte_size = size * std::mem::size_of::<u32>();
            let mmap = MmapMut::map_anon(byte_size)
                .expect("Failed to create anonymous mmap for metadata timestamps");
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

        /// Get a raw mutable pointer to the data as u32.
        #[inline(always)]
        pub fn as_mut_ptr(&mut self) -> *mut u32 {
            self.mmap.as_mut_ptr() as *mut u32
        }

        /// Get the number of u32 entries.
        #[inline(always)]
        pub fn len(&self) -> usize {
            self.len
        }

        /// Returns true if the storage contains no elements.
        #[inline(always)]
        pub fn is_empty(&self) -> bool {
            self.len == 0
        }

        /// Get the underlying slice as u32.
        #[inline(always)]
        pub fn as_slice(&self) -> &[u32] {
            unsafe { std::slice::from_raw_parts(self.mmap.as_ptr() as *const u32, self.len) }
        }

        /// Get the underlying mutable slice as u32.
        #[inline(always)]
        pub fn as_mut_slice(&mut self) -> &mut [u32] {
            unsafe { std::slice::from_raw_parts_mut(self.mmap.as_mut_ptr() as *mut u32, self.len) }
        }
    }

    #[cfg(feature = "mmap-memory")]
    impl Clone for MetadataTimestampStorage {
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

use storage::{MetadataChunkStorage, MetadataTimestampStorage, ValuesStorage};

// ============================================================================
// ContiguousRiscvMemory - High-performance unified memory model
// ============================================================================

// Bitmap size calculation:
// SDK max memory (0x7800_0000 bytes) / 8 (bytes per dword) / 64 (bits per u64).
// This yields 4,096,256 (0x3E8000) u64 entries (~32MB).
const BITMAP_SIZE_U64: usize = (VALUES_SIZE >> 3) >> 6;

/// A contiguous SDK-limited memory model for high-performance RISC-V emulation.
///
/// This memory model uses a flat SDK-limited address space where:
/// - `values`: A contiguous storage of size 0x7800_0000 (~2GB) for storing actual data.
///   - The range is byte-addressed main memory.
/// - `metadata_chunk`: A contiguous `u32` storage of size (VALUES_SIZE >> 3) for chunks.
/// - `metadata_timestamp`: A contiguous `u32` storage of size (VALUES_SIZE >> 3) for timestamps.
///
/// Metadata mapping: Each 8-byte dword at address `addr` has metadata at index `addr >> 3`.
/// The two arrays store `(chunk, timestamp)` in parallel at that same index.
///
/// ## Storage Backend
///
/// The storage backend is selected at compile time via feature flags:
/// - **Default**: Uses `Box<[u8]>` / `Box<[u32]>` / `Box<[u32]>` for heap allocation.
/// - **`mmap-memory` feature (Unix only)**: Uses anonymous mmap with fast reset
///   via `madvise(MADV_DONTNEED)`.
///
/// To enable mmap-based storage, compile with:
/// ```bash
/// cargo build --features mmap-memory
/// ```
pub struct ContiguousRiscvMemory {
    /// Raw byte storage for the SDK-limited address space.
    values: ValuesStorage,

    /// Chunk metadata storage: one u32 per 8-byte dword.
    /// Index = addr >> 3.
    metadata_chunk: MetadataChunkStorage,

    /// Timestamp metadata storage: one u32 per 8-byte dword.
    /// Index = addr >> 3.
    metadata_timestamp: MetadataTimestampStorage,

    /// Tracks accessed addresses for iteration in postprocess.
    /// This is a compatibility feature to support existing code patterns.
    accessed_bitmap: Box<[u64]>,
}

/// Size of the values array (SDK limit, ~2GB).
pub const VALUES_SIZE: usize = 0x7800_0000;

/// Size of the metadata array (one per 8-byte dword).
pub const METADATA_SIZE: usize = VALUES_SIZE >> 3;

/// Number of registers.
pub const NUM_REGISTERS: u32 = 32;

impl ContiguousRiscvMemory {
    /// Create a new ContiguousRiscvMemory with zeroed values and metadata.
    ///
    /// This allocates ~2GB for values and split metadata arrays:
    /// ~1GB for chunks + ~2GB for timestamps.
    ///
    /// - **Default backend**: Uses `vec![0; size].into_boxed_slice()` for contiguous heap memory.
    /// - **Mmap backend**: Uses anonymous mmap for zero-copy allocation.
    #[must_use]
    pub fn new() -> Self {
        Self {
            values: ValuesStorage::new(VALUES_SIZE),
            metadata_chunk: MetadataChunkStorage::new(METADATA_SIZE),
            metadata_timestamp: MetadataTimestampStorage::new(METADATA_SIZE),
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
            self.metadata_chunk.reset();
            self.metadata_timestamp.reset();
            self.accessed_bitmap.fill(0);
        } else {
            // Smart Reset: Only clear accessed pages
            // 1. Clear registers (always potentially dirty)
            let reg_size = NUM_REGISTERS as usize * 8;
            self.values.as_mut_slice()[..reg_size].fill(0);
            self.metadata_chunk.as_mut_slice()[..NUM_REGISTERS as usize].fill(0);
            self.metadata_timestamp.as_mut_slice()[..NUM_REGISTERS as usize].fill(0);

            // 2. Clear accessed memory ranges
            for (vec_idx, &bits) in self.accessed_bitmap.iter().enumerate() {
                if bits == 0 {
                    continue;
                }

                // Each bits (u64) covers 64 * 8 = 512 bytes
                let base_addr = vec_idx << 9;
                let values_slice = self.values.as_mut_slice();
                let metadata_chunk_slice = self.metadata_chunk.as_mut_slice();
                let metadata_timestamp_slice = self.metadata_timestamp.as_mut_slice();

                // Optimization: just zero the whole block covered by the u64 bitmap entry (512 bytes)
                // This is faster than bit-twiddling for individual dwords when resetting.
                let end_addr = base_addr + 512;

                // Safety bound check (though logic guarantees bounds)
                if end_addr <= values_slice.len() {
                    values_slice[base_addr..end_addr].fill(0);
                }

                // Metadata: per 8-byte dword, 1 chunk + 1 timestamp entry.
                // For a 512-byte block, that is 64 metadata entries.
                // Index = addr >> 3
                let meta_start = base_addr >> 3;
                let meta_end = meta_start + 64;
                if meta_end <= metadata_chunk_slice.len() {
                    metadata_chunk_slice[meta_start..meta_end].fill(0);
                    metadata_timestamp_slice[meta_start..meta_end].fill(0);
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
    /// Get a raw pointer to the metadata chunk array.
    #[inline(always)]
    pub fn metadata_chunk_ptr(&mut self) -> *mut u32 {
        self.metadata_chunk.as_mut_ptr()
    }

    /// Get a raw pointer to the metadata timestamp array.
    #[inline(always)]
    pub fn metadata_timestamp_ptr(&mut self) -> *mut u32 {
        self.metadata_timestamp.as_mut_ptr()
    }

    /// Returns true if this memory instance uses mmap-based storage.
    #[inline(always)]
    pub const fn is_mmap_backed() -> bool {
        cfg!(feature = "mmap-memory")
    }
}

// Implement Debug manually to avoid printing large memory buffers
impl std::fmt::Debug for ContiguousRiscvMemory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ContiguousRiscvMemory")
            .field("values_size", &self.values.len())
            .field("metadata_chunk_size", &self.metadata_chunk.len())
            .field("metadata_timestamp_size", &self.metadata_timestamp.len())
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
            metadata_chunk: self.metadata_chunk.clone(),
            metadata_timestamp: self.metadata_timestamp.clone(),
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

        // Serialize main memory (scan bitmap).
        // Each bit represents one 8-byte dword.
        for (vec_idx, &bits) in self.accessed_bitmap.iter().enumerate() {
            if bits == 0 {
                continue;
            }

            // Base Address = vec_idx * 64 dwords * 8 bytes/dword = vec_idx << 9
            let base_addr = (vec_idx as u64) << 9;

            let mut temp_bits = bits;
            while temp_bits != 0 {
                let bit_offset = temp_bits.trailing_zeros();

                // Addr = Base + (Offset * 8)
                let addr_u64 = base_addr + ((bit_offset << 3) as u64);
                let value = self.peek_dword(addr_u64);
                let (chunk, timestamp) = self.peek_metadata(addr_u64);
                non_zero_entries.push((addr_u64, value, chunk, timestamp));

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
                while let Some((addr, value, chunk, timestamp)) =
                    seq.next_element::<(u64, u64, u32, u32)>()?
                {
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

        // Insert some test data at 8-byte-aligned addresses
        memory.insert(
            0x100,
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
            deserialized.get(0x100),
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
            deserialized.get(96),
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

        // Verify byte-address contract (dword containing byte 8 is addr 8).
        memory.insert(
            8,
            MemoryRecord {
                value: 42,
                chunk: 1,
                timestamp: 1,
            },
        );
        assert!(
            memory.has_accessed(8),
            "has_accessed expects byte addresses"
        );
    }

    #[test]
    fn test_dword_access_near_upper_bound() {
        let mut memory = ContiguousRiscvMemory::new();
        let addr = (VALUES_SIZE - 8) as u64;
        memory.write_dword(addr, 0xAABB_CCDD_1122_3344, 7, 11);
        assert_eq!(memory.peek_dword(addr), 0xAABB_CCDD_1122_3344);
        assert_eq!(memory.peek_metadata(addr), (7, 11));
    }

    #[test]
    fn test_metadata_roundtrip_preserves_max_u32_timestamp() {
        let mut memory = ContiguousRiscvMemory::new();
        let addr = 0x1000u64;
        let ts = u32::MAX;
        memory.write_dword(addr, 0xAABB_CCDD_1122_3344, 7, ts);
        assert_eq!(memory.peek_metadata(addr), (7, ts));
    }

    #[test]
    fn test_metadata_update_preserves_prev_timestamp() {
        let mut memory = ContiguousRiscvMemory::new();
        let addr = 0x2000u64;
        let prev_ts = u32::MAX - 155;
        memory.write_dword(addr, 0x1122_3344_5566_7788, 2, prev_ts);

        let (_v, prev_chunk, got_prev_ts) = memory.read_and_update_metadata(addr, 3, prev_ts + 100);
        assert_eq!(prev_chunk, 2);
        assert_eq!(got_prev_ts, prev_ts);
    }

    #[test]
    fn test_par_restore_preserves_timestamp() {
        let mut src = ContiguousRiscvMemory::new();
        let mut dst = ContiguousRiscvMemory::new();
        let addr = 0x4000u64;
        let ts = u32::MAX - 777;

        src.insert(
            addr,
            MemoryRecord {
                value: 0xDEAD_BEEF,
                chunk: 9,
                timestamp: ts,
            },
        );
        dst.par_restore_from(&src);

        assert_eq!(dst.get(addr).timestamp, ts);
        assert_eq!(dst.get(addr).chunk, 9);
        assert_eq!(dst.get(addr).value, 0xDEAD_BEEF);
    }

    #[test]
    #[should_panic(expected = "dword address out of range")]
    fn test_dword_access_out_of_range_panics() {
        let mut memory = ContiguousRiscvMemory::new();
        memory.write_dword(VALUES_SIZE as u64, 1, 0, 0);
    }

    #[test]
    fn test_dword_insert_and_get() {
        let mut memory = ContiguousRiscvMemory::new();

        let mem_addr = 0x1000u64;
        let mem_record = MemoryRecord {
            value: 0xDEAD_BEEF_CAFE_BABE,
            chunk: 9,
            timestamp: 10,
        };
        memory.insert(mem_addr, mem_record);
        assert_eq!(memory.peek_dword(mem_addr), mem_record.value);
        assert_eq!(memory.get(mem_addr), mem_record);
    }

    #[test]
    fn test_memory32_parity_insert_get() {
        let mut memory: Memory32<u32> = Memory::new_preallocated();
        memory.insert(0, 11);
        memory.insert(4, 22);
        assert_eq!(memory.get(0), Some(&11));
        assert_eq!(memory.get(4), Some(&22));
    }

    #[test]
    fn test_memory64_high_address_path() {
        let mut memory: Memory64<u32> = Memory::new_preallocated();

        let high_addr = 0x1_0000_0000u64;
        memory.insert(high_addr, 0xCAFE_BABE);
        memory.insert(high_addr + 0x1000, 0xDEAD_BEEF);

        assert_eq!(memory.get(high_addr), Some(&0xCAFE_BABE));
        assert_eq!(memory.get(high_addr + 0x1000), Some(&0xDEAD_BEEF));
    }

    #[test]
    fn test_memory64_register_path_uses_low_addresses() {
        let mut memory: Memory64<u32> = Memory::new_preallocated();
        memory.insert(5, 0x1234_5678);
        assert_eq!(memory.get(5), Some(&0x1234_5678));
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
    // Dword (8-byte) operations
    // ------------------------------------------------------------------------

    /// Read a dword (8 bytes) from the given 8-byte-aligned address without modifying metadata.
    #[inline(always)]
    pub fn peek_dword(&self, addr: RvAddr) -> RvValue {
        let addr = Self::guest_addr_to_usize_for_dword(addr);
        let ptr = self.values.as_slice().as_ptr();
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
        let ptr = self.values.as_mut_ptr();
        unsafe {
            std::ptr::write_unaligned(ptr.add(byte_addr) as *mut u64, value);
        }
        let idx = byte_addr >> 3;
        let metadata_chunk = self.metadata_chunk.as_mut_slice();
        let metadata_timestamp = self.metadata_timestamp.as_mut_slice();
        unsafe {
            *metadata_chunk.get_unchecked_mut(idx) = chunk;
            *metadata_timestamp.get_unchecked_mut(idx) = timestamp;
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
        let ptr = self.values.as_slice().as_ptr();
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
        let metadata_chunk = self.metadata_chunk.as_mut_slice();
        let metadata_timestamp = self.metadata_timestamp.as_mut_slice();
        unsafe {
            *metadata_chunk.get_unchecked_mut(idx) = new_chunk;
            *metadata_timestamp.get_unchecked_mut(idx) = new_timestamp;
        }
        value
    }

    /// Read metadata for the dword containing the given address.
    /// Returns (chunk, timestamp).
    #[inline(always)]
    pub fn peek_metadata(&self, addr: RvAddr) -> (RvChunk, RvTimestamp) {
        let idx = Self::guest_addr_to_dword_index(addr);
        let metadata_chunk = self.metadata_chunk.as_slice();
        let metadata_timestamp = self.metadata_timestamp.as_slice();
        unsafe {
            (
                *metadata_chunk.get_unchecked(idx),
                *metadata_timestamp.get_unchecked(idx),
            )
        }
    }

    /// Write a word (4 bytes) to the given address and update the containing dword's metadata.
    /// Uses Little Endian byte order.
    #[inline(always)]
    pub fn write_word(&mut self, addr: RvAddr, value: u32, chunk: RvChunk, timestamp: RvTimestamp) {
        let byte_addr = Self::guest_addr_to_usize_for_word(addr);
        let ptr = self.values.as_mut_ptr();
        unsafe {
            std::ptr::write_unaligned(ptr.add(byte_addr) as *mut u32, value);
        }
        let idx = byte_addr >> 3;
        let metadata_chunk = self.metadata_chunk.as_mut_slice();
        let metadata_timestamp = self.metadata_timestamp.as_mut_slice();
        unsafe {
            *metadata_chunk.get_unchecked_mut(idx) = chunk;
            *metadata_timestamp.get_unchecked_mut(idx) = timestamp;
        }
    }

    // ------------------------------------------------------------------------
    // Byte operations
    // ------------------------------------------------------------------------

    /// Read a single byte without modifying metadata.
    #[inline(always)]
    pub fn peek_byte(&self, addr: RvAddr) -> u8 {
        let addr = Self::guest_addr_to_usize(addr);
        let values = self.values.as_slice();
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
        let metadata_chunk = self.metadata_chunk.as_mut_slice();
        let metadata_timestamp = self.metadata_timestamp.as_mut_slice();
        // SAFETY: idx is at most 2^30 - 1, which is within bounds.
        unsafe {
            *metadata_chunk.get_unchecked_mut(idx) = new_chunk;
            *metadata_timestamp.get_unchecked_mut(idx) = new_timestamp;
        }
        value
    }

    /// Write a single byte and update the containing dword's metadata.
    #[inline(always)]
    pub fn write_byte(&mut self, addr: RvAddr, value: u8, chunk: RvChunk, timestamp: RvTimestamp) {
        let addr = Self::guest_addr_to_usize(addr);
        let values = self.values.as_mut_slice();
        unsafe {
            *values.get_unchecked_mut(addr) = value;
        }
        // Update metadata for the containing dword.
        let idx = addr >> 3;
        let metadata_chunk = self.metadata_chunk.as_mut_slice();
        let metadata_timestamp = self.metadata_timestamp.as_mut_slice();
        // SAFETY: idx is at most 2^30 - 1, which is within bounds.
        unsafe {
            *metadata_chunk.get_unchecked_mut(idx) = chunk;
            *metadata_timestamp.get_unchecked_mut(idx) = timestamp;
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
        let metadata_chunk = self.metadata_chunk.as_mut_slice();
        let metadata_timestamp = self.metadata_timestamp.as_mut_slice();
        unsafe {
            *metadata_chunk.get_unchecked_mut(idx) = new_chunk;
            *metadata_timestamp.get_unchecked_mut(idx) = new_timestamp;
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
        let ptr = self.values.as_mut_ptr();
        unsafe {
            std::ptr::write_unaligned(ptr.add(addr) as *mut u64, value);
        }
    }

    /// Set just the metadata at addr (uses dword index: addr >> 3).
    #[inline(always)]
    pub fn set_metadata(&mut self, addr: RvAddr, chunk: RvChunk, timestamp: RvTimestamp) {
        let idx = Self::guest_addr_to_dword_index(addr);
        let metadata_chunk = self.metadata_chunk.as_mut_slice();
        let metadata_timestamp = self.metadata_timestamp.as_mut_slice();
        unsafe {
            *metadata_chunk.get_unchecked_mut(idx) = chunk;
            *metadata_timestamp.get_unchecked_mut(idx) = timestamp;
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
        let self_values_ptr = self.values.as_mut_ptr() as usize;
        let self_metadata_chunk_ptr = self.metadata_chunk.as_mut_ptr() as usize;
        let self_metadata_timestamp_ptr = self.metadata_timestamp.as_mut_ptr() as usize;

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
                            let chunk_ptr = (self_metadata_chunk_ptr as *mut u32).add(m_idx);
                            let timestamp_ptr =
                                (self_metadata_timestamp_ptr as *mut u32).add(m_idx);
                            *chunk_ptr = chunk;
                            *timestamp_ptr = ts;
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
    memory: &'a mut ContiguousRiscvMemory,
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
// ============================================================================
// Legacy paged memory implementation (used by uninitialized_memory)
// ============================================================================

pub trait Addr: Copy + Eq + Hash {
    fn to_usize(self) -> usize;
    fn from_usize(value: usize) -> Self;
}

impl Addr for u32 {
    fn to_usize(self) -> usize {
        self as usize
    }

    fn from_usize(value: usize) -> Self {
        u32::try_from(value).unwrap_or_else(|_| panic!("address index {value} does not fit in u32"))
    }
}

impl Addr for u64 {
    fn to_usize(self) -> usize {
        usize::try_from(self)
            .unwrap_or_else(|_| panic!("address 0x{self:016x} does not fit in usize"))
    }

    fn from_usize(value: usize) -> Self {
        value as u64
    }
}

/// A memory.
///
/// Consists of registers, as well as a page table for main memory.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(serialize = "A: Serialize, V: Serialize"))]
#[serde(bound(deserialize = "A: DeserializeOwned, V: DeserializeOwned"))]
pub struct Memory<A: Addr, V: Copy + Default> {
    /// The registers.
    pub registers: Registers<V>,
    /// The page table.
    pub page_table: PagedMemory<A, V>,
}

pub type Memory32<V> = Memory<u32, V>;
pub type Memory64<V> = Memory<u64, V>;
pub type PagedMemory32<V> = PagedMemory<u32, V>;
pub type PagedMemory64<V> = PagedMemory<u64, V>;

impl<A: Addr + 'static, V: Copy + Default + 'static> IntoIterator for Memory<A, V> {
    type Item = (A, V);

    type IntoIter = Box<dyn Iterator<Item = Self::Item>>;

    fn into_iter(self) -> Self::IntoIter {
        let reg_iter = self
            .registers
            .into_iter()
            .map(|(addr, value)| (A::from_usize(addr as usize), value));
        Box::new(reg_iter.chain(self.page_table))
    }
}

impl<A: Addr, V: Copy + Default> Default for Memory<A, V> {
    fn default() -> Self {
        Self {
            registers: Registers::default(),
            page_table: PagedMemory::default(),
        }
    }
}

impl<A: Addr, V: Copy + Default> Memory<A, V> {
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
    pub fn insert(&mut self, addr: A, value: V) -> V {
        if addr.to_usize() < 32 {
            self.registers.insert(addr, value)
        } else {
            self.page_table.insert(addr, value)
        }
    }

    /// Get a value from the memory.
    ///
    /// Returns None only if it's a page table address and the page doesn't exist.
    /// When possible, prefer directly accessing the `page_table` or `registers` fields.
    /// This method often incurs unnecessary branching.
    #[inline]
    pub fn get(&self, addr: A) -> Option<&V> {
        if addr.to_usize() < 32 {
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
    pub fn get_mut_or_create(&mut self, addr: A) -> &mut V {
        if addr.to_usize() < 32 {
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

impl<A: Addr, V: Copy + Default> FromIterator<(A, V)> for Memory<A, V> {
    fn from_iter<T: IntoIterator<Item = (A, V)>>(iter: T) -> Self {
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
    pub fn get<A: Addr>(&self, addr: A) -> &T {
        &self.registers[addr.to_usize()]
    }

    /// Get a mutable reference to the value at the given address.
    ///
    /// Assumes addr < 32.
    #[inline]
    pub fn get_mut<A: Addr>(&mut self, addr: A) -> &mut T {
        &mut self.registers[addr.to_usize()]
    }

    /// Insert a value into the registers.
    ///
    /// Assumes addr < 32.
    #[inline]
    pub fn insert<A: Addr>(&mut self, addr: A, value: T) -> T {
        std::mem::replace(&mut self.registers[addr.to_usize()], value)
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
#[serde(bound(serialize = "A: Serialize, V: Serialize"))]
#[serde(bound(deserialize = "A: DeserializeOwned, V: DeserializeOwned"))]
pub struct PagedMemory<A: Addr, V: Copy + Default> {
    /// The internal page table.
    pub page_table: Vec<NewPage<V>>,
    pub index: hashbrown::HashMap<usize, u16>,
    #[serde(skip)]
    _marker: core::marker::PhantomData<A>,
}

impl<A: Addr, V: Copy + Default> PagedMemory<A, V> {
    /// The number of lower bits to ignore, since addresses (except registers) are a multiple of 4.
    const NUM_IGNORED_LOWER_BITS: usize = 2;

    /// Create a `PagedMemory`.
    pub fn new_preallocated() -> Self {
        Self {
            page_table: Vec::new(),
            index: hashbrown::HashMap::new(),
            _marker: core::marker::PhantomData,
        }
    }

    /// Get a reference to the memory value at the given address.
    /// Returns None if the page doesn't exist.
    pub fn get(&self, addr: A) -> Option<&V> {
        let (upper, lower) = Self::indices(addr);
        self.index
            .get(&upper)
            .map(|index| &self.page_table[*index as usize].0[lower])
    }

    /// Get a mutable reference to the memory value at the given address.
    /// Returns None if the page doesn't exist.
    pub fn get_mut(&mut self, addr: A) -> Option<&mut V> {
        let (upper, lower) = Self::indices(addr);
        self.index
            .get(&upper)
            .map(|index| &mut self.page_table[*index as usize].0[lower])
    }

    /// Get a mutable reference to the memory value at the given address,
    /// creating the page if it doesn't exist.
    pub fn get_mut_or_create(&mut self, addr: A) -> &mut V {
        let (upper, lower) = Self::indices(addr);
        let mut index = self.index.get(&upper).copied().unwrap_or(u16::MAX);
        if index == u16::MAX {
            index = self.page_table.len() as u16;
            self.index.insert(upper, index);
            self.page_table.push(NewPage::new());
        }
        &mut self.page_table[index as usize].0[lower]
    }

    /// Insert a value at the given address. Returns the previous value.
    pub fn insert(&mut self, addr: A, value: V) -> V {
        let (upper, lower) = Self::indices(addr);
        let mut index = self.index.get(&upper).copied().unwrap_or(u16::MAX);
        if index == u16::MAX {
            index = self.page_table.len() as u16;
            self.index.insert(upper, index);
            self.page_table.push(NewPage::new());
        }
        std::mem::replace(&mut self.page_table[index as usize].0[lower], value)
    }

    /// Returns an iterator over addresses in allocated pages.
    pub fn keys(&self) -> impl Iterator<Item = A> + '_ {
        self.index.iter().flat_map(|(i, index)| {
            let upper = *i << LOG_PAGE_LEN;
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
            .map(|index| self.page_table[*index.1 as usize].0.len())
            .sum()
    }

    /// Estimate the number of addresses in use.
    pub fn estimate_len(&self) -> usize {
        self.index.len() * PAGE_LEN
    }

    /// Clears the page table. Drops all `Page`s, but retains the memory used by the table itself.
    pub fn clear(&mut self) {
        self.page_table.clear();
        self.index.clear();
    }

    /// Break apart an address into an upper and lower index.
    #[inline]
    fn indices(addr: A) -> (usize, usize) {
        let index = Self::compress_addr(addr);
        (index >> LOG_PAGE_LEN, index & PAGE_MASK)
    }

    /// Compress an address from the sparse address space to a contiguous space.
    #[inline]
    fn compress_addr(addr: A) -> usize {
        addr.to_usize() >> Self::NUM_IGNORED_LOWER_BITS
    }

    /// Decompress an address from a contiguous space to the sparse address space.
    #[inline]
    fn decompress_addr(addr: usize) -> A {
        A::from_usize(addr << Self::NUM_IGNORED_LOWER_BITS)
    }
}

impl<A: Addr, V: Copy + Default> Default for PagedMemory<A, V> {
    fn default() -> Self {
        Self {
            page_table: Vec::new(),
            index: hashbrown::HashMap::new(),
            _marker: core::marker::PhantomData,
        }
    }
}

impl<A: Addr, V: Copy + Default> FromIterator<(A, V)> for PagedMemory<A, V> {
    fn from_iter<T: IntoIterator<Item = (A, V)>>(iter: T) -> Self {
        let mut mmu = Self::new_preallocated();
        for (k, v) in iter {
            mmu.insert(k, v);
        }
        mmu
    }
}

impl<A: Addr + 'static, V: Copy + Default + 'static> IntoIterator for PagedMemory<A, V> {
    type Item = (A, V);

    type IntoIter = Box<dyn Iterator<Item = Self::Item>>;

    fn into_iter(mut self) -> Self::IntoIter {
        Box::new(self.index.into_iter().flat_map(move |(i, index)| {
            let upper = i << LOG_PAGE_LEN;
            std::mem::take(&mut self.page_table[index as usize])
                .0
                .into_iter()
                .enumerate()
                .map(move |(lower, v)| (Self::decompress_addr(upper + lower), v))
        }))
    }
}
