use serde::{
    de::{SeqAccess, Visitor},
    ser::SerializeSeq,
    Deserialize, Deserializer, Serialize, Serializer,
};
use std::fmt;

use crate::chips::chips::riscv_memory::event::MemoryRecord;

use super::{
    constants::{BITMAP_SIZE_U64, METADATA_SIZE, NUM_REGISTERS, VALUES_SIZE},
    storage::{MetadataStorage, ValuesStorage},
};

/// A contiguous SDK-limited memory model for high-performance RISC-V emulation.
///
/// This memory model uses a flat SDK-limited address space where:
/// - `values`: A contiguous storage of size 0x7800_0000 (~2GB) for storing actual data.
///   - The range is byte-addressed main memory.
/// - `metadata`: A contiguous `u64` storage of size (VALUES_SIZE >> 3). Each slot packs the
///   dword's `(chunk: u32, timestamp: u32)` — chunk in the low 32 bits, timestamp in the high
///   32 bits. (Previously two parallel `u32` arrays; interleaving them co-locates each dword's
///   metadata on one cache line.)
///
/// Metadata mapping: Each 8-byte dword at address `addr` has metadata at index `addr >> 3`.
///
/// ## Storage Backend
///
/// The storage backend is selected at compile time via feature flags:
/// - **Default**: Uses `Box<[u8]>` / `Box<[u64]>` for heap allocation.
/// - **`mmap-memory` feature (Unix only)**: Uses anonymous mmap storage by default, with an
///   opt-in checkpointable variant for unconstrained-mode CoW.
///
/// To enable mmap-based storage, compile with:
/// ```bash
/// cargo build --features mmap-memory
/// ```
#[derive(Clone)]
pub(super) struct MemoryBacking {
    pub(super) values: ValuesStorage,
    /// Packed `(chunk, timestamp)` per dword: low 32 bits = chunk, high 32 bits = timestamp.
    pub(super) metadata: MetadataStorage,
}

#[cfg(feature = "mmap-memory")]
use super::storage;

#[cfg(feature = "mmap-memory")]
#[derive(Debug)]
pub(super) struct MemoryBackingCheckpoint {
    values: storage::ValuesStorageCheckpoint,
    metadata: storage::MetadataStorageCheckpoint,
}

pub struct ContiguousRiscvMemory {
    /// Unified owner for the physical storage of values and metadata.
    pub(super) backing: MemoryBacking,

    /// Tracks accessed addresses for iteration in postprocess.
    /// This is a compatibility feature to support existing code patterns.
    pub(super) accessed_bitmap: Box<[u64]>,
}

#[cfg(feature = "mmap-memory")]
#[derive(Debug)]
pub struct ContiguousMemoryCheckpoint {
    pub(super) backing: MemoryBackingCheckpoint,
}

#[cfg(not(feature = "mmap-memory"))]
#[derive(Debug)]
pub struct ContiguousMemoryCheckpoint {
    pub(super) _private: (),
}

impl MemoryBacking {
    fn new() -> Self {
        Self {
            values: ValuesStorage::new(VALUES_SIZE),
            metadata: MetadataStorage::new(METADATA_SIZE),
        }
    }

    fn new_checkpointable() -> Self {
        Self {
            values: ValuesStorage::new_checkpointable(VALUES_SIZE),
            metadata: MetadataStorage::new_checkpointable(METADATA_SIZE),
        }
    }

    fn supports_cow_checkpoint(&self) -> bool {
        self.values.supports_cow_checkpoint() && self.metadata.supports_cow_checkpoint()
    }

    #[cfg(feature = "mmap-memory")]
    fn fork_cow_checkpoint(&mut self) -> Option<MemoryBackingCheckpoint> {
        let values_cow = self.values.prepare_cow_checkpoint()?;
        let metadata_cow = self.metadata.prepare_cow_checkpoint()?;

        Some(MemoryBackingCheckpoint {
            values: self.values.install_cow_checkpoint(values_cow)?,
            metadata: self.metadata.install_cow_checkpoint(metadata_cow)?,
        })
    }

    #[cfg(feature = "mmap-memory")]
    fn restore_from_checkpoint(&mut self, checkpoint: MemoryBackingCheckpoint) {
        self.values.restore_from_checkpoint(checkpoint.values);
        self.metadata.restore_from_checkpoint(checkpoint.metadata);
    }
}

impl ContiguousRiscvMemory {
    /// Create a new ContiguousRiscvMemory with zeroed values and metadata.
    ///
    /// This allocates ~2GB for values and one packed `u64` metadata array
    /// (`METADATA_SIZE * 8` bytes — same total size as the two former `u32` arrays).
    ///
    /// - **Default backend**: Uses `vec![0; size].into_boxed_slice()` for contiguous heap memory.
    /// - **Mmap backend**: Uses anonymous mmap storage and preserves the existing fast reset path.
    #[must_use]
    pub fn new() -> Self {
        Self {
            backing: MemoryBacking::new(),
            accessed_bitmap: vec![0u64; BITMAP_SIZE_U64].into_boxed_slice(),
        }
    }

    /// Create a memory instance whose backing can be swapped into zero-copy CoW views during
    /// unconstrained execution.
    #[must_use]
    pub fn new_checkpointable() -> Self {
        Self {
            backing: MemoryBacking::new_checkpointable(),
            accessed_bitmap: vec![0u64; BITMAP_SIZE_U64].into_boxed_slice(),
        }
    }

    #[inline(always)]
    pub fn supports_cow_checkpoint(&self) -> bool {
        self.backing.supports_cow_checkpoint()
    }

    #[inline]
    pub fn fork_cow_checkpoint(&mut self) -> Option<ContiguousMemoryCheckpoint> {
        #[cfg(feature = "mmap-memory")]
        {
            Some(ContiguousMemoryCheckpoint {
                backing: self.backing.fork_cow_checkpoint()?,
            })
        }

        #[cfg(not(feature = "mmap-memory"))]
        {
            None
        }
    }

    #[inline]
    pub fn restore_from_checkpoint(&mut self, checkpoint: ContiguousMemoryCheckpoint) {
        #[cfg(feature = "mmap-memory")]
        {
            self.backing.restore_from_checkpoint(checkpoint.backing);
        }

        #[cfg(not(feature = "mmap-memory"))]
        {
            let _ = checkpoint;
        }
    }

    /// Reset the memory by zeroing values and metadata for all tracked pages.
    #[inline]
    pub fn reset(&mut self) {
        // Smart reset works for both box-backed and file-backed memory.
        let reg_size = NUM_REGISTERS as usize * 8;
        self.backing.values.as_mut_slice()[..reg_size].fill(0);
        self.backing.metadata.as_mut_slice()[..NUM_REGISTERS as usize].fill(0);

        // Disjoint field borrows: clear each set bitmap word inline as we scan, instead of
        // an unconditional `accessed_bitmap.fill(0)` over the whole (~31 MB) bitmap afterwards.
        // Semantics are identical (set bits' pages are zeroed and the bit cleared; already-zero
        // words are left zero), but the per-batch `memory_snapshot.clear()` path — which usually
        // operates on an already-clean bitmap — no longer pays a full 31 MB memset every batch.
        let bitmap = &mut self.accessed_bitmap;
        let backing = &mut self.backing;
        let values_slice = backing.values.as_mut_slice();
        let values_len = values_slice.len();
        let metadata_slice = backing.metadata.as_mut_slice();
        let metadata_len = metadata_slice.len();

        for (vec_idx, bits) in bitmap.iter_mut().enumerate() {
            if *bits == 0 {
                continue;
            }

            let base_addr = vec_idx << 9;

            let end_addr = base_addr + 512;
            if end_addr <= values_len {
                values_slice[base_addr..end_addr].fill(0);
            }

            let meta_start = base_addr >> 3;
            let meta_end = meta_start + 64;
            if meta_end <= metadata_len {
                metadata_slice[meta_start..meta_end].fill(0);
            }

            *bits = 0;
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
        self.backing.values.as_mut_ptr()
    }
}
impl ContiguousRiscvMemory {
    /// Returns true if this memory instance uses mmap-based storage.
    #[inline(always)]
    pub const fn is_mmap_backed() -> bool {
        cfg!(feature = "mmap-memory")
    }
}

impl fmt::Debug for ContiguousRiscvMemory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContiguousRiscvMemory")
            .field("values_size", &self.backing.values.len())
            .field("metadata_size", &self.backing.metadata.len())
            .field(
                "accessed_bitmap_size_bytes",
                &(self.accessed_bitmap.len() * 8),
            )
            .field("is_mmap_backed", &Self::is_mmap_backed())
            .finish()
    }
}

impl Clone for ContiguousRiscvMemory {
    fn clone(&self) -> Self {
        Self {
            backing: self.backing.clone(),
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
impl Default for ContiguousRiscvMemory {
    fn default() -> Self {
        Self::new()
    }
}
