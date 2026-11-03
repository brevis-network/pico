/// Storage backend for values (u8 array).
///
/// Provides two implementations:
///
/// - Box-based (default): Uses `Box<[u8]>` for heap allocation
/// - Mmap-based (feature "mmap-memory"): Uses anonymous mmap with fast reset via madvise
///
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

/// Box-based storage for packed metadata (default implementation).
///
/// Each dword's `(chunk: u32, timestamp: u32)` pair is interleaved into a single `u64`
/// (chunk in the low 32 bits, timestamp in the high 32 bits), so the formerly-separate
/// `MetadataChunkStorage` + `MetadataTimestampStorage` arrays become one `u64` array. This
/// co-locates each dword's metadata on a single cache line (one access touches one line
/// instead of two parallel arrays) at identical total byte size (`size * 8`).
#[cfg(not(feature = "mmap-memory"))]
pub struct MetadataStorage {
    data: Box<[u64]>,
}

#[cfg(not(feature = "mmap-memory"))]
impl MetadataStorage {
    /// Create a new storage with the given number of dword-metadata slots, initialized to zero.
    pub fn new(size: usize) -> Self {
        Self {
            data: vec![0u64; size].into_boxed_slice(),
        }
    }

    /// Get a raw mutable pointer to the data.
    #[inline(always)]
    pub fn as_mut_ptr(&mut self) -> *mut u64 {
        self.data.as_mut_ptr()
    }

    /// Get the length of the storage (number of packed u64 slots).
    #[inline(always)]
    pub fn len(&self) -> usize {
        self.data.len()
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

#[cfg(feature = "mmap-memory")]
struct MmapStorage(MmapMut);

#[cfg(feature = "mmap-memory")]
impl MmapStorage {
    fn anonymous(byte_len: usize, label: &str) -> Self {
        Self(
            MmapMut::map_anon(byte_len)
                .unwrap_or_else(|_| panic!("Failed to create anonymous mmap for {label}")),
        )
    }

    fn as_slice(&self) -> &[u8] {
        &self.0
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.0
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr()
    }

    fn len(&self) -> usize {
        self.0.len()
    }
}

#[cfg(feature = "mmap-memory")]
impl Clone for MmapStorage {
    fn clone(&self) -> Self {
        let mut clone =
            Self(MmapMut::map_anon(self.0.len()).expect("Failed to clone anonymous mmap"));
        clone.as_mut_slice().copy_from_slice(self.as_slice());
        clone
    }
}

#[cfg(feature = "mmap-memory")]
pub struct ValuesStorage {
    inner: MmapStorage,
}

#[cfg(feature = "mmap-memory")]
impl ValuesStorage {
    pub fn new(size: usize) -> Self {
        Self {
            inner: MmapStorage::anonymous(size, "values"),
        }
    }

    #[inline(always)]
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.inner.as_mut_ptr()
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    #[inline(always)]
    pub fn as_slice(&self) -> &[u8] {
        self.inner.as_slice()
    }

    #[inline(always)]
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        self.inner.as_mut_slice()
    }
}

#[cfg(feature = "mmap-memory")]
impl Clone for ValuesStorage {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

#[cfg(feature = "mmap-memory")]
pub struct MetadataStorage {
    inner: MmapStorage,
    len: usize,
}

#[cfg(feature = "mmap-memory")]
impl MetadataStorage {
    pub fn new(size: usize) -> Self {
        let byte_size = size * std::mem::size_of::<u64>();
        Self {
            inner: MmapStorage::anonymous(byte_size, "metadata"),
            len: size,
        }
    }

    #[inline(always)]
    pub fn as_mut_ptr(&mut self) -> *mut u64 {
        self.inner.as_mut_ptr() as *mut u64
    }

    #[inline(always)]
    pub fn len(&self) -> usize {
        self.len
    }

    #[inline(always)]
    pub fn as_slice(&self) -> &[u64] {
        unsafe {
            std::slice::from_raw_parts(self.inner.as_slice().as_ptr() as *const u64, self.len)
        }
    }

    #[inline(always)]
    pub fn as_mut_slice(&mut self) -> &mut [u64] {
        unsafe { std::slice::from_raw_parts_mut(self.inner.as_mut_ptr() as *mut u64, self.len) }
    }
}

#[cfg(feature = "mmap-memory")]
impl Clone for MetadataStorage {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            len: self.len,
        }
    }
}
