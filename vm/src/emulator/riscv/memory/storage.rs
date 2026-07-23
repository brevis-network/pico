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

    /// Compatibility constructor for code paths that request checkpoint-capable storage.
    /// Box-backed storage cannot support CoW checkpoints, so this is identical to `new`.
    pub fn new_checkpointable(size: usize) -> Self {
        Self::new(size)
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

    #[inline(always)]
    pub(crate) const fn supports_cow_checkpoint(&self) -> bool {
        false
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

    /// Compatibility constructor for code paths that request checkpoint-capable storage.
    /// Box-backed storage cannot support CoW checkpoints, so this is identical to `new`.
    pub fn new_checkpointable(size: usize) -> Self {
        Self::new(size)
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

    #[inline(always)]
    pub(crate) const fn supports_cow_checkpoint(&self) -> bool {
        false
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
use memmap2::{MmapMut, MmapOptions};
#[cfg(feature = "mmap-memory")]
use std::{
    fs::{File, OpenOptions},
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

#[cfg(feature = "mmap-memory")]
static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

#[cfg(feature = "mmap-memory")]
fn temp_file_path(label: &str) -> PathBuf {
    let counter = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "pico-{label}-{}-{counter}.mmap",
        std::process::id()
    ))
}

#[cfg(feature = "mmap-memory")]
fn create_temp_backing_file(byte_len: usize, label: &str) -> File {
    let path = temp_file_path(label);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
        .unwrap_or_else(|_| panic!("Failed to create mmap backing file for {label}"));
    file.set_len(byte_len as u64)
        .unwrap_or_else(|_| panic!("Failed to size mmap backing file for {label}"));
    let _ = std::fs::remove_file(path);
    file
}

#[cfg(feature = "mmap-memory")]
fn map_file_mut(file: &File, byte_len: usize, label: &str) -> MmapMut {
    unsafe {
        MmapOptions::new()
            .len(byte_len)
            .map_mut(file)
            .unwrap_or_else(|_| panic!("Failed to create writable mmap for {label}"))
    }
}

#[cfg(feature = "mmap-memory")]
fn map_file_copy(file: &File, byte_len: usize, label: &str) -> Option<MmapMut> {
    let _ = label;
    unsafe { MmapOptions::new().len(byte_len).map_copy(file).ok() }
}

#[cfg(feature = "mmap-memory")]
#[derive(Debug)]
enum MmapStorage {
    Anonymous(MmapMut),
    FileBacked {
        file: File,
        active: MmapMut,
        byte_len: usize,
    },
}

#[cfg(feature = "mmap-memory")]
#[derive(Debug)]
struct FileBackedMmapCheckpoint {
    original: MmapMut,
}

#[cfg(feature = "mmap-memory")]
type PreparedCowMapping = MmapMut;

#[cfg(feature = "mmap-memory")]
impl MmapStorage {
    fn anonymous(byte_len: usize, label: &str) -> Self {
        Self::Anonymous(
            MmapMut::map_anon(byte_len)
                .unwrap_or_else(|_| panic!("Failed to create anonymous mmap for {label}")),
        )
    }

    fn file_backed(byte_len: usize, label: &str) -> Self {
        let file = create_temp_backing_file(byte_len, label);
        let active = map_file_mut(&file, byte_len, label);
        Self::FileBacked {
            file,
            active,
            byte_len,
        }
    }

    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Anonymous(mmap) => mmap,
            Self::FileBacked { active, .. } => active,
        }
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        match self {
            Self::Anonymous(mmap) => mmap,
            Self::FileBacked { active, .. } => active,
        }
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.as_mut_slice().as_mut_ptr()
    }

    fn len(&self) -> usize {
        match self {
            Self::Anonymous(mmap) => mmap.len(),
            Self::FileBacked { byte_len, .. } => *byte_len,
        }
    }

    fn prepare_cow(&self, label: &str) -> Option<MmapMut> {
        match self {
            Self::Anonymous(_) => None,
            Self::FileBacked { file, byte_len, .. } => {
                let cloned = file.try_clone().ok()?;
                map_file_copy(&cloned, *byte_len, label)
            }
        }
    }

    fn supports_cow_checkpoint(&self) -> bool {
        matches!(self, Self::FileBacked { .. })
    }

    fn install_cow(&mut self, cow: MmapMut) -> Option<FileBackedMmapCheckpoint> {
        match self {
            Self::Anonymous(_) => None,
            Self::FileBacked { active, .. } => Some(FileBackedMmapCheckpoint {
                original: std::mem::replace(active, cow),
            }),
        }
    }

    fn restore_from_checkpoint(&mut self, checkpoint: FileBackedMmapCheckpoint) {
        match self {
            Self::Anonymous(_) => {}
            Self::FileBacked { active, .. } => *active = checkpoint.original,
        }
    }
}

#[cfg(feature = "mmap-memory")]
impl Clone for MmapStorage {
    fn clone(&self) -> Self {
        let mut clone = match self {
            Self::Anonymous(mmap) => Self::Anonymous(
                MmapMut::map_anon(mmap.len()).expect("Failed to clone anonymous mmap"),
            ),
            Self::FileBacked { byte_len, .. } => Self::file_backed(*byte_len, "clone"),
        };
        clone.as_mut_slice().copy_from_slice(self.as_slice());
        clone
    }
}

#[cfg(feature = "mmap-memory")]
pub struct ValuesStorage {
    inner: MmapStorage,
}

#[cfg(feature = "mmap-memory")]
#[derive(Debug)]
pub(crate) struct ValuesStorageCheckpoint {
    inner: FileBackedMmapCheckpoint,
}

#[cfg(feature = "mmap-memory")]
impl ValuesStorage {
    pub fn new(size: usize) -> Self {
        Self {
            inner: MmapStorage::anonymous(size, "values"),
        }
    }

    pub fn new_checkpointable(size: usize) -> Self {
        Self {
            inner: MmapStorage::file_backed(size, "values"),
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

    pub(crate) fn prepare_cow_checkpoint(&self) -> Option<PreparedCowMapping> {
        self.inner.prepare_cow("values")
    }

    pub(crate) fn install_cow_checkpoint(
        &mut self,
        cow: PreparedCowMapping,
    ) -> Option<ValuesStorageCheckpoint> {
        Some(ValuesStorageCheckpoint {
            inner: self.inner.install_cow(cow)?,
        })
    }

    pub(crate) fn restore_from_checkpoint(&mut self, checkpoint: ValuesStorageCheckpoint) {
        self.inner.restore_from_checkpoint(checkpoint.inner);
    }

    pub(crate) fn supports_cow_checkpoint(&self) -> bool {
        self.inner.supports_cow_checkpoint()
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
#[derive(Debug)]
pub(crate) struct MetadataStorageCheckpoint {
    inner: FileBackedMmapCheckpoint,
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

    pub fn new_checkpointable(size: usize) -> Self {
        let byte_size = size * std::mem::size_of::<u64>();
        Self {
            inner: MmapStorage::file_backed(byte_size, "metadata"),
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

    pub(crate) fn prepare_cow_checkpoint(&self) -> Option<PreparedCowMapping> {
        self.inner.prepare_cow("metadata")
    }

    pub(crate) fn install_cow_checkpoint(
        &mut self,
        cow: PreparedCowMapping,
    ) -> Option<MetadataStorageCheckpoint> {
        Some(MetadataStorageCheckpoint {
            inner: self.inner.install_cow(cow)?,
            len: self.len,
        })
    }

    pub(crate) fn restore_from_checkpoint(&mut self, checkpoint: MetadataStorageCheckpoint) {
        self.inner.restore_from_checkpoint(checkpoint.inner);
        self.len = checkpoint.len;
    }

    pub(crate) fn supports_cow_checkpoint(&self) -> bool {
        self.inner.supports_cow_checkpoint()
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
