use pico_vm::emulator::riscv::memory::VALUES_SIZE;

/// Minimal register metadata needed for snapshot compatibility.
#[derive(Debug, Copy, Clone, Default)]
pub struct RegisterRecord {
    pub chunk: u32,
    pub timestamp: u32,
}

/// Number of u64 words needed to cover the full VALUES_SIZE address space as a dword bitmap.
const BITMAP_WORDS: usize = ((VALUES_SIZE >> 3) + 63) >> 6;

// ============================================================================
// Mmap-backed SimpleBitSet (Linux production path)
// ============================================================================

/// Mmap-backed bitmap for chunk split tracking.
///
/// Uses anonymous mmap so pages are lazily committed on first write (zero physical
/// memory until touched). Reset via `madvise(MADV_DONTNEED)` returns pages to the
/// OS in a single syscall instead of iterating dirty entries.
#[cfg(feature = "mmap-memory")]
#[derive(Debug)]
pub struct SimpleBitSet {
    mmap: memmap2::MmapMut,
}

#[cfg(feature = "mmap-memory")]
impl SimpleBitSet {
    pub fn new() -> Self {
        let byte_size = BITMAP_WORDS * std::mem::size_of::<u64>();
        let mmap =
            memmap2::MmapMut::map_anon(byte_size).expect("Failed to create mmap for SimpleBitSet");
        Self { mmap }
    }

    #[inline(always)]
    fn words_mut(&mut self) -> &mut [u64] {
        unsafe { std::slice::from_raw_parts_mut(self.mmap.as_mut_ptr() as *mut u64, BITMAP_WORDS) }
    }

    #[inline(always)]
    pub fn insert_dword_index(&mut self, dword_index: usize) -> bool {
        let word_index = dword_index >> 6;
        if word_index >= BITMAP_WORDS {
            return false;
        }

        let bit_offset = dword_index & 63;
        let mask = 1u64 << bit_offset;
        let words = self.words_mut();
        let word = &mut words[word_index];
        let is_new = (*word & mask) == 0;
        if is_new {
            *word |= mask;
        }
        is_new
    }

    pub fn clear(&mut self) {
        // On Linux, MADV_DONTNEED discards pages so next access faults in fresh zeroes.
        // On macOS, MADV_DONTNEED is advisory only, so we must also zero explicitly.
        #[cfg(target_os = "linux")]
        unsafe {
            libc::madvise(
                self.mmap.as_mut_ptr() as *mut libc::c_void,
                self.mmap.len(),
                libc::MADV_DONTNEED,
            );
        }
        #[cfg(not(target_os = "linux"))]
        {
            self.mmap.fill(0);
        }
    }
}

#[cfg(feature = "mmap-memory")]
impl Clone for SimpleBitSet {
    fn clone(&self) -> Self {
        let mut new = Self::new();
        new.mmap.copy_from_slice(&self.mmap);
        new
    }
}

#[cfg(feature = "mmap-memory")]
impl Default for SimpleBitSet {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Box-backed SimpleBitSet (fallback for non-Linux / tests)
// ============================================================================

/// Dirty-cleared bitmap for chunk split tracking.
#[cfg(not(feature = "mmap-memory"))]
#[derive(Debug, Clone)]
pub struct SimpleBitSet {
    words: Box<[u64]>,
    dirty_words: Vec<u32>,
}

#[cfg(not(feature = "mmap-memory"))]
impl SimpleBitSet {
    pub fn new() -> Self {
        Self {
            words: vec![0u64; BITMAP_WORDS].into_boxed_slice(),
            dirty_words: Vec::new(),
        }
    }

    #[inline(always)]
    pub fn insert_dword_index(&mut self, dword_index: usize) -> bool {
        let word_index = dword_index >> 6;
        if word_index >= self.words.len() {
            return false;
        }

        let bit_offset = dword_index & 63;
        let mask = 1u64 << bit_offset;
        let word = &mut self.words[word_index];
        let was_zero = *word == 0;
        let is_new = (*word & mask) == 0;
        if is_new {
            if was_zero {
                self.dirty_words.push(word_index as u32);
            }
            *word |= mask;
        }
        is_new
    }

    pub fn clear(&mut self) {
        for idx in self.dirty_words.drain(..) {
            self.words[idx as usize] = 0;
        }
    }
}

#[cfg(not(feature = "mmap-memory"))]
impl Default for SimpleBitSet {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Default)]
pub struct ChunkSplitState {
    pub num_syscall_events: usize,
    pub num_syscall_memory_events: usize,
    pub num_memory_read_write_events: usize,
    pub num_global_lookup_base: usize,
    memory_access_addrs: SimpleBitSet,
    unique_memory_addrs: usize,
    reg_write_mask: u32,
    unique_reg_writes: usize,
    syscall_depth: u32,
}

impl ChunkSplitState {
    #[inline(always)]
    pub fn num_global_lookup_events(&self) -> usize {
        self.num_global_lookup_base << 1
    }

    #[inline(always)]
    pub fn insert_memory_address(&mut self, addr: u64) {
        if addr < 32 {
            let bit = 1u32 << (addr as u32);
            if (self.reg_write_mask & bit) == 0 {
                self.reg_write_mask |= bit;
                self.unique_reg_writes += 1;
                self.num_global_lookup_base += 1;
            }
            return;
        }

        if addr >= VALUES_SIZE as u64 {
            return;
        }

        let dword_index = (addr >> 3) as usize;
        if self.memory_access_addrs.insert_dword_index(dword_index) {
            self.unique_memory_addrs += 1;
            self.num_global_lookup_base += 1;
        }
    }

    #[inline(always)]
    pub fn unique_address_count(&self) -> usize {
        self.unique_memory_addrs + self.unique_reg_writes
    }

    #[inline(always)]
    pub fn record_syscall_event(&mut self) {
        self.num_syscall_events += 1;
        self.num_global_lookup_base += 1;
    }

    #[inline(always)]
    pub fn add_syscall_memory_events(&mut self, count: usize) {
        self.num_syscall_memory_events += count;
        self.num_global_lookup_base += count;
    }

    #[inline(always)]
    pub fn add_memory_rw_events(&mut self, count: usize) {
        self.num_memory_read_write_events += count;
    }

    #[inline(always)]
    pub fn enter_syscall(&mut self) {
        self.syscall_depth = self.syscall_depth.wrapping_add(1);
    }

    #[inline(always)]
    pub fn exit_syscall(&mut self) {
        self.syscall_depth = self.syscall_depth.wrapping_sub(1);
    }

    #[inline(always)]
    pub fn in_syscall(&self) -> bool {
        self.syscall_depth > 0
    }

    pub fn clear(&mut self) {
        self.num_syscall_events = 0;
        self.num_syscall_memory_events = 0;
        self.num_memory_read_write_events = 0;
        self.num_global_lookup_base = 0;
        self.unique_memory_addrs = 0;
        self.reg_write_mask = 0;
        self.unique_reg_writes = 0;
        self.memory_access_addrs.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::ChunkSplitState;

    #[test]
    fn chunk_split_state_counts_unique_registers_once_per_chunk() {
        let mut state = ChunkSplitState::default();

        state.insert_memory_address(5);
        state.insert_memory_address(5);

        assert_eq!(state.unique_address_count(), 1);
        assert_eq!(state.num_global_lookup_base, 1);
    }

    #[test]
    fn chunk_split_state_counts_unique_memory_per_dword() {
        let mut state = ChunkSplitState::default();

        state.insert_memory_address(0x100);
        state.insert_memory_address(0x104);
        state.insert_memory_address(0x108);

        assert_eq!(state.unique_address_count(), 2);
        assert_eq!(state.num_global_lookup_base, 2);
    }

    #[test]
    fn chunk_split_state_clear_resets_dirty_words_and_allows_reuse() {
        let mut state = ChunkSplitState::default();

        state.insert_memory_address(0x100);
        state.record_syscall_event();
        state.add_syscall_memory_events(2);
        state.add_memory_rw_events(3);
        state.clear();

        assert_eq!(state.unique_address_count(), 0);
        assert_eq!(state.num_syscall_events, 0);
        assert_eq!(state.num_syscall_memory_events, 0);
        assert_eq!(state.num_memory_read_write_events, 0);
        assert_eq!(state.num_global_lookup_base, 0);

        state.insert_memory_address(0x100);
        assert_eq!(state.unique_address_count(), 1);
        assert_eq!(state.num_global_lookup_base, 1);
    }

    #[test]
    fn chunk_split_state_cached_global_base_tracks_all_components() {
        let mut state = ChunkSplitState::default();

        state.insert_memory_address(7);
        state.insert_memory_address(0x100);
        state.record_syscall_event();
        state.add_syscall_memory_events(2);

        assert_eq!(state.unique_address_count(), 2);
        assert_eq!(state.num_global_lookup_base, 5);
        assert_eq!(state.num_global_lookup_events(), 10);
    }
}
