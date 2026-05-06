use super::memory::VALUES_SIZE;

/// Number of u64 words needed to cover the full VALUES_SIZE address space as a dword bitmap.
const BITMAP_WORDS: usize = ((VALUES_SIZE >> 3) + 63) >> 6;

/// Shared chunk-splitting thresholds derived from chunk size and syscall slack.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChunkSplitConfig {
    pub chunk_size: u32,
    pub clk_threshold: u32,
    pub clk_fast_threshold: u32,
    pub memory_rw_threshold: usize,
    pub global_lookup_base_threshold: usize,
    pub event_fast_threshold: usize,
}

impl ChunkSplitConfig {
    pub const FAST_PATH_CLK_MARGIN: u32 = 10_000;
    pub const FAST_PATH_EVENT_MARGIN: usize = 5_000;

    #[inline(always)]
    pub fn disabled(max_syscall_cycles: u32) -> Self {
        let chunk_size = u32::MAX / 4;
        let clk_threshold = chunk_size
            .saturating_mul(4)
            .saturating_sub(max_syscall_cycles);
        Self {
            chunk_size,
            clk_threshold,
            clk_fast_threshold: clk_threshold.saturating_sub(Self::FAST_PATH_CLK_MARGIN),
            memory_rw_threshold: usize::MAX,
            global_lookup_base_threshold: usize::MAX,
            event_fast_threshold: usize::MAX.saturating_sub(Self::FAST_PATH_EVENT_MARGIN),
        }
    }

    #[inline(always)]
    pub fn for_chunk_size(chunk_size: u32, max_syscall_cycles: u32) -> Self {
        let clk_threshold = chunk_size
            .saturating_mul(4)
            .saturating_sub(max_syscall_cycles);
        let memory_rw_threshold = (chunk_size as usize) >> 1;
        Self {
            chunk_size,
            clk_threshold,
            clk_fast_threshold: clk_threshold.saturating_sub(Self::FAST_PATH_CLK_MARGIN),
            memory_rw_threshold,
            global_lookup_base_threshold: memory_rw_threshold >> 2,
            event_fast_threshold: memory_rw_threshold.saturating_sub(Self::FAST_PATH_EVENT_MARGIN),
        }
    }
}

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
struct SimpleBitSet {
    mmap: memmap2::MmapMut,
}

#[cfg(feature = "mmap-memory")]
impl SimpleBitSet {
    fn new() -> Self {
        let byte_size = BITMAP_WORDS * std::mem::size_of::<u64>();
        let mmap =
            memmap2::MmapMut::map_anon(byte_size).expect("Failed to create mmap for SimpleBitSet");
        Self { mmap }
    }

    #[inline(always)]
    fn words_mut(&mut self) -> &mut [u64] {
        // SAFETY: mmap is allocated with byte_size = BITMAP_WORDS * size_of::<u64>().
        unsafe { std::slice::from_raw_parts_mut(self.mmap.as_mut_ptr() as *mut u64, BITMAP_WORDS) }
    }

    #[inline(always)]
    fn insert_dword_index(&mut self, dword_index: usize) -> bool {
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

    fn clear(&mut self) {
        #[cfg(target_os = "linux")]
        // SAFETY: madvise covers the full mmap region and does not outlive the mapping.
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
struct SimpleBitSet {
    words: Box<[u64]>,
    dirty_words: Vec<u32>,
}

#[cfg(not(feature = "mmap-memory"))]
impl SimpleBitSet {
    fn new() -> Self {
        Self {
            words: vec![0u64; BITMAP_WORDS].into_boxed_slice(),
            dirty_words: Vec::new(),
        }
    }

    #[inline(always)]
    fn insert_dword_index(&mut self, dword_index: usize) -> bool {
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

    fn clear(&mut self) {
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

#[inline(always)]
pub fn should_check_fast(clk: u32, state: &ChunkSplitState, cfg: &ChunkSplitConfig) -> bool {
    clk >= cfg.clk_fast_threshold || state.num_memory_read_write_events >= cfg.event_fast_threshold
}

#[inline(always)]
pub fn should_split(
    clk: u32,
    max_syscall_cycles: u32,
    state: &ChunkSplitState,
    cfg: &ChunkSplitConfig,
) -> bool {
    let max_chunk_clk = cfg.chunk_size.saturating_mul(4);
    let is_max_chunk_size = clk.saturating_add(max_syscall_cycles) >= max_chunk_clk;
    let over_event_limit = (state.num_memory_read_write_events > cfg.memory_rw_threshold
        && state.num_global_lookup_base >= cfg.global_lookup_base_threshold)
        || (state.num_memory_read_write_events >= cfg.memory_rw_threshold
            && state.num_global_lookup_base > cfg.global_lookup_base_threshold);

    is_max_chunk_size || over_event_limit
}

#[inline(always)]
pub fn can_fit_block(
    clk: u32,
    insn_count: u32,
    mem_rw_exact: usize,
    non_register_global_lookup_base_max: usize,
    reg_write_mask: u32,
    state: &ChunkSplitState,
    cfg: &ChunkSplitConfig,
) -> bool {
    let cost = insn_count.saturating_mul(4);
    let remaining = cfg.clk_threshold.saturating_sub(clk);
    if cost > remaining {
        return false;
    }

    let projected_memory = state
        .num_memory_read_write_events
        .saturating_add(mem_rw_exact);
    if projected_memory < cfg.memory_rw_threshold {
        return true;
    }

    let new_reg_writes = (reg_write_mask & !state.reg_write_mask).count_ones() as usize;
    let projected_global = state
        .num_global_lookup_base
        .saturating_add(non_register_global_lookup_base_max)
        .saturating_add(new_reg_writes);

    !((projected_memory > cfg.memory_rw_threshold
        && projected_global >= cfg.global_lookup_base_threshold)
        || (projected_memory >= cfg.memory_rw_threshold
            && projected_global > cfg.global_lookup_base_threshold))
}

impl ChunkSplitState {
    #[inline(always)]
    pub fn num_global_lookup_events(&self) -> usize {
        self.num_global_lookup_base << 1
    }

    #[inline(always)]
    pub fn track_address(&mut self, addr: u64) {
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

    #[inline(always)]
    pub fn should_split(&self, clk: u32, max_syscall_cycles: u32, cfg: &ChunkSplitConfig) -> bool {
        should_split(clk, max_syscall_cycles, self, cfg)
    }

    #[inline(always)]
    pub fn can_fit_block(
        &self,
        clk: u32,
        insn_count: u32,
        mem_rw_exact: usize,
        non_register_global_lookup_base_max: usize,
        reg_write_mask: u32,
        cfg: &ChunkSplitConfig,
    ) -> bool {
        can_fit_block(
            clk,
            insn_count,
            mem_rw_exact,
            non_register_global_lookup_base_max,
            reg_write_mask,
            self,
            cfg,
        )
    }

    pub fn clear(&mut self) {
        self.num_syscall_events = 0;
        self.num_syscall_memory_events = 0;
        self.num_memory_read_write_events = 0;
        self.num_global_lookup_base = 0;
        self.unique_memory_addrs = 0;
        self.reg_write_mask = 0;
        self.unique_reg_writes = 0;
        self.syscall_depth = 0;
        self.memory_access_addrs.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        can_fit_block, should_check_fast, should_split, ChunkSplitConfig, ChunkSplitState,
    };

    #[test]
    fn chunk_split_state_counts_unique_registers_once_per_chunk() {
        let mut state = ChunkSplitState::default();

        state.track_address(5);
        state.track_address(5);

        assert_eq!(state.unique_address_count(), 1);
        assert_eq!(state.num_global_lookup_base, 1);
    }

    #[test]
    fn chunk_split_state_counts_unique_memory_per_dword() {
        let mut state = ChunkSplitState::default();

        state.track_address(0x100);
        state.track_address(0x104);
        state.track_address(0x108);

        assert_eq!(state.unique_address_count(), 2);
        assert_eq!(state.num_global_lookup_base, 2);
    }

    #[test]
    fn chunk_split_state_clear_resets_dirty_words_and_allows_reuse() {
        let mut state = ChunkSplitState::default();

        state.track_address(0x100);
        state.record_syscall_event();
        state.add_syscall_memory_events(2);
        state.add_memory_rw_events(3);
        state.enter_syscall();
        state.clear();

        assert_eq!(state.unique_address_count(), 0);
        assert_eq!(state.num_syscall_events, 0);
        assert_eq!(state.num_syscall_memory_events, 0);
        assert_eq!(state.num_memory_read_write_events, 0);
        assert_eq!(state.num_global_lookup_base, 0);
        assert!(!state.in_syscall());

        state.track_address(0x100);
        assert_eq!(state.unique_address_count(), 1);
        assert_eq!(state.num_global_lookup_base, 1);
    }

    #[test]
    fn chunk_split_state_cached_global_base_tracks_all_components() {
        let mut state = ChunkSplitState::default();

        state.track_address(7);
        state.track_address(0x100);
        state.record_syscall_event();
        state.add_syscall_memory_events(2);

        assert_eq!(state.unique_address_count(), 2);
        assert_eq!(state.num_global_lookup_base, 5);
        assert_eq!(state.num_global_lookup_events(), 10);
    }

    #[test]
    fn repeated_syscall_memory_events_do_not_duplicate_uniqueness() {
        let mut state = ChunkSplitState::default();

        state.track_address(0x100);
        state.add_syscall_memory_events(1);
        state.track_address(0x100);
        state.add_syscall_memory_events(1);

        assert_eq!(state.unique_address_count(), 1);
        assert_eq!(state.num_syscall_memory_events, 2);
        assert_eq!(state.num_global_lookup_base, 3);
    }

    #[test]
    fn split_predicate_matches_aot_edges() {
        let cfg = ChunkSplitConfig {
            chunk_size: 64,
            clk_threshold: 256,
            clk_fast_threshold: 240,
            memory_rw_threshold: 4,
            global_lookup_base_threshold: 2,
            event_fast_threshold: 3,
        };
        let mut state = ChunkSplitState::default();

        assert!(!should_split(128, 0, &state, &cfg));

        state.num_memory_read_write_events = 5;
        state.num_global_lookup_base = 2;
        assert!(should_split(128, 0, &state, &cfg));

        state.num_memory_read_write_events = 4;
        state.num_global_lookup_base = 3;
        assert!(should_split(128, 0, &state, &cfg));

        state.num_memory_read_write_events = 4;
        state.num_global_lookup_base = 2;
        assert!(!should_split(128, 0, &state, &cfg));
    }

    #[test]
    fn can_fit_block_matches_runtime_predicate() {
        let cfg = ChunkSplitConfig {
            chunk_size: 64,
            clk_threshold: 256,
            clk_fast_threshold: 240,
            memory_rw_threshold: 4,
            global_lookup_base_threshold: 2,
            event_fast_threshold: 3,
        };
        let state = ChunkSplitState {
            num_memory_read_write_events: 3,
            num_global_lookup_base: 1,
            ..Default::default()
        };

        assert!(!can_fit_block(0, 1, 2, 1, 0, &state, &cfg));
        assert!(can_fit_block(0, 1, 1, 1, 0, &state, &cfg));
    }

    #[test]
    fn can_fit_block_ignores_registers_already_written_in_chunk() {
        let cfg = ChunkSplitConfig {
            chunk_size: 64,
            clk_threshold: 256,
            clk_fast_threshold: 240,
            memory_rw_threshold: 4,
            global_lookup_base_threshold: 1,
            event_fast_threshold: 3,
        };
        let mut state = ChunkSplitState {
            num_memory_read_write_events: 3,
            ..Default::default()
        };
        state.track_address(1);

        assert!(can_fit_block(0, 1, 1, 0, 1 << 1, &state, &cfg));
        assert!(!can_fit_block(0, 1, 1, 0, 1 << 2, &state, &cfg));
    }

    #[test]
    fn should_check_fast_enters_slow_path_near_threshold() {
        let cfg = ChunkSplitConfig {
            chunk_size: 64,
            clk_threshold: 256,
            clk_fast_threshold: 240,
            memory_rw_threshold: 4,
            global_lookup_base_threshold: 2,
            event_fast_threshold: 3,
        };
        let mut state = ChunkSplitState::default();
        assert!(!should_check_fast(128, &state, &cfg));

        state.num_memory_read_write_events = 3;
        assert!(should_check_fast(128, &state, &cfg));
    }
}
