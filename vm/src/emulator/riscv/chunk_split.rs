use super::memory::VALUES_SIZE;
use crate::primitives::consts::{CHUNK_CLK_START, DIGEST_SIZE};

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
    /// Clk below the ceiling that only a half-written digest may spend; see `should_split`.
    pub commit_tail_reserve: u32,
    /// Clk past the ceiling a half-written digest may spend instead, on a chunk too short to
    /// reserve room below it.
    pub commit_tail_overrun: u32,
}

/// Experiment knob (`CHUNK_EVENT_LIMIT_SCALE`, default 1.0 = behavior unchanged): scales the
/// event-limit thresholds (mem-rw and, via derivation, global-lookup) so a chunk can fill closer
/// to its instruction limit. reth-188 @ 2^22 closes chunks on the event limits at ~70% of the
/// 4.19M-instr cap; scaling trades per-chunk VRAM for fewer chunks. Shared by the interpreter and
/// AOT emulators (both build `ChunkSplitConfig` here). Clamped to [1.0, 16.0]; unparseable → 1.0.
pub fn event_limit_scale() -> f64 {
    static SCALE: std::sync::OnceLock<f64> = std::sync::OnceLock::new();
    *SCALE.get_or_init(|| {
        std::env::var("CHUNK_EVENT_LIMIT_SCALE")
            .ok()
            .and_then(|v| v.trim().parse::<f64>().ok())
            .filter(|s| (1.0..=16.0).contains(s))
            .unwrap_or(1.0)
    })
}

impl ChunkSplitConfig {
    /// Room held back from every chunk so the guest's commit tail — the 8 `COMMIT` and 8
    /// `COMMIT_DEFERRED_PROOFS` ecalls the SDK issues back-to-back before `HALT`, a few hundred
    /// clk — can finish inside the chunk that started it. A committed digest cut in two is two
    /// partial values the combine layer rejects; a deferred run cut in two is a chunk the convert
    /// leaf rejects. Charged only to chunks of at least 64 tails; a CHUNK_SIZE below 2^15 cycles
    /// holds past its ceiling instead (`commit_tail_overrun`).
    pub const COMMIT_TAIL_RESERVE_CLK: u32 = 2048;
    pub const FAST_PATH_CLK_MARGIN: u32 = 10_000;
    pub const FAST_PATH_EVENT_MARGIN: usize = 5_000;

    #[inline(always)]
    pub fn disabled(max_syscall_cycles: u32) -> Self {
        let chunk_size = u32::MAX / 4;
        let clk_threshold = chunk_size
            .saturating_mul(4)
            .saturating_sub(max_syscall_cycles)
            .saturating_sub(CHUNK_CLK_START);
        Self {
            chunk_size,
            clk_threshold,
            clk_fast_threshold: clk_threshold.saturating_sub(Self::FAST_PATH_CLK_MARGIN),
            memory_rw_threshold: usize::MAX,
            global_lookup_base_threshold: usize::MAX,
            event_fast_threshold: usize::MAX.saturating_sub(Self::FAST_PATH_EVENT_MARGIN),
            commit_tail_reserve: 0,
            commit_tail_overrun: 0,
        }
    }

    /// The absolute clk ceiling of a chunk (`4 * chunk_size`).
    #[inline(always)]
    pub fn max_chunk_clk(&self) -> u32 {
        self.chunk_size.saturating_mul(4)
    }

    /// The chunk-clk bit budget baked into the AIRs: the CPU chip decomposes clk into
    /// a 16-bit limb plus a 9-bit limb (`riscv_cpu/chunk_clk`; the limbs are a representation,
    /// the AIR bounds clk through the row chain), and the Global chip range-checks the leading
    /// slot of the syscall message -- the clk -- to 25 bits and packs its interaction kind above
    /// it. A chunk whose clk exceeds
    /// this budget would get its limbs truncated during trace generation — the resulting
    /// proof is UNSOUND and only fails at verify time (SumClaimMismatch); trace generation
    /// also asserts, but this guard fails earliest. History: the budget was 24 bits (the
    /// long-lost rationale for the CHUNK_SIZE=2^22 default), widened to 25 to admit
    /// CHUNK_SIZE=2^23. 25 is now a hard ceiling: the syscall Global message leads with `clk`
    /// and the digest packs `kind` above bit 25, so a wider clk would overflow that packing.
    pub const MAX_CHUNK_CLK_BITS: u32 = 25;

    #[inline(always)]
    pub fn for_chunk_size(chunk_size: u32, max_syscall_cycles: u32) -> Self {
        // Loud guard for the chunk-clk budget (MAX_CHUNK_CLK_BITS, now 25): without it, an
        // oversized CHUNK_SIZE emulates fine and proves fine, and the bad trace is only caught
        // by an explicit verify — or worse, shipped.
        assert!(
            (chunk_size as u64) * 4 <= 1u64 << Self::MAX_CHUNK_CLK_BITS,
            "CHUNK_SIZE={chunk_size} exceeds the chunk-clk budget: max chunk clk = 4*CHUNK_SIZE \
             must fit in {} bits (CHUNK_SIZE <= {}). Larger chunks silently truncate the CPU/\
             Global chip clk limbs and produce unverifiable traces.",
            Self::MAX_CHUNK_CLK_BITS,
            1u32 << (Self::MAX_CHUNK_CLK_BITS - 2),
        );
        // `CHUNK_CLK_START` comes off the threshold, not off the admissible CHUNK_SIZE: the
        // clock starts there instead of at zero, so charging it here keeps the *absolute* clk
        // ceiling exactly where it was and leaves CHUNK_SIZE=2^23 -- the shipping operating
        // point, whose log2 is baked into the VK -- valid.
        let max_chunk_clk = chunk_size.saturating_mul(4);
        // A chunk shorter than 64 tails cannot spare one; only toy chunk sizes are that short.
        // `CHUNK_COMMIT_TAIL_HOLD_OFF=1` (tests only) drops the hold, so a harness can cut the tail.
        let hold_off = std::env::var("CHUNK_COMMIT_TAIL_HOLD_OFF").is_ok_and(|v| v == "1");
        let (commit_tail_reserve, commit_tail_overrun) = if hold_off {
            (0, 0)
        } else if max_chunk_clk >= 64 * Self::COMMIT_TAIL_RESERVE_CLK {
            (Self::COMMIT_TAIL_RESERVE_CLK, 0)
        } else {
            // A short chunk holds past its ceiling, which stays far below the clk budget.
            let budget = (1u32 << Self::MAX_CHUNK_CLK_BITS) - 1;
            (0, Self::COMMIT_TAIL_RESERVE_CLK.min(budget - max_chunk_clk))
        };
        let clk_threshold = max_chunk_clk
            .saturating_sub(max_syscall_cycles)
            .saturating_sub(CHUNK_CLK_START)
            .saturating_sub(commit_tail_reserve);
        // Chunk-split knob (`CHUNK_EVENT_LIMITS_OFF=1`, default off = behavior unchanged): drop
        // the mem-rw/global-lookup event arm entirely so the clk limit is the only split condition
        // (the event arm is an AND that reth-shaped workloads never trip), leaving `CHUNK_SIZE` as
        // the single knob. Off here; enabled by the later tail-merge / chunk-count reduction work.
        let memory_rw_threshold = if event_limits_off() {
            usize::MAX
        } else {
            (((chunk_size as usize) >> 1) as f64 * event_limit_scale()) as usize
        };
        let cfg = Self {
            chunk_size,
            clk_threshold,
            clk_fast_threshold: clk_threshold.saturating_sub(Self::FAST_PATH_CLK_MARGIN),
            memory_rw_threshold,
            global_lookup_base_threshold: memory_rw_threshold >> 2,
            event_fast_threshold: memory_rw_threshold.saturating_sub(Self::FAST_PATH_EVENT_MARGIN),
            commit_tail_reserve,
            commit_tail_overrun,
        };
        // One-shot effective-config snapshot so every bench log records the split conditions
        // it actually ran with (debug reference for OOM/chunk-count attribution).
        static SNAPSHOT: std::sync::Once = std::sync::Once::new();
        SNAPSHOT.call_once(|| {
            tracing::info!(
                "[chunk-split] config: chunk_size={} clk_threshold={} memory_rw_threshold={} \
                 global_lookup_base_threshold={} event_limits_off={} commit_tail_reserve={} \
                 commit_tail_overrun={}",
                cfg.chunk_size,
                cfg.clk_threshold,
                cfg.memory_rw_threshold,
                cfg.global_lookup_base_threshold,
                event_limits_off(),
                cfg.commit_tail_reserve,
                cfg.commit_tail_overrun,
            );
        });
        cfg
    }
}

/// `CHUNK_EVENT_LIMITS_OFF=1` (cached): remove the event arm from the split condition.
#[inline(always)]
pub fn event_limits_off() -> bool {
    static OFF: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *OFF.get_or_init(|| std::env::var("CHUNK_EVENT_LIMITS_OFF").is_ok_and(|v| v == "1"))
}

/// `CHUNK_SPLIT_DEBUG=1` (cached): per-chunk close-reason probe (see `debug_split_snapshot`).
#[inline(always)]
pub fn split_debug() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("CHUNK_SPLIT_DEBUG").is_ok_and(|v| v == "1"))
}

/// Print why a chunk closed and its event readings vs the thresholds; silent unless
/// `CHUNK_SPLIT_DEBUG=1`. The guard lives here so no split site can report on one emulator and
/// stay silent on the other. Per-chunk instruction counts are recovered offline by diffing
/// consecutive `global_clk` readings (`global_clk` increments once per retired instruction).
pub fn maybe_debug_split_snapshot(
    chunk_idx: u32,
    clk: u32,
    max_syscall_cycles: u32,
    global_clk: u64,
    state: &ChunkSplitState,
    cfg: &ChunkSplitConfig,
) {
    if !split_debug() {
        return;
    }
    let max_chunk_clk = cfg.max_chunk_clk();
    let hold = holds_for_commit_tail(state, cfg);
    let cut_line = clk_cut_line(max_syscall_cycles, hold, cfg);
    let clk_hit = clk >= cut_line;
    let events_hit = !hold
        && ((state.num_memory_read_write_events > cfg.memory_rw_threshold
            && state.num_global_lookup_base >= cfg.global_lookup_base_threshold)
            || (state.num_memory_read_write_events >= cfg.memory_rw_threshold
                && state.num_global_lookup_base > cfg.global_lookup_base_threshold));
    let reason = match (clk_hit, events_hit) {
        (true, true) => "clk+events",
        (true, false) => "clk",
        (false, true) => "events",
        (false, false) => "none?", // unreachable if called at a split point
    };
    tracing::info!(
        "[chunk-split] chunk={chunk_idx} reason={reason} clk={clk} (cut {cut_line}, max \
         {max_chunk_clk}) commit_in_flight={} mem_rw={} (thr {}) lookups_base={} (thr {}) \
         global_clk={global_clk}",
        state.commit_in_flight,
        state.num_memory_read_write_events,
        cfg.memory_rw_threshold,
        state.num_global_lookup_base,
        cfg.global_lookup_base_threshold,
    );
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
    /// The record's committed or deferred digest has some words written and some not: the guest
    /// is mid-way through its COMMIT ecalls. Set by the COMMIT handlers after every word they
    /// write, cleared when the chunk closes; `should_split` holds the cut while it is set.
    pub commit_in_flight: bool,
    /// COMMIT_DEFERRED_PROOFS ecalls run in this chunk. Counted rather than read off the digest,
    /// which stays all zero for a guest that defers nothing.
    pub deferred_commits: u32,
}

#[inline(always)]
pub fn should_check_fast(clk: u32, state: &ChunkSplitState, cfg: &ChunkSplitConfig) -> bool {
    clk >= cfg.clk_fast_threshold || state.num_memory_read_write_events >= cfg.event_fast_threshold
}

/// A digest with some words written and some still zero: the guest is between two ecalls of a
/// `COMMIT` (or `COMMIT_DEFERRED_PROOFS`) sequence. All-zero (nothing committed) and fully
/// written digests are not partial.
#[inline(always)]
pub fn digest_partial(digest: &[u32]) -> bool {
    digest.iter().any(|&w| w != 0) && digest.contains(&0)
}

/// Whether the commit tail is mid-way: the committed digest is half-written, or the chunk has run
/// some but not all of the deferred digest's words. The recursion only takes a deferred digest
/// from a chunk that ran all of them, so a cut inside that run leaves an honest execution
/// unprovable.
#[inline(always)]
pub fn commit_tail_in_flight(committed: &[u32], deferred_commits: u32) -> bool {
    digest_partial(committed) || (deferred_commits > 0 && (deferred_commits as usize) < DIGEST_SIZE)
}

/// Whether the cut is being held for a commit tail in flight. With neither a reserve nor an
/// overrun there is no room to hold, and the chunk closes as it did before either existed.
#[inline(always)]
fn holds_for_commit_tail(state: &ChunkSplitState, cfg: &ChunkSplitConfig) -> bool {
    state.commit_in_flight && (cfg.commit_tail_reserve > 0 || cfg.commit_tail_overrun > 0)
}

/// The clk at which the chunk closes: the ceiling that keeps any one syscall's cycles under
/// `4 * chunk_size`, less the commit-tail reserve unless a tail in flight is spending it — or,
/// on a chunk too short for a reserve, plus the overrun a tail in flight may spend.
#[inline(always)]
fn clk_cut_line(max_syscall_cycles: u32, hold: bool, cfg: &ChunkSplitConfig) -> u32 {
    let ceiling = cfg.max_chunk_clk().saturating_sub(max_syscall_cycles);
    if hold {
        ceiling + cfg.commit_tail_overrun
    } else {
        ceiling.saturating_sub(cfg.commit_tail_reserve)
    }
}

#[inline(always)]
pub fn should_split(
    clk: u32,
    max_syscall_cycles: u32,
    state: &ChunkSplitState,
    cfg: &ChunkSplitConfig,
) -> bool {
    let hold = holds_for_commit_tail(state, cfg);
    let is_max_chunk_size = clk >= clk_cut_line(max_syscall_cycles, hold, cfg);
    // A half-written digest holds the event arm too: a cut between two COMMIT ecalls splits the
    // digest whatever triggered it. The hold ends when the digest is whole or at the ceiling,
    // which is where a chunk closed before the reserve existed, so no chunk outgrows its old
    // bound; a chunk that does reach the ceiling still split is the case this cannot fix.
    if hold {
        if is_max_chunk_size {
            tracing::warn!(
                "[chunk-split] closing a chunk at clk {clk} with its commit tail in flight: it \
                 outran the {} clk the hold may spend, and the recursion will reject the split \
                 (a partial committed digest at combine, a partial deferred run at convert)",
                cfg.commit_tail_reserve.max(cfg.commit_tail_overrun)
            );
        }
        return is_max_chunk_size;
    }
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
        self.commit_in_flight = false;
        self.deferred_commits = 0;
        self.memory_access_addrs.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::{
        can_fit_block, commit_tail_in_flight, digest_partial, should_check_fast, should_split,
        ChunkSplitConfig, ChunkSplitState, CHUNK_CLK_START,
    };
    use crate::{
        chips::chips::riscv_memory::event::MemoryAccessPosition,
        primitives::consts::BENCH_MAX_CHUNK_SIZE,
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
            commit_tail_reserve: 0,
            commit_tail_overrun: 0,
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
            commit_tail_reserve: 0,
            commit_tail_overrun: 0,
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
            commit_tail_reserve: 0,
            commit_tail_overrun: 0,
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
            commit_tail_reserve: 0,
            commit_tail_overrun: 0,
        };
        let mut state = ChunkSplitState::default();
        assert!(!should_check_fast(128, &state, &cfg));

        state.num_memory_read_write_events = 3;
        assert!(should_check_fast(128, &state, &cfg));
    }

    /// The 25-bit chunk-clk budget guard (see `MAX_CHUNK_CLK_BITS`): CHUNK_SIZE=2^23 exactly
    /// saturates the widened budget and must be accepted. It is the shipping operating point and
    /// its log2 is baked into the VK, so `CHUNK_CLK_START` is charged to the split threshold
    /// rather than to this ceiling.
    #[test]
    fn chunk_clk_budget_accepts_2_23() {
        let cfg = ChunkSplitConfig::for_chunk_size(1 << 23, 48);
        assert_eq!(cfg.chunk_size, 1 << 23);
        assert_eq!(cfg.chunk_size, BENCH_MAX_CHUNK_SIZE);
        // The clock starts at CHUNK_CLK_START, so the threshold gives it back; the commit-tail
        // reserve comes off as well.
        assert_eq!(
            cfg.commit_tail_reserve,
            ChunkSplitConfig::COMMIT_TAIL_RESERVE_CLK
        );
        assert_eq!(
            cfg.clk_threshold,
            (1u32 << 25) - 48 - CHUNK_CLK_START - cfg.commit_tail_reserve
        );
        // What the budget has to hold is a memory-access stamp, `clk + position`. `clk` is
        // absolute and the threshold already accounts for its start, so the start is not added
        // again. The sum lands on exactly `4 * CHUNK_SIZE - 1` — the concrete form of "the
        // absolute clk ceiling is unchanged".
        //
        // This is a bound on the AOT block path, whose `can_fit_block` is what reads
        // `clk_threshold`. The interpreter splits on `clk + max_syscall_cycles >= 4 * chunk_size`
        // without subtracting the start, so its last row sits 3 higher; `sha_extend` then stamps
        // up to `base + 47` (its `clk += 1` is at the end of each of 48 iterations), landing at
        // `2^25 - 2`. The bound above also over-charges: no row pays both the syscall reserve and
        // position A, so it is not tight either way. A half-written digest may spend the
        // commit-tail reserve, so it is charged back here.
        let max_stamp = u64::from(cfg.clk_threshold + cfg.commit_tail_reserve)
            + 48
            + MemoryAccessPosition::A as u64;
        assert!(
            max_stamp < 1u64 << ChunkSplitConfig::MAX_CHUNK_CLK_BITS,
            "max memory-access stamp {max_stamp} does not fit the {}-bit chunk-clk budget",
            ChunkSplitConfig::MAX_CHUNK_CLK_BITS
        );
    }

    /// CHUNK_SIZE > 2^23 would truncate the AIR clk limbs — must fail loudly here instead
    /// of producing an unverifiable trace (2^24 is additionally impossible: KoalaBear
    /// 2-adicity caps the stacked domain).
    #[test]
    #[should_panic(expected = "exceeds the chunk-clk budget")]
    fn chunk_clk_budget_rejects_beyond_2_23() {
        let _ = ChunkSplitConfig::for_chunk_size((1 << 23) + 1, 48);
    }

    fn reserve_cfg(commit_tail_reserve: u32) -> ChunkSplitConfig {
        ChunkSplitConfig {
            chunk_size: 64,
            clk_threshold: 256 - 4 - commit_tail_reserve,
            clk_fast_threshold: 240 - commit_tail_reserve,
            memory_rw_threshold: 4,
            global_lookup_base_threshold: 2,
            event_fast_threshold: 3,
            commit_tail_reserve,
            commit_tail_overrun: 0,
        }
    }

    #[test]
    fn digest_partial_means_some_words_written_some_not() {
        assert!(!digest_partial(&[0u32; 8]));
        assert!(!digest_partial(&[1u32; 8]));
        assert!(digest_partial(&[1u32, 2, 3, 0, 0, 0, 0, 0]));
        assert!(digest_partial(&[0u32, 0, 0, 0, 0, 0, 0, 9]));
    }

    #[test]
    fn the_deferred_run_is_in_flight_by_count_whatever_its_words() {
        let whole = [1u32; 8];
        // A guest that defers nothing commits eight zero words: only the count shows the run.
        assert!(!commit_tail_in_flight(&whole, 0));
        for n in 1..8 {
            assert!(commit_tail_in_flight(&whole, n), "after {n} deferred words");
        }
        assert!(!commit_tail_in_flight(&whole, 8));
        // The committed digest still holds the cut on its own.
        assert!(commit_tail_in_flight(&[1u32, 0, 0, 0, 0, 0, 0, 0], 0));
    }

    #[test]
    fn half_written_digest_holds_the_cut_up_to_the_ceiling() {
        let cfg = reserve_cfg(32);
        let mut state = ChunkSplitState::default();
        // Not in flight: the chunk closes at the reserve line, 4 * 64 - 32.
        assert!(!should_split(223, 0, &state, &cfg));
        assert!(should_split(224, 0, &state, &cfg));
        // In flight: the reserve is spent finishing the digest; the ceiling still holds.
        state.commit_in_flight = true;
        assert!(!should_split(224, 0, &state, &cfg));
        assert!(!should_split(255, 0, &state, &cfg));
        assert!(should_split(256, 0, &state, &cfg));
        // In flight holds the event arm too.
        state.num_memory_read_write_events = 5;
        state.num_global_lookup_base = 2;
        assert!(!should_split(128, 0, &state, &cfg));
        state.commit_in_flight = false;
        assert!(should_split(128, 0, &state, &cfg));
    }

    #[test]
    fn without_a_reserve_the_flag_changes_nothing() {
        let cfg = reserve_cfg(0);
        let mut state = ChunkSplitState {
            commit_in_flight: true,
            ..Default::default()
        };
        assert!(!should_split(255, 0, &state, &cfg));
        assert!(should_split(256, 0, &state, &cfg));
        state.num_memory_read_write_events = 5;
        state.num_global_lookup_base = 2;
        assert!(should_split(128, 0, &state, &cfg));
    }

    #[test]
    fn clear_drops_the_in_flight_flag() {
        let mut state = ChunkSplitState {
            commit_in_flight: true,
            deferred_commits: 5,
            ..Default::default()
        };
        state.clear();
        assert!(!state.commit_in_flight);
        assert_eq!(state.deferred_commits, 0);
    }

    #[test]
    fn a_short_chunk_holds_past_its_ceiling() {
        let cfg = ChunkSplitConfig {
            commit_tail_overrun: 32,
            ..reserve_cfg(0)
        };
        let mut state = ChunkSplitState::default();
        // Not in flight: the chunk closes at its ceiling, 4 * 64.
        assert!(should_split(256, 0, &state, &cfg));
        // In flight: it spends the overrun past the ceiling, and no more.
        state.commit_in_flight = true;
        assert!(!should_split(287, 0, &state, &cfg));
        assert!(should_split(288, 0, &state, &cfg));
    }

    #[test]
    fn for_chunk_size_charges_the_reserve_only_to_chunks_that_can_spare_it() {
        let tiny = ChunkSplitConfig::for_chunk_size(64, 4);
        assert_eq!(tiny.commit_tail_reserve, 0);
        assert_eq!(
            tiny.commit_tail_overrun,
            ChunkSplitConfig::COMMIT_TAIL_RESERVE_CLK
        );
        assert_eq!(tiny.clk_threshold, 256 - 4 - CHUNK_CLK_START);
        let big = ChunkSplitConfig::for_chunk_size(1 << 23, 48);
        assert_eq!(
            big.commit_tail_reserve,
            ChunkSplitConfig::COMMIT_TAIL_RESERVE_CLK
        );
        assert_eq!(big.commit_tail_overrun, 0);
    }
}
