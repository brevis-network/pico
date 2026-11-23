use super::memory::VALUES_SIZE;
use crate::{
    compiler::riscv::opcode::Opcode,
    emulator::opts::EmulatorOpts,
    mle::machine::shape::{
        unaligned_log_height, MLE_CORE_LADDER, MLE_GLOBAL_LOG_HEIGHT,
        MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT,
    },
    primitives::consts::{CHUNK_CLK_START, DIGEST_SIZE, LOCAL_MEMORY_DATAPAR},
};

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
    /// Most LogUp-GKR leaves a chunk may grow to (`CHUNK_LEAF_CAP`); 0 turns the cap off. See
    /// [`leaf_estimate`].
    pub leaf_cap: u64,
    /// The misaligned loads and stores a chunk may hold: the most `MemoryUnaligned` rows a core
    /// shape has. A hard limit of the circuit, unlike the event arm, so
    /// neither `CHUNK_EVENT_LIMITS_OFF` nor a commit tail in flight lifts it.
    pub misaligned_threshold: usize,
    /// The cross-chunk events a chunk may hold: the rows of its `Global` table, which has one
    /// fixed height. A hard limit of the circuit like the one above, and lifted by nothing.
    pub global_event_cap: usize,
    /// Close a chunk while a row of the core ladder still holds its rows: what
    /// `EmulatorOpts::ladder_fit` asks for, as a prover does in whitelist mode. See
    /// [`ChunkSplitState::ladder_room`].
    pub ladder_fit: bool,
}

/// Default [`ChunkSplitConfig::leaf_cap`]: 1.5 * 2^28 leaves, which at 40 B a KB5 leaf bounds the
/// GKR input buffer at 15 GiB. The cap is on the estimate, which runs 7-40% over the real count
/// (median 21%) on the p99 reth corpus: its largest chunk estimates at 1.248 * 2^28 for a real
/// 1.118, so a 1.25 cap would cut ordinary blocks. Without a cap the leaf count follows the
/// instruction mix: a chunk that is mostly divisions (121 interactions a DivRem row) reaches
/// 4.5 * 2^28.
pub const DEFAULT_LEAF_CAP: u64 = 3 << 27;

/// `CHUNK_LEAF_CAP` (cached): the leaf cap in leaves, 0 for none; unset or unparseable →
/// [`DEFAULT_LEAF_CAP`].
pub fn leaf_cap() -> u64 {
    static CAP: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *CAP.get_or_init(|| {
        std::env::var("CHUNK_LEAF_CAP")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_LEAF_CAP)
    })
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
            leaf_cap: 0,
            misaligned_threshold: usize::MAX,
            global_event_cap: usize::MAX,
            ladder_fit: false,
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
    /// slot of the syscall message -- the clk -- to 25 bits. A chunk whose clk exceeds
    /// this budget would get its limbs truncated during trace generation — the resulting
    /// proof is UNSOUND and only fails at verify time (SumClaimMismatch); trace generation
    /// also asserts, but this guard fails earliest. History: the budget was 24 bits (the
    /// long-lost rationale for the CHUNK_SIZE=2^22 default), widened to 25 to admit
    /// CHUNK_SIZE=2^23. 25 is a hard ceiling: the syscall Global message leads with `clk`,
    /// and the Global chip's range check of that slot is 25 bits wide.
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
        let (commit_tail_reserve, commit_tail_overrun) = if commit_tail_hold_off() {
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
            leaf_cap: leaf_cap(),
            misaligned_threshold: 1 << MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT,
            global_event_cap: 1 << MLE_GLOBAL_LOG_HEIGHT,
            ladder_fit: false,
        };
        // One-shot effective-config snapshot so every bench log records the split conditions
        // it actually ran with (debug reference for OOM/chunk-count attribution).
        static SNAPSHOT: std::sync::Once = std::sync::Once::new();
        SNAPSHOT.call_once(|| {
            tracing::info!(
                "[chunk-split] config: chunk_size={} clk_threshold={} memory_rw_threshold={} \
                 global_lookup_base_threshold={} event_limits_off={} commit_tail_reserve={} \
                 commit_tail_overrun={} leaf_cap={} misaligned_threshold={} global_event_cap={}",
                cfg.chunk_size,
                cfg.clk_threshold,
                cfg.memory_rw_threshold,
                cfg.global_lookup_base_threshold,
                event_limits_off(),
                cfg.commit_tail_reserve,
                cfg.commit_tail_overrun,
                cfg.leaf_cap,
                cfg.misaligned_threshold,
                cfg.global_event_cap,
            );
        });
        cfg
    }

    /// The split of an emulation under `opts`: [`Self::for_chunk_size`] at their chunk size, and
    /// the ladder fit if they ask for it.
    #[inline(always)]
    pub fn for_opts(opts: &EmulatorOpts, max_syscall_cycles: u32) -> Self {
        let cfg = Self {
            ladder_fit: opts.ladder_fit,
            ..Self::for_chunk_size(opts.chunk_size, max_syscall_cycles)
        };
        // Beside the config line above: a process proves in one mode, and the mode moves the cuts
        // of a program whose mix leaves the ladder.
        static SNAPSHOT: std::sync::Once = std::sync::Once::new();
        SNAPSHOT.call_once(|| tracing::info!("[chunk-split] ladder_fit={}", cfg.ladder_fit));
        cfg
    }
}

/// `CHUNK_COMMIT_TAIL_HOLD_OFF=1` (tests only): drop the commit-tail hold, so a harness can cut the
/// tail. Not cached: a test sets it around the one emulation it cuts.
pub fn commit_tail_hold_off() -> bool {
    std::env::var("CHUNK_COMMIT_TAIL_HOLD_OFF").is_ok_and(|v| v == "1")
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
    let events_hit = !hold && over_event_limit(state, cfg);
    let (max_cpu_rows, max_memory_rw) = state.row_ceilings(cfg);
    let leaf_hit = !hold
        && cfg.leaf_cap != 0
        && state.leaf_estimate_after(LEAF_STEP_GROWTH, max_cpu_rows, max_memory_rw) > cfg.leaf_cap;
    let ladder_room = state.ladder_room(max_cpu_rows);
    let ladder_hit =
        !hold && cfg.ladder_fit && ladder_room.is_none_or(|room| room < LEAF_STEP_GROWTH);
    let misaligned_hit = at_misaligned_cap(state, cfg);
    let reasons: Vec<&str> = [
        (clk_hit, "clk"),
        (events_hit, "events"),
        (leaf_hit, "leaf"),
        (ladder_hit, "ladder"),
        (misaligned_hit, "misaligned"),
    ]
    .into_iter()
    .filter_map(|(hit, name)| hit.then_some(name))
    .collect();
    // "none?" is unreachable at a split point.
    let reason = if reasons.is_empty() {
        "none?".to_string()
    } else {
        reasons.join("+")
    };
    tracing::info!(
        "[chunk-split] chunk={chunk_idx} reason={reason} clk={clk} (cut {cut_line}, max \
         {max_chunk_clk}) commit_in_flight={} mem_rw={} (thr {}) lookups_base={} (thr {}) \
         leaves={} (cap {}) ladder_room={ladder_room:?} misaligned={} (cap {}) \
         global_clk={global_clk} fit_rows={:?}",
        state.commit_in_flight,
        state.num_memory_read_write_events,
        cfg.memory_rw_threshold,
        state.num_global_lookup_base,
        cfg.global_lookup_base_threshold,
        state.leaf_estimate(),
        cfg.leaf_cap,
        state.num_misaligned,
        cfg.misaligned_threshold,
        state.fit_rows(),
    );
}

// ============================================================================
// LogUp-GKR leaf estimate
// ============================================================================
//
// A chunk's GKR input holds one leaf per interaction per row: the sum over its AIRs of
// interactions times rows, the rows lifted to a power of two and to at least 2^l_skip
// (`total_interactions` in `cuda-mle`'s `logup_zerocheck`, which sizes the leaf buffer by it).
// The clk limit bounds instructions, not leaves, and an instruction costs anywhere from the 17
// leaves of a Cpu row alone to 148 for a signed division, so the leaf count is a split condition
// of its own. The estimate never under-counts: every chip is charged as present, derived rows
// are charged at their most, and the Global table at its fixed height.

/// The chips an instruction adds rows to one at a time, as indices into
/// [`ChunkSplitState::leaf_rows`].
pub const LEAF_CPU: usize = 0;
pub const LEAF_ADD: usize = 1;
pub const LEAF_SUB: usize = 2;
pub const LEAF_ADDW: usize = 3;
pub const LEAF_SUBW: usize = 4;
pub const LEAF_MUL: usize = 5;
pub const LEAF_DIVREM: usize = 6;
pub const LEAF_LT: usize = 7;
pub const LEAF_SLL: usize = 8;
pub const LEAF_SR: usize = 9;
pub const LEAF_BITWISE: usize = 10;
pub const LEAF_ECALL: usize = 11;
pub const LEAF_INSN_CHIPS: usize = 12;

/// Interactions per row of the chips above, in index order. A change to one of these AIRs is a
/// change here; `leaf_interaction_counts_match_the_airs` fails until it is made.
pub const LEAF_INSN_INTERACTIONS: [u64; LEAF_INSN_CHIPS] =
    [17, 5, 5, 4, 4, 36, 121, 4, 11, 13, 9, 14];
/// Interactions per row of the chips the memory and lookup counters size. A MemoryReadWrite row
/// counts its store's code-range check: the Program table's lookup and two u16 checks.
pub const LEAF_MEMORY_RW_INTERACTIONS: u64 = 13;
pub const LEAF_MEMORY_LOCAL_INTERACTIONS: u64 = 44;
pub const LEAF_SYSCALL_INTERACTIONS: u64 = 4;
/// Interactions per row of `Global`, whose table has one fixed height in every chunk.
pub const LEAF_GLOBAL_INTERACTIONS: u64 = 6;
/// Interactions per row of `MemoryUnaligned`.
pub const LEAF_MEMORY_UNALIGNED_INTERACTIONS: u64 = 28;
/// The tables charged as a constant: the preprocessed Program (two interactions, the fetch and
/// the code range a store checks, one row an instruction, up to 2^21 rows) and Byte (ten
/// interactions, 2^17 rows), and `Global` at the height its table has in every chunk at the
/// production stacked height (under it the table is shorter, and this over-counts).
/// `MemoryUnaligned` is charged at the height its misaligned accesses take ([`unaligned_rows`]).
const LEAF_FIXED_ALLOWANCE: u64 =
    2 * (1 << 21) + 10 * (1 << 17) + LEAF_GLOBAL_INTERACTIONS * (1 << MLE_GLOBAL_LOG_HEIGHT);
/// Rows below 2^l_skip (l_skip = 4) are lifted to it.
const LEAF_MIN_ROWS: u64 = 16;
/// Growth one instruction can add to a chip: its own four rows, four memory events and two
/// lookups for each of four new addresses. A split check that keeps this much room cuts before
/// the next instruction crosses the cap — all but a syscall touching more memory, which can
/// overrun it by that syscall. AOT blocks are checked against their own growth on entry.
pub const LEAF_STEP_GROWTH: u64 = 64;

/// The rows one instruction adds to the per-instruction chips besides its Cpu row: the ALU row
/// it dispatches, and the rows trace generation derives from it (`count_extra_records`) — a
/// branch's Lt comparison, and an Add row for each negative divisor or remainder of a signed
/// division, charged here as two, the most it can be. An ALU op into x0 dispatches nothing; it
/// is charged anyway.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InsnLeaf {
    pub chip: Option<usize>,
    pub extra_add: u32,
    pub extra_lt: u32,
}

pub const fn insn_leaf(opcode: Opcode) -> InsnLeaf {
    use Opcode::*;
    let (chip, extra_add, extra_lt) = match opcode {
        ADD | AUIPC => (Some(LEAF_ADD), 0, 0),
        SUB => (Some(LEAF_SUB), 0, 0),
        ADDW => (Some(LEAF_ADDW), 0, 0),
        SUBW => (Some(LEAF_SUBW), 0, 0),
        XOR | OR | AND => (Some(LEAF_BITWISE), 0, 0),
        SLL | SLLW => (Some(LEAF_SLL), 0, 0),
        SRL | SRA | SRLW | SRAW => (Some(LEAF_SR), 0, 0),
        SLT | SLTU => (Some(LEAF_LT), 0, 0),
        MUL | MULH | MULHU | MULHSU | MULW => (Some(LEAF_MUL), 0, 0),
        DIV | REM | DIVW | REMW => (Some(LEAF_DIVREM), 2, 0),
        DIVU | REMU | DIVUW | REMUW => (Some(LEAF_DIVREM), 0, 0),
        BEQ | BNE | BLT | BGE | BLTU | BGEU => (None, 0, 1),
        ECALL => (Some(LEAF_ECALL), 0, 0),
        LB | LH | LW | LBU | LHU | LWU | LD | SB | SH | SW | SD | JAL | JALR | EBREAK | UNIMP => {
            (None, 0, 0)
        }
    };
    InsnLeaf {
        chip,
        extra_add,
        extra_lt,
    }
}

/// Adds one instruction's rows to `rows` and returns how many it added.
#[inline(always)]
pub fn add_insn_leaf_rows(rows: &mut [u32; LEAF_INSN_CHIPS], opcode: Opcode) -> u32 {
    let leaf = insn_leaf(opcode);
    rows[LEAF_CPU] += 1;
    rows[LEAF_ADD] += leaf.extra_add;
    rows[LEAF_LT] += leaf.extra_lt;
    let mut added = 1 + leaf.extra_add + leaf.extra_lt;
    if let Some(chip) = leaf.chip {
        rows[chip] += 1;
        added += 1;
    }
    added
}

/// Rows as the GKR input counts them: a power of two, at least 2^l_skip. An absent chip is
/// charged the minimum too; that is a few thousand leaves in all, and keeps the estimate
/// monotone in the counts.
#[inline(always)]
fn lifted_rows(rows: u64) -> u64 {
    rows.next_power_of_two().max(LEAF_MIN_ROWS)
}

/// `MemoryUnaligned`'s rows for `misaligned` accesses: the core shape's height that holds them,
/// one of `MLE_MEMORY_UNALIGNED_LOG_HEIGHTS`, which every core shape carries (even at none).
#[inline]
fn unaligned_rows(misaligned: u64) -> u64 {
    1 << unaligned_log_height(usize::try_from(misaligned).unwrap_or(usize::MAX))
}

// ============================================================================
// Ladder fit
// ============================================================================
//
// In whitelist mode a CPU chunk proves under the first row of `MLE_CORE_LADDER` that holds its
// rows chip by chip. One that no row holds selects the catch-all, which the provers refuse as too
// large to prove (`CatchAllShape`), and a chunk can outgrow that one too: it stands at 2^22 rows
// an arithmetic table, under 2^23 instructions. The clk limit admits those instructions whatever
// they are, while the rows follow the mix: LessThan takes one for every comparison and one for
// every branch, so a chunk more than half of which is those has no shape at all. The split
// therefore closes a chunk while a row still holds it.
//
// It does so when the emulation's options ask for it (`EmulatorOpts::ladder_fit`), as a prover
// does in whitelist mode. With the whitelist off a chunk proves at the heights it has and no row
// is asked for, so the split leaves it as it was: a program whose mix leaves the ladder has more
// chunks under the whitelist than without it.
//
// The fit reads the chips whose height differs from one row to another. Byte and Program have
// one height in every row; Global has one in every core shape and a cap of its own
// (`at_global_cap`). MemoryUnaligned has a cap of its own too (`at_misaligned_cap`), the most any
// row holds, and a row's entry is the most that row holds: the fit reads it, so a chunk of many
// misaligned accesses leaves a row whose entry is lower.
//
// The rows are counted never under what the traces of an unsplit replay hold, so a chunk the
// fit lets grow selects a ladder row. MemoryReadWrite is counted over: it also takes the
// chunk's jumps for loads. A chunk at the edge of the last row that holds it can close a little
// early for that. What the fit does not bound:
// - what a single step adds past `LEAF_STEP_GROWTH`, a syscall touching that many new addresses;
// - a commit tail in flight, which the split holds for;
// - the windows of a replay cut into segments (`MLE_SPLIT_REPLAY`). The fold keeps a window for
//   an address on each side of a cut (`record_merge`), so a chunk replayed that way has more
//   MemoryLocal rows than are counted here.

/// The chips the fit reads beyond the per-instruction ones, as indices into a row of
/// [`ladder_caps`].
const FIT_MEMORY_RW: usize = LEAF_INSN_CHIPS;
const FIT_MEMORY_LOCAL: usize = LEAF_INSN_CHIPS + 1;
const FIT_SYSCALL: usize = LEAF_INSN_CHIPS + 2;
const FIT_MEMORY_UNALIGNED: usize = LEAF_INSN_CHIPS + 3;
const FIT_CHIPS: usize = LEAF_INSN_CHIPS + 4;

/// The ladder's name for each of them, in index order: the `LEAF_*` chips, then the `FIT_*`
/// ones; [`ChunkSplitState::fit_rows`] counts them. They are the chips whose height differs
/// from one row to another, which a test holds the ladder to.
const FIT_CHIP_NAMES: [&str; FIT_CHIPS] = [
    "Cpu",
    "Add",
    "Sub",
    "Addw",
    "Subw",
    "Mul",
    "DivRem",
    "LessThan",
    "ShiftLeft",
    "ShiftRight",
    "Bitwise",
    "Ecall",
    "MemoryReadWrite",
    "MemoryLocal",
    "SyscallRiscv",
    "MemoryUnaligned",
];

/// The rows each row of [`MLE_CORE_LADDER`] admits of each chip, built once.
fn ladder_caps() -> &'static [[u64; FIT_CHIPS]] {
    static CAPS: std::sync::OnceLock<Vec<[u64; FIT_CHIPS]>> = std::sync::OnceLock::new();
    CAPS.get_or_init(|| {
        MLE_CORE_LADDER
            .iter()
            .map(|row| {
                FIT_CHIP_NAMES.map(|name| {
                    let (_, log) = row
                        .iter()
                        .find(|(chip, _)| *chip == name)
                        .unwrap_or_else(|| panic!("a core ladder row has no height for {name}"));
                    1u64 << log
                })
            })
            .collect()
    })
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

    #[cfg(test)]
    fn words(&self) -> &[u64] {
        // SAFETY: mmap is allocated with byte_size = BITMAP_WORDS * size_of::<u64>().
        unsafe { std::slice::from_raw_parts(self.mmap.as_ptr() as *const u64, BITMAP_WORDS) }
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

    #[inline(always)]
    fn remove_dword_index(&mut self, dword_index: usize) -> bool {
        let word_index = dword_index >> 6;
        if word_index >= BITMAP_WORDS {
            return false;
        }
        let mask = 1u64 << (dword_index & 63);
        let word = &mut self.words_mut()[word_index];
        let was_set = (*word & mask) != 0;
        *word &= !mask;
        was_set
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
#[derive(Clone)]
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

    #[cfg(test)]
    fn words(&self) -> &[u64] {
        &self.words
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

    /// The word stays on the dirty list, so `clear` still visits it; an insert that refills it lists
    /// it again, which `clear` only zeroes twice.
    #[inline(always)]
    fn remove_dword_index(&mut self, dword_index: usize) -> bool {
        let word_index = dword_index >> 6;
        if word_index >= self.words.len() {
            return false;
        }
        let mask = 1u64 << (dword_index & 63);
        let word = &mut self.words[word_index];
        let was_set = (*word & mask) != 0;
        *word &= !mask;
        was_set
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

impl SimpleBitSet {
    /// Every dword marked, in order. Walks the whole bitmap, megabytes and under `mmap-memory`
    /// every page of it, so it stays out of `Debug`.
    #[cfg(test)]
    fn marked_dwords(&self) -> Vec<usize> {
        self.words()
            .iter()
            .enumerate()
            .filter(|&(_, &word)| word != 0)
            .flat_map(|(index, &word)| {
                (0..64usize)
                    .filter(move |&bit| word & (1u64 << bit) != 0)
                    .map(move |bit| index * 64 + bit)
            })
            .collect()
    }
}

/// The size and backing, never the contents: any `{:?}` of a `ChunkSplitState` lands here, and
/// reading the bitmap costs megabytes. [`SimpleBitSet::marked_dwords`] lists the contents.
impl std::fmt::Debug for SimpleBitSet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let backing = if cfg!(feature = "mmap-memory") {
            "mmap"
        } else {
            "boxed"
        };
        f.debug_struct("SimpleBitSet")
            .field("dwords", &(BITMAP_WORDS * 64))
            .field("backing", &backing)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Clone, Default)]
pub struct ChunkSplitState {
    pub num_syscall_events: usize,
    /// Memory accesses inside syscalls, repeats included. No split condition reads it; the
    /// interpreter-vs-AOT parity checks compare it.
    pub num_syscall_memory_events: usize,
    pub num_memory_read_write_events: usize,
    pub num_global_lookup_base: usize,
    memory_access_addrs: SimpleBitSet,
    unique_memory_addrs: usize,
    /// Dwords with a CPU memory window open in this chunk. A precompile touching one closes the
    /// window into the chunk's record (`SyscallContext::postprocess`), and the CPU's next access
    /// opens another: one more MemoryLocal row and Global lookup that `memory_access_addrs`,
    /// counting each address once, does not see.
    cpu_windows: SimpleBitSet,
    /// Windows closed that way, counted as reopened whether or not the CPU comes back.
    reopened_windows: usize,
    reg_write_mask: u32,
    unique_reg_writes: usize,
    syscall_depth: u32,
    /// The chunk has run some but not all of a digest's COMMIT (or COMMIT_DEFERRED_PROOFS)
    /// ecalls: the guest is mid-way through them. Set by the COMMIT handlers after every word they
    /// write, cleared when the chunk closes; `should_split` holds the cut while it is set.
    pub commit_in_flight: bool,
    /// COMMIT and COMMIT_DEFERRED_PROOFS ecalls run in this chunk. Counted rather than read off
    /// the digests, whose words may be zero (all of them, for a guest that defers nothing).
    pub commits: u32,
    /// Rows of the per-instruction chips (`LEAF_*`) in this chunk.
    pub leaf_rows: [u32; LEAF_INSN_CHIPS],
    /// At least the rows any one chip has gained since `leaf_allowance` was last set: every
    /// counter feeds it the most rows its event adds to a single chip.
    leaf_growth: std::cell::Cell<u64>,
    /// Growth the leaf cap still admits, as of the last estimate; spent, the estimate is redone.
    /// Starts at 0, so a fresh chunk estimates on its first check.
    leaf_allowance: std::cell::Cell<u64>,
    /// Misaligned loads and stores run in this chunk outside unconstrained mode: the rows its
    /// `MemoryUnaligned` trace takes. Counted by both emulators' `misaligned`.
    pub num_misaligned: usize,
}

/// Whether the chunk may be at a split point, a cheap test that skips `should_split` far from
/// every threshold. The misaligned and Global caps have no margin: they are the exact limits
/// `should_split` tests, the Global one as for a chunk with no commit tail in flight, which is
/// the earlier of its two.
#[inline(always)]
pub fn should_check_fast(clk: u32, state: &ChunkSplitState, cfg: &ChunkSplitConfig) -> bool {
    clk >= cfg.clk_fast_threshold
        || state.num_memory_read_write_events >= cfg.event_fast_threshold
        || ((cfg.leaf_cap != 0 || cfg.ladder_fit)
            && state.leaf_growth.get() + LEAF_STEP_GROWTH > state.leaf_allowance.get())
        || at_misaligned_cap(state, cfg)
        || at_global_cap(state, cfg, false)
}

/// The event arm: the chunk's memory events and global lookups have both reached their
/// thresholds, one of them past it.
#[inline(always)]
fn over_event_limit(state: &ChunkSplitState, cfg: &ChunkSplitConfig) -> bool {
    (state.num_memory_read_write_events > cfg.memory_rw_threshold
        && state.num_global_lookup_base >= cfg.global_lookup_base_threshold)
        || (state.num_memory_read_write_events >= cfg.memory_rw_threshold
            && state.num_global_lookup_base > cfg.global_lookup_base_threshold)
}

/// The chunk holds as many misaligned accesses as its `MemoryUnaligned` trace has rows.
#[inline(always)]
fn at_misaligned_cap(state: &ChunkSplitState, cfg: &ChunkSplitConfig) -> bool {
    state.num_misaligned >= cfg.misaligned_threshold
}

/// Cross-chunk events one more step may add to a chunk, for the cap on them: an instruction
/// touches a few registers and dwords, two events for each, and a precompile call sends one
/// syscall event and closes the chunk's window on each dword of its operands that has one open
/// (the dwords themselves travel with the precompile's own record). A step that added more
/// than this would overrun the cap by the excess, and the prover refuses such a chunk where it
/// commits the table.
pub const GLOBAL_STEP_EVENTS: usize = 1 << 10;

/// Cross-chunk events a commit tail may add once its first word is written: its ecalls, an
/// event each, and the few registers and dwords their arguments touch, two events for each.
/// Sixteen ecalls come to well under this.
///
/// A chunk with no tail in flight closes this much earlier, so that a tail that starts in it
/// finishes in it: the hold of a tail in flight spends the room, as it spends the clk reserve.
pub const GLOBAL_TAIL_EVENTS: usize = 1 << 8;

/// The chunk's cross-chunk events leave no room in its `Global` table for another step. The
/// count is the split state's, two events per base entry, which is never below the events the
/// chunk's record carries when it is replayed in one piece. A replay cut into segments folds
/// to a record with two more events for every address live across a cut, and a fold past the
/// table has those rejoined (`record_merge`).
///
/// `hold` is a commit tail in flight, which may spend the room kept for one
/// ([`GLOBAL_TAIL_EVENTS`]); the room for the next step is never spent.
#[inline(always)]
fn at_global_cap(state: &ChunkSplitState, cfg: &ChunkSplitConfig, hold: bool) -> bool {
    let room = if hold {
        GLOBAL_STEP_EVENTS
    } else {
        GLOBAL_STEP_EVENTS + GLOBAL_TAIL_EVENTS
    };
    state.num_global_lookup_events().saturating_add(room) > cfg.global_event_cap
}

/// Whether the commit tail is mid-way: the chunk has run some but not all of the eight words of a
/// digest. The guest commits the output digest and then the deferred one, eight words each, so
/// that is a count that is not a multiple of eight. The recursion takes each digest only from a
/// chunk that ran all eight of its words, so a cut inside a run leaves an honest execution
/// unprovable.
#[inline(always)]
pub fn commit_tail_in_flight(commits: u32) -> bool {
    !(commits as usize).is_multiple_of(DIGEST_SIZE)
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
    // The chunk's misaligned accesses fill its `MemoryUnaligned` trace: no hold lifts that. Each
    // instruction makes at most one, so a chunk closed here holds exactly the cap.
    let misaligned_full = at_misaligned_cap(state, cfg);
    // The chunk's cross-chunk events fill its `Global` table: no event-limit switch lifts that,
    // and a hold only spends the room kept for a commit tail.
    let global_full = at_global_cap(state, cfg, hold);
    // A half-written digest holds the event arm too: a cut between two COMMIT ecalls splits the
    // digest whatever triggered it. The hold ends when the digest is whole or at the ceiling,
    // which is where a chunk closed before the reserve existed, so no chunk outgrows its old
    // bound; a chunk that does reach the ceiling still split is the case this cannot fix, and so
    // is a commit tail whose own misaligned accesses fill the chunk, which the SDK's never makes.
    if hold {
        if is_max_chunk_size || misaligned_full || global_full {
            tracing::warn!(
                "[chunk-split] closing a chunk at clk {clk} with its commit tail in flight: it \
                 outran the {} clk the hold may spend, made its {}th misaligned access or filled \
                 its Global table, and the recursion will reject the split (a partial run of \
                 either digest at convert)",
                cfg.commit_tail_reserve.max(cfg.commit_tail_overrun),
                cfg.misaligned_threshold,
            );
        }
        return is_max_chunk_size || misaligned_full || global_full;
    }
    // Checked after a step, the cap has to hold for the next one too: the estimate can jump by
    // a whole chip's leaves when its rows pass a power of two. So has the ladder: the next step
    // may be the row that the last ladder row to hold the chunk cannot take.
    let over_leaf_cap = !state.leaf_room(LEAF_STEP_GROWTH, cfg);

    is_max_chunk_size
        || over_event_limit(state, cfg)
        || over_leaf_cap
        || misaligned_full
        || global_full
}

/// Whether a compiled block can run whole without reaching a split point, so that the cut after it
/// is the cut the interpreter makes. The counts are the block's static bounds: its instructions,
/// its memory events and non-register global lookups when every access is aligned, the registers
/// it writes, and its loads and stores (`memory_insns`).
///
/// A misaligned access is one of the block's loads and stores, so `memory_insns` bounds the
/// misaligned accesses it can add, and the block must leave the chunk below the cap. One that runs
/// into the next dword touches that one too: one more address, and, for a store, one more memory
/// event than the aligned counts; `memory_insns` bounds those as well.
#[allow(clippy::too_many_arguments)]
#[inline(always)]
pub fn can_fit_block(
    clk: u32,
    insn_count: u32,
    mem_rw_exact: usize,
    non_register_global_lookup_base_max: usize,
    reg_write_mask: u32,
    memory_insns: usize,
    state: &ChunkSplitState,
    cfg: &ChunkSplitConfig,
) -> bool {
    let cost = insn_count.saturating_mul(4);
    let remaining = cfg.clk_threshold.saturating_sub(clk);
    if cost > remaining {
        return false;
    }

    if state.num_misaligned.saturating_add(memory_insns) >= cfg.misaligned_threshold {
        return false;
    }

    // The most rows the block can add to one chip: per instruction its Cpu and ALU rows and up
    // to three derived ones, each memory event, and two global lookups per new base entry; and,
    // for each of its loads and stores that runs into the next dword, one more memory event and
    // two more lookups for the address it adds.
    let leaf_growth = 5 * u64::from(insn_count)
        + mem_rw_exact as u64
        + 3 * memory_insns as u64
        + 2 * (non_register_global_lookup_base_max as u64 + u64::from(reg_write_mask.count_ones()));
    // The leaf cap and the ladder fit both: neither lets a chip grow that much.
    if !state.leaf_room(leaf_growth, cfg) {
        return false;
    }

    // The most base entries the chunk holds after the block, for the Global cap and the event
    // arm alike.
    let new_reg_writes = (reg_write_mask & !state.reg_write_mask).count_ones() as usize;
    let projected_global = state
        .num_global_lookup_base
        .saturating_add(non_register_global_lookup_base_max)
        .saturating_add(memory_insns)
        .saturating_add(new_reg_writes);
    // As for a chunk with no commit tail in flight: a block that runs a tail's ecalls stops at
    // each of them, and one refused here is stepped through under `should_split`.
    if (projected_global << 1).saturating_add(GLOBAL_STEP_EVENTS + GLOBAL_TAIL_EVENTS)
        > cfg.global_event_cap
    {
        return false;
    }

    let projected_memory = state
        .num_memory_read_write_events
        .saturating_add(mem_rw_exact)
        .saturating_add(memory_insns);
    if projected_memory < cfg.memory_rw_threshold {
        return true;
    }

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
                self.grow_leaves(2);
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
            self.grow_leaves(2);
        }
        if !self.in_syscall() {
            self.cpu_windows.insert_dword_index(dword_index);
        } else if self.cpu_windows.remove_dword_index(dword_index) {
            self.reopened_windows += 1;
            self.num_global_lookup_base += 1;
            self.grow_leaves(2);
        }
    }

    #[inline(always)]
    pub fn unique_address_count(&self) -> usize {
        self.unique_memory_addrs + self.unique_reg_writes
    }

    /// The dwords its two bitmaps mark, `[memory_access_addrs, cpu_windows]`: what its `Debug`
    /// leaves out.
    #[cfg(test)]
    pub(crate) fn marked_dwords(&self) -> [Vec<usize>; 2] {
        [
            self.memory_access_addrs.marked_dwords(),
            self.cpu_windows.marked_dwords(),
        ]
    }

    #[inline(always)]
    pub fn record_syscall_event(&mut self) {
        self.num_syscall_events += 1;
        self.num_global_lookup_base += 1;
        self.grow_leaves(2);
    }

    /// Not a global lookup of this chunk: a precompile's memory events travel with it to its own
    /// record. What it costs this chunk, each address once and each CPU window it closes, is
    /// counted by `track_address`.
    #[inline(always)]
    pub fn add_syscall_memory_events(&mut self, count: usize) {
        self.num_syscall_memory_events += count;
    }

    #[inline(always)]
    pub fn add_memory_rw_events(&mut self, count: usize) {
        self.num_memory_read_write_events += count;
        self.grow_leaves(count as u64);
    }

    /// Counts one executed instruction's rows on the per-instruction chips.
    #[inline(always)]
    pub fn count_insn(&mut self, opcode: Opcode) {
        let added = add_insn_leaf_rows(&mut self.leaf_rows, opcode);
        self.grow_leaves(u64::from(added));
    }

    /// Adds `rows` rows to the per-instruction chip `chip`: a straight-line block's count,
    /// tallied when it was compiled.
    #[inline(always)]
    pub fn add_leaf_rows(&mut self, chip: usize, rows: u32) {
        self.leaf_rows[chip] += rows;
        self.grow_leaves(u64::from(rows));
    }

    #[inline(always)]
    fn grow_leaves(&mut self, rows: u64) {
        let growth = self.leaf_growth.get_mut();
        *growth += rows;
    }

    /// The chunk's leaves were every chip `growth` rows taller, Cpu at most `max_cpu_rows` and
    /// MemoryReadWrite at most `max_memory_rw`.
    fn leaf_estimate_after(&self, growth: u64, max_cpu_rows: u64, max_memory_rw: u64) -> u64 {
        let mut leaves = LEAF_FIXED_ALLOWANCE;
        for (chip, (&rows, &interactions)) in self
            .leaf_rows
            .iter()
            .zip(LEAF_INSN_INTERACTIONS.iter())
            .enumerate()
        {
            let rows = u64::from(rows);
            let grown = if chip == LEAF_CPU {
                (rows + growth).min(max_cpu_rows.max(rows))
            } else {
                rows + growth
            };
            leaves += interactions * lifted_rows(grown);
        }
        let memory_rw = self.num_memory_read_write_events as u64;
        let local = (self.unique_address_count() + self.reopened_windows) as u64;
        leaves += LEAF_MEMORY_RW_INTERACTIONS
            * lifted_rows((memory_rw + growth).min(max_memory_rw.max(memory_rw)));
        leaves += LEAF_MEMORY_LOCAL_INTERACTIONS
            * lifted_rows(local.div_ceil(LOCAL_MEMORY_DATAPAR as u64) + growth);
        leaves += LEAF_SYSCALL_INTERACTIONS * lifted_rows(self.num_syscall_events as u64 + growth);
        leaves += LEAF_MEMORY_UNALIGNED_INTERACTIONS
            * unaligned_rows(self.num_misaligned as u64 + growth);
        leaves
    }

    /// The chunk's LogUp-GKR leaves as the rows stand: never fewer than the prover will count.
    pub fn leaf_estimate(&self) -> u64 {
        self.leaf_estimate_after(0, u64::MAX, u64::MAX)
    }

    /// Whether the leaf cap and the ladder fit leave room for every chip to grow `growth` more
    /// rows. Cheap while the allowance of the last estimate lasts; once it is spent the estimate
    /// is redone.
    #[inline(always)]
    pub fn leaf_room(&self, growth: u64, cfg: &ChunkSplitConfig) -> bool {
        if (cfg.leaf_cap == 0 && !cfg.ladder_fit)
            || self.leaf_growth.get() + growth <= self.leaf_allowance.get()
        {
            return true;
        }
        self.refresh_leaf_allowance(cfg) && growth <= self.leaf_allowance.get()
    }

    /// Re-estimates, and sets the allowance to the most growth (the same for every chip) under
    /// which the estimate stays within the cap and a ladder row holds the chunk. False if it is
    /// over the cap, or out of every row, already.
    #[cold]
    fn refresh_leaf_allowance(&self, cfg: &ChunkSplitConfig) -> bool {
        let (max_cpu_rows, max_memory_rw) = self.row_ceilings(cfg);
        let fits = |growth: u64| {
            cfg.leaf_cap == 0
                || self.leaf_estimate_after(growth, max_cpu_rows, max_memory_rw) <= cfg.leaf_cap
        };
        // With no ladder to fit, more than a chunk has rows.
        let ladder_room = if cfg.ladder_fit {
            self.ladder_room(max_cpu_rows)
        } else {
            Some(1 << 26)
        };
        self.leaf_growth.set(0);
        let Some(ladder_room) = ladder_room.filter(|_| fits(0)) else {
            self.leaf_allowance.set(0);
            return false;
        };
        // The estimate only grows with `growth`: bisect for the last value that fits, among
        // those the ladder leaves. Far from the leaf cap that is the ladder's own, at the cost
        // of one estimate.
        let (mut lo, mut hi) = (0u64, ladder_room.min(1 << 26));
        if fits(hi) {
            lo = hi;
        } else {
            while hi - lo > 1 {
                let mid = lo + (hi - lo) / 2;
                if fits(mid) {
                    lo = mid;
                } else {
                    hi = mid;
                }
            }
        }
        self.leaf_allowance.set(lo);
        true
    }

    /// The rows Cpu and MemoryReadWrite can reach in this chunk, where something else stops them.
    fn row_ceilings(&self, cfg: &ChunkSplitConfig) -> (u64, u64) {
        // The clk ceiling stops Cpu below its next power of two; without this every chunk's
        // last stretch would look one Cpu doubling away from the cap.
        let max_cpu_rows = u64::from(cfg.max_chunk_clk() + cfg.commit_tail_overrun) / 4;
        // Likewise the event arm: once the global lookups are past their threshold it cuts as
        // the memory events reach theirs, and MemoryReadWrite never takes its next doubling.
        let max_memory_rw = match self
            .num_global_lookup_base
            .cmp(&cfg.global_lookup_base_threshold)
        {
            std::cmp::Ordering::Greater => cfg.memory_rw_threshold as u64,
            std::cmp::Ordering::Equal => cfg.memory_rw_threshold as u64 + 1,
            std::cmp::Ordering::Less => u64::MAX,
        };
        (max_cpu_rows, max_memory_rw)
    }

    /// The chunk's rows on the chips the ladder fit reads: at least what their traces will hold.
    ///
    /// MemoryLocal is counted as the leaf estimate counts it. MemoryReadWrite is not: the
    /// estimate charges it the chunk's memory events, which count every register access and
    /// run to three times its rows. It holds a row for each load and store, and one more for
    /// one that runs into the next dword. An instruction that is neither has its row on
    /// another chip, unless it is a jump, and a signed division is charged two rows beside its
    /// own; so the loads and stores are at most the instructions that left no such row.
    ///
    /// The base entries count a register once the chunk writes it. One the chunk only reads
    /// has a window too, a MemoryLocal entry the estimate does not see, so the fit charges all
    /// 32 registers from the start.
    fn fit_rows(&self) -> [u64; FIT_CHIPS] {
        let mut rows = [0u64; FIT_CHIPS];
        for (chip, &insn_rows) in self.leaf_rows.iter().enumerate() {
            rows[chip] = u64::from(insn_rows);
        }
        let dispatched: u64 = rows[LEAF_CPU + 1..LEAF_INSN_CHIPS].iter().sum();
        let loads_and_stores = (rows[LEAF_CPU] + 2 * rows[LEAF_DIVREM]).saturating_sub(dispatched);
        let unwritten = (32 - self.unique_reg_writes) as u64;
        let local = (self.unique_address_count() + self.reopened_windows) as u64 + unwritten;
        rows[FIT_MEMORY_RW] = loads_and_stores + self.num_misaligned as u64;
        rows[FIT_MEMORY_LOCAL] = local.div_ceil(LOCAL_MEMORY_DATAPAR as u64);
        rows[FIT_SYSCALL] = self.num_syscall_events as u64;
        rows[FIT_MEMORY_UNALIGNED] = self.num_misaligned as u64;
        rows
    }

    /// The most rows every chip can grow by and leave the chunk in a row of the core ladder, Cpu
    /// growing to at most `max_cpu_rows`: what the row with the most room leaves. `None` if no
    /// row holds the chunk as it stands.
    fn ladder_room(&self, max_cpu_rows: u64) -> Option<u64> {
        let rows = self.fit_rows();
        ladder_caps()
            .iter()
            .filter_map(|caps| {
                let mut room = u64::MAX;
                for (chip, (&have, &cap)) in rows.iter().zip(caps).enumerate() {
                    let left = cap.checked_sub(have)?;
                    // The clk ceiling stops Cpu: under the row's height, it takes no room.
                    if chip != LEAF_CPU || max_cpu_rows > cap {
                        room = room.min(left);
                    }
                }
                Some(room)
            })
            .max()
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

    #[allow(clippy::too_many_arguments)]
    #[inline(always)]
    pub fn can_fit_block(
        &self,
        clk: u32,
        insn_count: u32,
        mem_rw_exact: usize,
        non_register_global_lookup_base_max: usize,
        reg_write_mask: u32,
        memory_insns: usize,
        cfg: &ChunkSplitConfig,
    ) -> bool {
        can_fit_block(
            clk,
            insn_count,
            mem_rw_exact,
            non_register_global_lookup_base_max,
            reg_write_mask,
            memory_insns,
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
        self.reopened_windows = 0;
        self.reg_write_mask = 0;
        self.unique_reg_writes = 0;
        self.syscall_depth = 0;
        self.commit_in_flight = false;
        self.commits = 0;
        self.num_misaligned = 0;
        self.memory_access_addrs.clear();
        self.cpu_windows.clear();
        self.leaf_rows = [0; LEAF_INSN_CHIPS];
        self.leaf_growth.set(0);
        self.leaf_allowance.set(0);
    }
}

#[cfg(test)]
mod tests {
    use super::{
        add_insn_leaf_rows, can_fit_block, commit_tail_in_flight, ladder_caps, should_check_fast,
        should_split, ChunkSplitConfig, ChunkSplitState, Opcode, SimpleBitSet, BITMAP_WORDS,
        CHUNK_CLK_START, FIT_CHIPS, FIT_CHIP_NAMES, FIT_MEMORY_LOCAL, FIT_MEMORY_RW, FIT_SYSCALL,
        GLOBAL_STEP_EVENTS, GLOBAL_TAIL_EVENTS, LEAF_ADD, LEAF_ADDW, LEAF_BITWISE, LEAF_CPU,
        LEAF_DIVREM, LEAF_ECALL, LEAF_GLOBAL_INTERACTIONS, LEAF_INSN_CHIPS, LEAF_INSN_INTERACTIONS,
        LEAF_LT, LEAF_MEMORY_LOCAL_INTERACTIONS, LEAF_MEMORY_RW_INTERACTIONS,
        LEAF_MEMORY_UNALIGNED_INTERACTIONS, LEAF_MUL, LEAF_SLL, LEAF_SR, LEAF_STEP_GROWTH,
        LEAF_SUB, LEAF_SUBW, LEAF_SYSCALL_INTERACTIONS,
    };
    use crate::{
        chips::chips::riscv_memory::event::MemoryAccessPosition,
        emulator::opts::EmulatorOpts,
        mle::machine::shape::{
            select_core_rung, MLE_CORE_LADDER, MLE_GLOBAL_LOG_HEIGHT,
            MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT,
        },
        primitives::consts::{BENCH_MAX_CHUNK_SIZE, LOCAL_MEMORY_DATAPAR},
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
        assert_eq!(state.num_global_lookup_base, 3);
        assert_eq!(state.num_global_lookup_events(), 6);
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
        assert_eq!(state.num_global_lookup_base, 1);
    }

    #[test]
    fn a_precompile_closing_a_cpu_window_counts_its_reopening() {
        let mut state = ChunkSplitState::default();

        // The CPU opens a window on the dword; a precompile then touches it twice.
        state.track_address(0x100);
        state.enter_syscall();
        state.track_address(0x100);
        state.track_address(0x104);
        state.exit_syscall();
        assert_eq!(state.unique_address_count(), 1);
        assert_eq!(state.reopened_windows, 1);
        assert_eq!(state.num_global_lookup_base, 2);

        // Each time the CPU comes back and a precompile follows, one more.
        state.track_address(0x100);
        state.enter_syscall();
        state.track_address(0x100);
        state.exit_syscall();
        assert_eq!(state.reopened_windows, 2);
        assert_eq!(state.num_global_lookup_base, 3);
    }

    #[test]
    fn a_precompile_alone_opens_no_cpu_window() {
        let mut state = ChunkSplitState::default();

        state.enter_syscall();
        state.track_address(0x100);
        state.track_address(0x100);
        state.exit_syscall();
        assert_eq!(state.reopened_windows, 0);
        assert_eq!(state.num_global_lookup_base, 1);

        // The window the CPU opens afterwards is the address's first, already counted.
        state.track_address(0x100);
        assert_eq!(state.num_global_lookup_base, 1);

        state.clear();
        state.enter_syscall();
        state.track_address(0x100);
        state.exit_syscall();
        assert_eq!(state.reopened_windows, 0, "clear forgets the windows");
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
            leaf_cap: 0,
            misaligned_threshold: usize::MAX,
            global_event_cap: usize::MAX,
            ladder_fit: false,
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
            leaf_cap: 0,
            misaligned_threshold: usize::MAX,
            global_event_cap: usize::MAX,
            ladder_fit: false,
        };
        let state = ChunkSplitState {
            num_memory_read_write_events: 3,
            num_global_lookup_base: 1,
            ..Default::default()
        };

        assert!(!can_fit_block(0, 1, 2, 1, 0, 0, &state, &cfg));
        assert!(can_fit_block(0, 1, 1, 1, 0, 0, &state, &cfg));
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
            leaf_cap: 0,
            misaligned_threshold: usize::MAX,
            global_event_cap: usize::MAX,
            ladder_fit: false,
        };
        let mut state = ChunkSplitState {
            num_memory_read_write_events: 3,
            ..Default::default()
        };
        state.track_address(1);

        assert!(can_fit_block(0, 1, 1, 0, 1 << 1, 0, &state, &cfg));
        assert!(!can_fit_block(0, 1, 1, 0, 1 << 2, 0, &state, &cfg));
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
            leaf_cap: 0,
            misaligned_threshold: usize::MAX,
            global_event_cap: usize::MAX,
            ladder_fit: false,
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
            leaf_cap: 0,
            misaligned_threshold: usize::MAX,
            global_event_cap: usize::MAX,
            ladder_fit: false,
        }
    }

    #[test]
    fn a_commit_run_is_in_flight_until_its_eighth_word() {
        // Eight output words, then eight deferred words: in flight inside either run, not before,
        // between or after them.
        for n in 0..=16 {
            assert_eq!(commit_tail_in_flight(n), n % 8 != 0, "after {n} words");
        }
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
            commits: 5,
            ..Default::default()
        };
        state.clear();
        assert!(!state.commit_in_flight);
        assert_eq!(state.commits, 0);
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

    fn leaf_cfg(leaf_cap: u64) -> ChunkSplitConfig {
        ChunkSplitConfig {
            leaf_cap,
            ..ChunkSplitConfig::disabled(0)
        }
    }

    #[test]
    fn a_signed_division_charges_divrem_and_two_adds_and_a_branch_one_lt() {
        let mut rows = [0u32; LEAF_INSN_CHIPS];
        assert_eq!(add_insn_leaf_rows(&mut rows, Opcode::DIVW), 4);
        assert_eq!(add_insn_leaf_rows(&mut rows, Opcode::DIVU), 2);
        assert_eq!(add_insn_leaf_rows(&mut rows, Opcode::BNE), 2);
        assert_eq!(add_insn_leaf_rows(&mut rows, Opcode::LD), 1);
        assert_eq!(rows[LEAF_CPU], 4);
        assert_eq!(rows[LEAF_DIVREM], 2);
        assert_eq!(rows[LEAF_ADD], 2);
        assert_eq!(rows[LEAF_LT], 1);
    }

    #[test]
    fn the_estimate_lifts_rows_to_powers_of_two() {
        let mut state = ChunkSplitState::default();
        let empty = state.leaf_estimate();
        // 17 divisions: DivRem goes from the 16-row floor to 32 rows.
        for _ in 0..17 {
            state.count_insn(Opcode::DIVU);
        }
        let grown = state.leaf_estimate();
        let cpu = LEAF_INSN_INTERACTIONS[LEAF_CPU] * (32 - 16);
        let divrem = LEAF_INSN_INTERACTIONS[LEAF_DIVREM] * (32 - 16);
        assert_eq!(grown - empty, cpu + divrem);
    }

    #[test]
    fn the_leaf_cap_splits_before_a_step_could_cross_it() {
        let mut state = ChunkSplitState::default();
        let cap = state.leaf_estimate() + LEAF_INSN_INTERACTIONS[LEAF_DIVREM] * (1 << 20);
        let cfg = leaf_cfg(cap);
        assert!(!should_split(0, 0, &state, &cfg));
        // Divisions until DivRem's next doubling would no longer fit under the cap.
        let mut split_at = None;
        for n in 0..(1u32 << 21) {
            if should_split(0, 0, &state, &cfg) {
                split_at = Some(n);
                break;
            }
            state.count_insn(Opcode::DIVU);
        }
        let n = split_at.expect("the cap never split the chunk");
        assert!(
            state.leaf_estimate() <= cap,
            "split only after the cap was crossed"
        );
        assert!(n > 1 << 18, "split far too early, after {n} divisions");
        // Off, the same state never splits on leaves.
        assert!(!should_split(0, 0, &state, &leaf_cfg(0)));
    }

    /// The event arm stops MemoryReadWrite at its threshold once the lookups are past theirs, so
    /// the leaf arm must not cut ahead of it for a doubling that cannot happen.
    #[test]
    fn the_leaf_cap_leaves_memory_rw_to_the_event_arm() {
        let threshold = 1usize << 12;
        let state = |num_global_lookup_base| ChunkSplitState {
            num_memory_read_write_events: threshold - 8,
            num_global_lookup_base,
            ..Default::default()
        };
        // Room for everything but MemoryReadWrite's next doubling.
        let cap = state(2).leaf_estimate() + LEAF_MEMORY_RW_INTERACTIONS * (threshold as u64) / 2;
        let cfg = ChunkSplitConfig {
            memory_rw_threshold: threshold,
            global_lookup_base_threshold: 1,
            ..leaf_cfg(cap)
        };
        assert!(!should_split(0, 0, &state(2), &cfg));
        // Lookups not past their threshold: nothing stops the doubling, and the cap cuts first.
        let cfg = ChunkSplitConfig {
            global_lookup_base_threshold: 4,
            ..cfg
        };
        assert!(should_split(0, 0, &state(2), &cfg));
    }

    #[test]
    fn can_fit_block_refuses_a_block_the_leaf_cap_cannot_take() {
        let state = ChunkSplitState::default();
        let cfg = leaf_cfg(state.leaf_estimate() + 1_000);
        assert!(can_fit_block(0, 1, 0, 0, 0, 0, &state, &cfg));
        assert!(!can_fit_block(0, 1 << 16, 0, 0, 0, 0, &state, &cfg));
    }

    /// `MemoryUnaligned` counts at the core shape's height for the chunk's misaligned accesses:
    /// flat within a height, one step to the next past it.
    #[test]
    fn the_leaf_estimate_charges_the_unaligned_height_a_chunk_takes() {
        let at = |misaligned: usize| {
            ChunkSplitState {
                num_misaligned: misaligned,
                ..Default::default()
            }
            .leaf_estimate()
        };
        assert_eq!(at(0), at(1 << 10));
        assert_eq!(
            at((1 << 10) + 1) - at(1 << 10),
            LEAF_MEMORY_UNALIGNED_INTERACTIONS * ((1 << 16) - (1 << 10))
        );
        assert_eq!(
            at(1 << MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT) - at(0),
            LEAF_MEMORY_UNALIGNED_INTERACTIONS
                * ((1 << MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT) - (1 << 10))
        );
    }

    #[test]
    fn clear_resets_the_leaf_rows() {
        let mut state = ChunkSplitState::default();
        let empty = state.leaf_estimate();
        state.count_insn(Opcode::MUL);
        state.add_leaf_rows(LEAF_DIVREM, 1000);
        state.clear();
        assert_eq!(state.leaf_estimate(), empty);
    }

    /// The interaction counts the estimate charges are the AIRs' own.
    #[test]
    fn leaf_interaction_counts_match_the_airs() {
        use crate::{
            instances::chiptype::riscv_chiptype::RiscvChipType, machine::chip::ChipBehavior,
            primitives::consts::MAX_NUM_PVS,
        };
        use p3_air::BaseAir;
        use p3_koala_bear::KoalaBear;
        use pico_mle_core::{
            air::symbolic::get_symbolic_builder_with_public_values, keygen::types::TraceWidth,
        };

        let expected: [(&str, u64); LEAF_INSN_CHIPS + 5] = [
            ("Cpu", LEAF_INSN_INTERACTIONS[LEAF_CPU]),
            ("Add", LEAF_INSN_INTERACTIONS[LEAF_ADD]),
            ("Sub", LEAF_INSN_INTERACTIONS[LEAF_SUB]),
            ("Addw", LEAF_INSN_INTERACTIONS[LEAF_ADDW]),
            ("Subw", LEAF_INSN_INTERACTIONS[LEAF_SUBW]),
            ("Mul", LEAF_INSN_INTERACTIONS[LEAF_MUL]),
            ("DivRem", LEAF_INSN_INTERACTIONS[LEAF_DIVREM]),
            ("LessThan", LEAF_INSN_INTERACTIONS[LEAF_LT]),
            ("ShiftLeft", LEAF_INSN_INTERACTIONS[LEAF_SLL]),
            ("ShiftRight", LEAF_INSN_INTERACTIONS[LEAF_SR]),
            ("Bitwise", LEAF_INSN_INTERACTIONS[LEAF_BITWISE]),
            ("Ecall", LEAF_INSN_INTERACTIONS[LEAF_ECALL]),
            ("MemoryReadWrite", LEAF_MEMORY_RW_INTERACTIONS),
            ("MemoryLocal", LEAF_MEMORY_LOCAL_INTERACTIONS),
            ("Global", LEAF_GLOBAL_INTERACTIONS),
            ("SyscallRiscv", LEAF_SYSCALL_INTERACTIONS),
            ("MemoryUnaligned", LEAF_MEMORY_UNALIGNED_INTERACTIONS),
        ];
        let chips = RiscvChipType::<KoalaBear>::all_chips();
        for (name, interactions) in expected {
            let chip = chips
                .iter()
                .find(|chip| chip.name() == name)
                .unwrap_or_else(|| panic!("no RISC-V chip named {name}"));
            let width = TraceWidth {
                preprocessed: None,
                cached_mains: vec![],
                common_main: BaseAir::<KoalaBear>::width(chip),
            };
            let builder =
                get_symbolic_builder_with_public_values::<KoalaBear, _>(chip, &width, MAX_NUM_PVS);
            assert_eq!(
                builder.constraints().interactions.len() as u64,
                interactions,
                "{name}"
            );
        }
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

    /// Event thresholds far off, and a cap of `cap` misaligned accesses.
    fn cap_cfg(cap: usize) -> ChunkSplitConfig {
        ChunkSplitConfig {
            memory_rw_threshold: 1 << 20,
            global_lookup_base_threshold: 1 << 18,
            event_fast_threshold: 1 << 19,
            misaligned_threshold: cap,
            ..reserve_cfg(0)
        }
    }

    #[test]
    fn a_chunk_closes_at_its_misaligned_cap() {
        let cfg = cap_cfg(3);
        let mut state = ChunkSplitState {
            num_misaligned: 2,
            ..Default::default()
        };
        assert!(!should_check_fast(128, &state, &cfg));
        assert!(!should_split(128, 0, &state, &cfg));
        state.num_misaligned = 3;
        assert!(should_check_fast(128, &state, &cfg));
        assert!(should_split(128, 0, &state, &cfg));
        state.clear();
        assert_eq!(state.num_misaligned, 0);
    }

    /// The hold spends clk; it cannot make room in a trace whose height is fixed.
    #[test]
    fn a_commit_tail_in_flight_does_not_hold_the_misaligned_cap() {
        let cfg = ChunkSplitConfig {
            misaligned_threshold: 3,
            ..reserve_cfg(32)
        };
        let mut state = ChunkSplitState {
            commit_in_flight: true,
            num_misaligned: 2,
            ..Default::default()
        };
        assert!(!should_split(128, 0, &state, &cfg));
        state.num_misaligned = 3;
        assert!(should_split(128, 0, &state, &cfg));
    }

    #[test]
    fn a_block_runs_whole_only_if_its_loads_and_stores_stay_below_the_cap() {
        let cfg = cap_cfg(4);
        let state = ChunkSplitState {
            num_misaligned: 1,
            ..Default::default()
        };
        // Two loads, both perhaps misaligned: the chunk ends the block with at most 3.
        assert!(can_fit_block(0, 2, 2, 2, 0b110, 2, &state, &cfg));
        // Three could make the chunk's fourth before the block's last instruction, and the
        // interpreter cuts right after it.
        assert!(!can_fit_block(0, 4, 3, 3, 0b1110, 3, &state, &cfg));
    }

    /// The event thresholds off, as `CHUNK_EVENT_LIMITS_OFF` sets them, and a `Global` table of
    /// `cap` rows.
    fn global_cap_cfg(cap: usize) -> ChunkSplitConfig {
        ChunkSplitConfig {
            memory_rw_threshold: usize::MAX,
            global_lookup_base_threshold: usize::MAX >> 2,
            event_fast_threshold: usize::MAX - ChunkSplitConfig::FAST_PATH_EVENT_MARGIN,
            global_event_cap: cap,
            ..reserve_cfg(0)
        }
    }

    /// The most base entries (two events each) a chunk with no commit tail in flight may hold
    /// and still take another step under a `Global` table of `cap` rows.
    fn base_room(cap: usize) -> usize {
        (cap - GLOBAL_STEP_EVENTS - GLOBAL_TAIL_EVENTS) / 2
    }

    /// The chunk closes while its `Global` table still has room for one more step, with the
    /// event arm switched off.
    #[test]
    fn a_chunk_closes_before_its_global_table_is_full() {
        let cap = 4 * GLOBAL_STEP_EVENTS;
        let cfg = global_cap_cfg(cap);
        let mut state = ChunkSplitState {
            num_global_lookup_base: base_room(cap),
            ..Default::default()
        };
        assert!(!should_check_fast(128, &state, &cfg));
        assert!(!should_split(128, 0, &state, &cfg));
        state.num_global_lookup_base += 1;
        assert!(should_check_fast(128, &state, &cfg));
        assert!(should_split(128, 0, &state, &cfg));
    }

    /// A commit tail in flight spends the room kept for it and no more: the hold cannot make
    /// room in a table whose height is fixed, so the room for the next step stays.
    #[test]
    fn a_commit_tail_in_flight_spends_its_room_under_the_global_cap() {
        let cap = 4 * GLOBAL_STEP_EVENTS;
        let cfg = ChunkSplitConfig {
            global_event_cap: cap,
            ..reserve_cfg(32)
        };
        let mut state = ChunkSplitState {
            num_global_lookup_base: base_room(cap) + 1,
            ..Default::default()
        };
        // No tail in flight: the chunk closes, with the tail's room still free.
        assert!(should_split(128, 0, &state, &cfg));
        // A tail in flight runs on through that room, up to the room of a step.
        state.commit_in_flight = true;
        assert!(!should_split(128, 0, &state, &cfg));
        state.num_global_lookup_base = (cap - GLOBAL_STEP_EVENTS) / 2;
        assert!(!should_split(128, 0, &state, &cfg));
        state.num_global_lookup_base += 1;
        assert!(should_split(128, 0, &state, &cfg));
    }

    #[test]
    fn a_block_runs_whole_only_if_the_global_table_has_room_for_it() {
        let cap = 4 * GLOBAL_STEP_EVENTS;
        let cfg = global_cap_cfg(cap);
        let state = ChunkSplitState {
            num_global_lookup_base: base_room(cap) - 4,
            ..Default::default()
        };
        // At most four new base entries: two addresses, one more for a load or store that runs
        // into the next dword, and one register.
        assert!(can_fit_block(0, 2, 2, 2, 0b10, 1, &state, &cfg));
        // A fifth could take the room the next step needs.
        assert!(!can_fit_block(0, 2, 2, 3, 0b10, 1, &state, &cfg));
    }

    /// The production cap is the height of the `Global` table, whatever the event-limit switch
    /// says; only a config that never cuts has none.
    #[test]
    fn the_global_cap_is_the_table_height() {
        assert_eq!(
            ChunkSplitConfig::for_chunk_size(1 << 23, 48).global_event_cap,
            1 << MLE_GLOBAL_LOG_HEIGHT
        );
        assert_eq!(ChunkSplitConfig::disabled(48).global_event_cap, usize::MAX);
    }

    /// A misaligned load or store that runs into the next dword touches that one too, beyond the
    /// block's aligned counts.
    #[test]
    fn can_fit_block_charges_each_load_and_store_a_second_dword() {
        let cfg = ChunkSplitConfig {
            chunk_size: 64,
            clk_threshold: 256,
            clk_fast_threshold: 240,
            memory_rw_threshold: 4,
            global_lookup_base_threshold: 2,
            event_fast_threshold: 3,
            commit_tail_reserve: 0,
            commit_tail_overrun: 0,
            leaf_cap: 0,
            misaligned_threshold: usize::MAX,
            global_event_cap: usize::MAX,
            ladder_fit: false,
        };
        let state = ChunkSplitState {
            num_memory_read_write_events: 2,
            num_global_lookup_base: 1,
            ..Default::default()
        };
        // One aligned store: 3 memory events and 2 lookups reach neither threshold.
        assert!(can_fit_block(0, 1, 1, 1, 0, 0, &state, &cfg));
        // The same store crossing into the next dword writes it too, at a new address: 4 events
        // and 3 lookups, and the interpreter would cut after it.
        assert!(!can_fit_block(0, 1, 1, 1, 0, 1, &state, &cfg));
    }

    #[test]
    fn the_cap_is_the_shapes_height_and_off_without_splitting() {
        assert_eq!(
            ChunkSplitConfig::for_chunk_size(1 << 23, 48).misaligned_threshold,
            1 << MLE_MEMORY_UNALIGNED_MAX_LOG_HEIGHT
        );
        assert_eq!(
            ChunkSplitConfig::disabled(48).misaligned_threshold,
            usize::MAX
        );
    }

    /// The options carry the fit to the split; the chunk size alone does not turn it on.
    #[test]
    fn the_fit_is_on_when_the_options_ask_for_it() {
        let opts = EmulatorOpts {
            chunk_size: 1 << 23,
            ..EmulatorOpts::default()
        };
        let plain = ChunkSplitConfig::for_chunk_size(1 << 23, 48);
        assert!(!plain.ladder_fit);
        assert!(!ChunkSplitConfig::for_opts(&opts, 48).ladder_fit);
        let fitted = ChunkSplitConfig::for_opts(&opts.with_ladder_fit(true), 48);
        assert!(fitted.ladder_fit);
        // Nothing else of the split moves with it.
        assert_eq!(fitted.clk_threshold, plain.clk_threshold);
        assert_eq!(fitted.memory_rw_threshold, plain.memory_rw_threshold);
        assert_eq!(fitted.leaf_cap, plain.leaf_cap);
    }

    /// The ladder fit and nothing else: no clk ceiling, no event arm, no leaf cap.
    fn ladder_cfg() -> ChunkSplitConfig {
        ChunkSplitConfig {
            ladder_fit: true,
            ..ChunkSplitConfig::disabled(0)
        }
    }

    /// The tallest height the ladder gives `chip`, in rows.
    fn tallest(chip: usize) -> u64 {
        ladder_caps().iter().map(|row| row[chip]).max().unwrap()
    }

    #[test]
    fn a_chunk_of_comparisons_and_branches_closes_under_the_lessthan_height() {
        let cfg = ladder_cfg();
        let mut state = ChunkSplitState::default();
        // A LessThan row an instruction: the comparison's own, and the one a branch derives.
        let mut steps = 0u64;
        while !should_split(0, 0, &state, &cfg) {
            state.count_insn(if steps.is_multiple_of(2) {
                Opcode::SLTU
            } else {
                Opcode::BNE
            });
            steps += 1;
        }
        // The split keeps a step's growth under the tallest LessThan of the ladder, and closes
        // the chunk on the first step that no longer has it. Without the fit this chunk runs to
        // the clk ceiling, with twice the rows the catch-all has.
        assert_eq!(steps, tallest(LEAF_LT) - LEAF_STEP_GROWTH + 1);
        assert_eq!(u64::from(state.leaf_rows[LEAF_LT]), steps);

        let off = ChunkSplitConfig::disabled(0);
        assert!(!should_split(0, 0, &state, &off));
    }

    #[test]
    fn the_fit_is_to_one_row_and_not_to_the_tallest_of_each_chip() {
        // Two chips whose tallest heights are in different rows.
        let at_tallest = |chip: usize| {
            ladder_caps()
                .iter()
                .enumerate()
                .filter(|(_, row)| row[chip] == tallest(chip))
                .map(|(i, _)| i)
                .collect::<Vec<_>>()
        };
        let pair = (LEAF_CPU + 1..LEAF_INSN_CHIPS)
            .flat_map(|a| (a + 1..LEAF_INSN_CHIPS).map(move |b| (a, b)))
            .find(|&(a, b)| at_tallest(a).iter().all(|row| !at_tallest(b).contains(row)));
        // A ladder with every chip at its tallest in one row leaves this nothing to tell apart.
        let Some((a, b)) = pair else { return };

        let cfg = ladder_cfg();
        let filled = |chips: &[usize]| {
            let mut state = ChunkSplitState::default();
            for &chip in chips {
                state.add_leaf_rows(chip, (tallest(chip) - 4 * LEAF_STEP_GROWTH) as u32);
            }
            state
        };
        assert!(!should_split(0, 0, &filled(&[a]), &cfg));
        assert!(!should_split(0, 0, &filled(&[b]), &cfg));
        assert!(should_split(0, 0, &filled(&[a, b]), &cfg));
    }

    #[test]
    fn can_fit_block_refuses_a_block_the_ladder_cannot_take() {
        let cfg = ladder_cfg();
        let mut state = ChunkSplitState::default();
        state.add_leaf_rows(LEAF_LT, (tallest(LEAF_LT) - 100) as u32);
        // A block is charged five rows an instruction: 50 fit under the height, 150 do not.
        assert!(can_fit_block(0, 10, 0, 0, 0, 0, &state, &cfg));
        assert!(!can_fit_block(0, 30, 0, 0, 0, 0, &state, &cfg));
    }

    #[test]
    fn a_commit_tail_in_flight_holds_the_ladder_fit_and_clear_resets_it() {
        let cfg = ChunkSplitConfig {
            ladder_fit: true,
            ..reserve_cfg(32)
        };
        let mut state = ChunkSplitState::default();
        state.add_leaf_rows(LEAF_LT, tallest(LEAF_LT) as u32);
        assert!(should_split(0, 0, &state, &cfg));
        state.commit_in_flight = true;
        assert!(!should_split(0, 0, &state, &cfg));

        state.clear();
        assert!(!should_split(0, 0, &state, &cfg));
    }

    /// The split and the prover read one ladder: a chunk has a row in the fit exactly when
    /// `select_core_rung` finds it one short of the catch-all.
    #[test]
    fn the_fit_holds_a_chunk_exactly_when_the_prover_finds_it_a_ladder_row() {
        let caps = ladder_caps();
        assert_eq!(caps.len(), MLE_CORE_LADDER.len());

        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move |below: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % below
        };
        let (mut held, mut refused) = (0, 0);
        for _ in 0..4000 {
            // A chunk at the edge of one row: every chip at that row's height or a little under
            // it, and now and then one chip a row over, or at the height another row gives it.
            let row = caps[next(caps.len() as u64) as usize];
            let mut rows = row.map(|cap| cap - next(3).min(cap));
            if next(2) == 0 {
                let chip = next(FIT_CHIPS as u64) as usize;
                rows[chip] = if next(2) == 0 {
                    row[chip] + 1
                } else {
                    caps[next(caps.len() as u64) as usize][chip]
                };
            }

            let mut state = ChunkSplitState::default();
            for chip in 0..LEAF_INSN_CHIPS {
                state.leaf_rows[chip] = rows[chip] as u32;
            }
            // MemoryReadWrite follows from the rows above; misaligned accesses take it higher.
            state.num_misaligned =
                rows[FIT_MEMORY_RW].saturating_sub(state.fit_rows()[FIT_MEMORY_RW]) as usize;
            // The 32 registers are charged whatever the chunk wrote.
            state.unique_memory_addrs =
                (rows[FIT_MEMORY_LOCAL] as usize * LOCAL_MEMORY_DATAPAR).saturating_sub(32);
            state.num_syscall_events = rows[FIT_SYSCALL] as usize;

            let natural = FIT_CHIP_NAMES
                .iter()
                .map(|name| name.to_string())
                .zip(state.fit_rows().map(|rows| rows as usize))
                .collect();
            let prover_holds =
                select_core_rung(&natural).is_some_and(|(rung, _)| rung < MLE_CORE_LADDER.len());
            assert_eq!(
                state.ladder_room(u64::MAX).is_some(),
                prover_holds,
                "{natural:?}"
            );
            if prover_holds {
                held += 1;
            } else {
                refused += 1;
            }
        }
        // Both sides of the edge were drawn. A ladder with more rows refuses fewer of these.
        assert!(
            held > 100 && refused > 100,
            "{held} held, {refused} refused"
        );
    }

    #[test]
    fn the_fit_counts_a_memory_local_entry_for_every_address_and_all_the_registers() {
        let mut state = ChunkSplitState::default();
        for addr in [64u64, 72, 80, 88, 96] {
            state.track_address(addr);
        }
        state.record_syscall_event();
        let rows = state.fit_rows();
        // Five addresses and the 32 registers: 37 MemoryLocal entries, four to a row.
        assert_eq!(rows[FIT_MEMORY_LOCAL], 10);
        assert_eq!(rows[FIT_SYSCALL], 1);

        // A register is charged once, written or only read.
        state.track_address(5);
        assert_eq!(state.fit_rows(), rows);
    }

    #[test]
    fn the_fit_counts_memory_rows_by_the_instructions_and_not_by_the_memory_events() {
        let mut state = ChunkSplitState::default();
        for opcode in [
            Opcode::LD,
            Opcode::SD,
            Opcode::LBU,
            Opcode::ADD,
            Opcode::BNE,
            Opcode::DIV,
        ] {
            state.count_insn(opcode);
        }
        // What the event arm counts: three register accesses an instruction and the like.
        state.add_memory_rw_events(17);
        assert_eq!(state.fit_rows()[FIT_MEMORY_RW], 3);

        // A jump leaves no row on another chip and passes for a load; a misaligned access takes
        // a second row.
        state.count_insn(Opcode::JAL);
        state.num_misaligned = 1;
        assert_eq!(state.fit_rows()[FIT_MEMORY_RW], 5);
    }

    /// A chip a ladder row names has one height in every row or is one the fit reads: a refit
    /// that lets another chip's height vary has to teach the fit that chip.
    #[test]
    fn the_fit_reads_every_chip_whose_height_varies_across_the_ladder() {
        let first = MLE_CORE_LADDER[0];
        for (chip, log) in first {
            let varies = MLE_CORE_LADDER.iter().any(|row| {
                row.iter()
                    .find(|(name, _)| name == chip)
                    .is_none_or(|(_, other)| other != log)
            });
            assert!(
                !varies || FIT_CHIP_NAMES.contains(chip),
                "{chip} varies across the ladder's rows and the fit does not read it"
            );
        }
        // No row names a chip the first does not.
        for row in MLE_CORE_LADDER {
            assert_eq!(row.len(), first.len());
        }
    }

    /// `Debug` prints the same however much is marked; `marked_dwords` lists what is.
    #[test]
    fn a_bitset_lists_its_marks_but_prints_only_its_size() {
        let mut bits = SimpleBitSet::default();
        let empty = format!("{bits:?}");
        assert!(
            empty.contains(&format!("dwords: {}", BITMAP_WORDS * 64)),
            "{empty}"
        );
        bits.insert_dword_index(70);
        bits.insert_dword_index(3);
        assert_eq!(format!("{bits:?}"), empty);
        assert_eq!(bits.marked_dwords(), [3, 70]);
        assert_eq!(bits.clone().marked_dwords(), [3, 70]);
    }
}
