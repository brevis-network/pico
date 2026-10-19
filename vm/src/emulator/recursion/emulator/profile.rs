//! Where a recursion emulation spends its time, broken down by instruction kind.
//!
//! A combine node's `Runtime::run()` runs 82 ms at the median — 572 nodes over the reth census
//! blocks 24002946 and 24004465, four cards — and the combine tree's levels are serial, so this
//! is measured to be optimised rather than merely reported. Two knobs, both default-OFF and both
//! read once, each with a sub-option that only matters once it is on:
//!
//! - `MLE_REC_EMULATE_PROFILE=1` — per-kind counts and ticks, one line per `run_range`, so a
//!   split node reports four: prologue, each child, merge tail.
//! - `MLE_REC_EMULATE_DUMP=<dir>` — bincode of `(program, witness_stream)`, the interpreter's
//!   entire input, so one node can be replayed off the box (gpu-base's `rec-emulate-replay`).
//!   `MLE_REC_EMULATE_DUMP_LABEL` picks which runs to catch (default `combine`) and
//!   `MLE_REC_EMULATE_DUMP_MAX` how many (default 1).
//!
//! Over a whole program the counts are exact without running anything: it is straight-line
//! (`run()` only ever advances `pc` by one), so every instruction executes exactly once and the
//! histogram is a static property of `program.instructions`. What needs the run is the ticks.
//! Per range this no longer holds — a child skips the constant writes hoisted ahead of the fork,
//! so its `executed` is below its instruction count.

use std::{
    path::PathBuf,
    sync::{atomic::AtomicUsize, LazyLock},
};

use crate::compiler::recursion::instruction::InstructionKind;

/// On only for `"1"`, so a stray value cannot turn a measurement arm on and have it scored as
/// the shipped path.
pub static PROFILE: LazyLock<bool> =
    LazyLock::new(|| std::env::var("MLE_REC_EMULATE_PROFILE").is_ok_and(|v| v == "1"));

/// Directory to write emulation inputs to, unset ⇒ no dumping.
pub static DUMP_DIR: LazyLock<Option<PathBuf>> =
    LazyLock::new(|| std::env::var_os("MLE_REC_EMULATE_DUMP").map(PathBuf::from));

/// Which `Runtime::run()` calls to dump: their `dump_label` must contain this. Defaults to
/// `combine`, the one on the tail's critical path; `convert` or `""` (everything) also work.
pub static DUMP_LABEL: LazyLock<String> = LazyLock::new(|| {
    std::env::var("MLE_REC_EMULATE_DUMP_LABEL").unwrap_or_else(|_| "combine".into())
});

/// How many dumps to write before ignoring the rest. One node is enough to replay; a whole run's
/// worth is tens of gigabytes.
pub static DUMP_MAX: LazyLock<usize> = LazyLock::new(|| {
    std::env::var("MLE_REC_EMULATE_DUMP_MAX")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1)
});

/// Dumps written so far, against [`DUMP_MAX`]. Process-wide: several cards emulate at once.
pub static DUMPS_WRITTEN: AtomicUsize = AtomicUsize::new(0);

/// The tick source, and what a tick is worth.
///
/// `rdtsc` on x86_64: ~25 cycles against a ~150 ns instruction, where `Instant::now()`'s ~25 ns
/// would inflate the cheap-and-numerous kinds by a third and rank them wrong. It does not
/// serialise, so one reading means nothing — the table sums ~10^5 executions per kind, over which
/// the reorder noise cancels. Everywhere else it reads zero: no counter that cheap is portable,
/// and the boxes this is measured on are x86_64. The report names the unit either way.
#[inline(always)]
pub fn ticks() -> u64 {
    #[cfg(target_arch = "x86_64")]
    {
        // SAFETY: `rdtsc` is unprivileged and present on every x86_64 CPU this targets.
        unsafe { core::arch::x86_64::_rdtsc() }
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        0
    }
}

/// What a tick is, for the report line.
pub const TICK_UNIT: &str = if cfg!(target_arch = "x86_64") {
    "rdtsc"
} else {
    "none"
};

/// Per-kind counts and ticks for one `Runtime::run()`.
///
/// Allocated unconditionally — 432 bytes against an emulation that allocates megabytes — so the
/// hot loop tests one `bool` rather than an `Option` it would have to unwrap twice per
/// instruction.
pub struct EmulateProfile {
    counts: [u64; InstructionKind::COUNT],
    ticks: [u64; InstructionKind::COUNT],
}

impl Default for EmulateProfile {
    fn default() -> Self {
        Self {
            counts: [0; InstructionKind::COUNT],
            ticks: [0; InstructionKind::COUNT],
        }
    }
}

impl EmulateProfile {
    #[inline(always)]
    pub fn add(&mut self, kind: InstructionKind, ticks: u64) {
        let i = kind as usize;
        self.counts[i] += 1;
        self.ticks[i] += ticks;
    }

    /// What one instrumented instruction costs when the instruction itself costs nothing: the
    /// floor of a back-to-back pair of reads. Reported so a kind's ticks can be read net of the
    /// timer, which matters precisely for the cheap kinds that dominate the count.
    fn sample_overhead() -> u64 {
        (0..1024)
            .map(|_| {
                let t0 = ticks();
                ticks().wrapping_sub(t0)
            })
            .min()
            .unwrap_or(0)
    }

    /// One line, `kind:count:ticks` for every kind that ran. Machine-readable on purpose: the
    /// table is assembled from ~50 combine nodes per block, not read one node at a time.
    pub fn report(&self, label: &str, instructions: usize, total_memory: usize) {
        let executed: u64 = self.counts.iter().sum();
        let total: u64 = self.ticks.iter().sum();
        let kinds = InstructionKind::ALL
            .iter()
            .filter(|k| self.counts[**k as usize] != 0)
            .map(|k| {
                let i = *k as usize;
                format!("{}:{}:{}", k.name(), self.counts[i], self.ticks[i])
            })
            .collect::<Vec<_>>()
            .join(",");
        tracing::info!(
            target: "bench",
            "rec_emulate_profile: label = {label}, instructions = {instructions}, \
             executed = {executed}, total_memory = {total_memory}, unit = {TICK_UNIT}, \
             total_ticks = {total}, sample_overhead_ticks = {}, kinds = {kinds}",
            Self::sample_overhead(),
        );
    }
}

/// The interpreter's entire input for one node, bincoded to `<MLE_REC_EMULATE_DUMP>/`.
///
/// `(program, witness_stream)` is sufficient: `Runtime::run()` reads nothing else, so replaying
/// the pair reproduces the emulation exactly — which is what makes an interpreter change
/// measurable off the box, at n=30, without a card. The program's `traces` are `#[serde(skip)]`
/// and come back empty; they are read only from the panic path.
///
/// `child_spans` rides alongside rather than inside the program, because it is `#[serde(skip)]`
/// there on purpose — a program is a wire format others may hold, and this is a property of how
/// this one was built. The replay tool puts it back.
///
/// Called from the two setup drivers rather than from `run()` itself, where `F` is generic and
/// carries no `Serialize` bound. Both call it outside their `emulate_ms` bracket.
pub fn dump_emulation<F: serde::Serialize>(
    label: &str,
    program: &crate::compiler::recursion::program::RecursionProgram<F>,
    witness_stream: &std::collections::VecDeque<crate::compiler::recursion::ir::Block<F>>,
) {
    use std::sync::atomic::Ordering;

    let Some(dir) = DUMP_DIR.as_ref() else { return };
    if !label.contains(DUMP_LABEL.as_str()) {
        return;
    }
    // Claim the slot before doing the work, so two cards dumping at once cannot both pass the
    // check and write `DUMP_MAX + 1` files.
    let seq = DUMPS_WRITTEN.fetch_add(1, Ordering::Relaxed);
    if seq >= *DUMP_MAX {
        return;
    }

    let path = dir.join(format!(
        "rec-emulate-{label}-{}-{seq}.bin",
        program.instructions.len()
    ));
    // A dump is a measurement aid: report a failure and carry on proving, never take the run down.
    let write = || -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        let file = std::io::BufWriter::new(std::fs::File::create(&path)?);
        bincode::serialize_into(file, &(program, witness_stream, &program.child_spans))
            .map_err(|e| std::io::Error::other(e.to_string()))
    };
    match write() {
        Ok(()) => tracing::info!(
            target: "bench",
            "rec_emulate_dump: label = {label}, instructions = {}, witness_blocks = {}, \
             child_spans = {:?}, path = {}",
            program.instructions.len(),
            witness_stream.len(),
            program.child_spans,
            path.display(),
        ),
        Err(e) => tracing::warn!("rec_emulate_dump failed for {}: {e}", path.display()),
    }
}
