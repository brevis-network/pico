//! Env-gated (`MLE_BREAKDOWN=1`) per-chunk prove-phase timing.
//!
//! The four coarse phases straddle two crates: **trace-gen** is recorded by the caller
//! (`pico-vm`'s `prove_chunk`), while **commit / rap_constraints / openings** are recorded by the
//! GPU device methods here. They all run synchronously on the same worker thread for one chunk, so
//! a `thread_local` accumulator lines up per-prove without any locking. The driver (the worker
//! loop, which knows `worker_id`/`chunk_idx`) calls [`take`] right after `prove_chunk` returns and
//! emits a one-line breakdown — mirroring the FRI prover's `(Prep/Commit/Perm/Quotient/FRI)` line.
//!
//! Timing is *synced* (a `current_stream_sync` brackets each phase) so the numbers attribute GPU
//! work rather than async dispatch — same discipline as the `*_PROF` flags and the FRI
//! `bench_timer`. This adds sync overhead, so it is off unless `MLE_BREAKDOWN` is set; the default
//! prove path is untouched.

use std::{cell::Cell, sync::OnceLock, time::Instant};

/// `MLE_BREAKDOWN` set (and not `0`) turns on the synced phase timing + collection.
pub fn enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| crate::cuda::jit::env_flag("MLE_BREAKDOWN", false))
}

thread_local! {
    static TRACEGEN_US: Cell<u64> = const { Cell::new(0) };
    static COMMIT_US: Cell<u64> = const { Cell::new(0) };
    static RAP_US: Cell<u64> = const { Cell::new(0) };
    static OPENINGS_US: Cell<u64> = const { Cell::new(0) };
}

/// Flush prior GPU work and start a phase timer, or `None` when disabled (zero overhead).
pub fn start() -> Option<Instant> {
    if !enabled() {
        return None;
    }
    let _ = crate::runtime::stream::current_stream_sync();
    Some(Instant::now())
}

fn stop(t: Option<Instant>, slot: &'static std::thread::LocalKey<Cell<u64>>) {
    if let Some(t) = t {
        let _ = crate::runtime::stream::current_stream_sync();
        slot.with(|c| c.set(t.elapsed().as_micros() as u64));
    }
}

/// Record trace-gen elapsed (caller already holds the `Instant` from [`start`]).
pub fn stop_tracegen(t: Option<Instant>) {
    stop(t, &TRACEGEN_US);
}
pub fn stop_commit(t: Option<Instant>) {
    stop(t, &COMMIT_US);
}
pub fn stop_rap(t: Option<Instant>) {
    stop(t, &RAP_US);
}
pub fn stop_openings(t: Option<Instant>) {
    stop(t, &OPENINGS_US);
}

/// `(tracegen, commit, rap_constraints, openings)` in µs for the chunk just proved on this thread;
/// resets the slots for the next chunk. Phases SET (not add), so this is per-prove regardless.
pub fn take() -> (u64, u64, u64, u64) {
    (
        TRACEGEN_US.with(|c| c.replace(0)),
        COMMIT_US.with(|c| c.replace(0)),
        RAP_US.with(|c| c.replace(0)),
        OPENINGS_US.with(|c| c.replace(0)),
    )
}
