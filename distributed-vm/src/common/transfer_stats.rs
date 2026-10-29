//! Bytes moved between machines, counted per run.
//!
//! A two-process run over loopback has **no propagation delay and no bandwidth ceiling**, so it
//! cannot tell you what
//! the link would cost between two real hosts. Recording the payload size is what gives a later
//! two-host estimate a basis instead of a guess. Transfer carries *convert* proofs rather than
//! riscv ones, so the figure is expected to be
//! modest and is worth knowing rather than assuming.
//!
//! Counted at the serialisation boundary in the scheduler client and service — the only place MLE
//! moves a payload across machines (there is no proof-transfer service in the MLE path).
//! Both directions are counted separately: the secondary sends convert proofs up, and receives
//! combine children back down, and those are very different sizes.
//!
//! Counted on BOTH sides of each RPC — client and server — so either machine's log answers the
//! question. They are the same bytes viewed from opposite ends: what the secondary calls `out` is
//! what the primary calls `in`. Only counting client-side left the primary's line blank, which
//! reads as "nothing was transferred" rather than "this process is the server".
//!
//! Cheap by construction: two relaxed atomic adds per RPC, on a path that already did a bincode
//! serialise. `Relaxed` is right because nothing orders against these — they are read once, after
//! the run, by the thread that prints them.

use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

static BYTES_OUT: AtomicU64 = AtomicU64::new(0);
static BYTES_IN: AtomicU64 = AtomicU64::new(0);
static PROOFS_OUT: AtomicUsize = AtomicUsize::new(0);
static PROOFS_IN: AtomicUsize = AtomicUsize::new(0);

/// A payload this machine sent to another.
pub fn record_out(bytes: usize, proofs: usize) {
    BYTES_OUT.fetch_add(bytes as u64, Ordering::Relaxed);
    PROOFS_OUT.fetch_add(proofs, Ordering::Relaxed);
}

/// A payload this machine received from another.
pub fn record_in(bytes: usize, proofs: usize) {
    BYTES_IN.fetch_add(bytes as u64, Ordering::Relaxed);
    PROOFS_IN.fetch_add(proofs, Ordering::Relaxed);
}

/// `(bytes_out, proofs_out, bytes_in, proofs_in)` since the last reset.
pub fn snapshot() -> (u64, usize, u64, usize) {
    (
        BYTES_OUT.load(Ordering::Relaxed),
        PROOFS_OUT.load(Ordering::Relaxed),
        BYTES_IN.load(Ordering::Relaxed),
        PROOFS_IN.load(Ordering::Relaxed),
    )
}

/// Zero the counters. `MLE_REPEAT` runs several blocks in one process, and a per-block figure is
/// what is wanted — without this the numbers would be cumulative and quietly wrong for every
/// iteration after the first.
pub fn reset() {
    BYTES_OUT.store(0, Ordering::Relaxed);
    BYTES_IN.store(0, Ordering::Relaxed);
    PROOFS_OUT.store(0, Ordering::Relaxed);
    PROOFS_IN.store(0, Ordering::Relaxed);
}

/// One line for the bench log, or `None` when nothing crossed a machine boundary — single-node
/// should not print a transfer figure of zero and invite the reader to compare it with a
/// two-machine run's.
pub fn summary_line() -> Option<String> {
    let (out_b, out_n, in_b, in_n) = snapshot();
    if out_b == 0 && in_b == 0 {
        return None;
    }
    let mib = |b: u64| b as f64 / (1024.0 * 1024.0);
    Some(format!(
        "MLE transfer: out={:.2} MiB ({out_n} payloads) | in={:.2} MiB ({in_n} payloads) | \
         total={:.2} MiB",
        mib(out_b),
        mib(in_b),
        mib(out_b + in_b)
    ))
}
