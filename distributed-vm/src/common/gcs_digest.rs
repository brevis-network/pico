//! Cross-machine collection point for partial GCS digests.
//!
//! The host-side memory-consistency check (`Σ per-chunk gcs + initial == 0`) is a whole-run
//! property, but each machine only accumulates its own chunks' terms — so under two-machine neither
//! side's sum closes on its own and the check has to be a cross-process reduction. The secondary
//! sends its partial over `Scheduler::ReportGcsDigest`; this is where the primary's server parks it
//! until the run ends and the pipeline can add its own half.
//!
//! Deliberately neutral rather than living in `mle_scheduler_singleton`: the gRPC service is generic
//! over the payload and shared with FRI, so it must not gain a dependency on MLE's types to hand a
//! digest over. FRI simply never sends one, and `take_remote_digests` returns empty.
//!
//! The digests are opaque bytes here. Only the MLE pipeline knows the field type to deserialise
//! them into, and restating that layout in the transport would be a second place for it to drift.

use parking_lot::Mutex;

/// A partial digest and who sent it. The label is carried so a non-zero total can name the
/// contributors instead of just failing.
pub struct RemoteGcsDigest {
    pub worker_id: String,
    pub digest: Vec<u8>,
}

static REMOTE_DIGESTS: Mutex<Vec<RemoteGcsDigest>> = Mutex::new(Vec::new());

/// Record a partial digest received from another machine. Called by the scheduler service.
pub fn push_remote_digest(worker_id: String, digest: Vec<u8>) {
    tracing::info!(
        "received partial GCS digest from {worker_id} ({} bytes)",
        digest.len()
    );
    REMOTE_DIGESTS
        .lock()
        .push(RemoteGcsDigest { worker_id, digest });
}

/// Take everything received so far.
///
/// Drains, matching the local terms it is reduced against — those are drained by
/// `assert_cross_chunk_gcs_zero_over` too, so both halves are single-shot per run and a second
/// call cannot silently re-close an already-closed sum.
pub fn take_remote_digests() -> Vec<RemoteGcsDigest> {
    std::mem::take(&mut *REMOTE_DIGESTS.lock())
}

/// Whether any remote partial has arrived. Lets the primary distinguish "the secondary reported
/// nothing" from "the secondary reported zero", which are very different failures.
pub fn remote_digest_count() -> usize {
    REMOTE_DIGESTS.lock().len()
}

/// Block until `expected` remote partials have arrived, or the timeout elapses.
///
/// There is no barrier between the two machines at the end of a run: the primary finishes its own
/// half and would otherwise reduce immediately, while the secondary is still proving its last chunk
/// and has not sent anything. That is not a hypothetical race — the first run where both sides
/// proved died on the primary with "reduced this machine plus 0 remote partial(s)", i.e. it closed
/// the sum over half the run and called the result inconsistent.
///
/// Returns whether they all arrived. The caller decides what a shortfall means; this deliberately
/// does not panic, so the reduction can report *which* machines were missing rather than a bare
/// timeout.
pub fn wait_for_remote_digests(expected: usize, timeout: std::time::Duration) -> bool {
    if expected == 0 {
        return true;
    }
    let deadline = std::time::Instant::now() + timeout;
    let mut announced = false;
    while remote_digest_count() < expected {
        if std::time::Instant::now() >= deadline {
            return false;
        }
        if !announced {
            tracing::info!(
                "waiting for {expected} remote GCS digest(s) before closing the sum \
                 (have {})",
                remote_digest_count()
            );
            announced = true;
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    true
}
