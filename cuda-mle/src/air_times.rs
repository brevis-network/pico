//! Per-AIR time inside one prove: a CUDA event pair on this thread's stream around each AIR's work
//! in the prove's two per-AIR loops, the batch constraints' round 0 and the GKR input evaluation.
//! Those are the loops whose kernels the JIT size gates choose between compiled and rule-interpreted;
//! the later rounds evaluate the AIRs in batches and have no per-AIR time.
//!
//! An AIR's time is the interval between its two events, so it is host and device wall, not kernel
//! time: round 0 ends each AIR with blocking read-backs and host work, which the interval holds.
//! Each step reports the path its kernels actually took, which the step notes as it launches.
//!
//! The caller opens a [`Window`] around a prove and takes the times after the prove returns, when
//! every event has completed; reading one earlier would take a wait of its own. Without a window each
//! hook is a thread-local read.

use std::cell::{Cell, RefCell};

use crate::runtime::stream::CudaEvent;

/// The log target of the prover's device readings, whose debug level the caller switches them on by.
pub const TARGET: &str = "gpu_tracegen";

struct Entry {
    air: String,
    step: &'static str,
    path: &'static str,
    start: CudaEvent,
    end: CudaEvent,
}

thread_local! {
    static ENTRIES: RefCell<Option<Vec<Entry>>> = const { RefCell::new(None) };
    /// The path the current AIR's step launched, as the step noted it.
    static PATH: Cell<Option<&'static str>> = const { Cell::new(None) };
}

/// One AIR's time in one step of a prove.
#[derive(Clone, Debug)]
pub struct AirTime {
    pub air: String,
    /// `round0` or `gkr_input`.
    pub step: &'static str,
    /// The path the step's kernels took: `compiled`, `interpreter`, `host` for a host evaluation,
    /// or `none` when the step launched nothing for the AIR.
    pub path: &'static str,
    /// `None` when an event had not completed.
    pub us: Option<u64>,
}

/// The calling thread's per-AIR times from [`begin`] to [`Window::take`]. Dropping it puts back
/// whatever the thread was recording before, on unwind too.
#[must_use = "the per-AIR times stop when the window drops"]
pub struct Window {
    prev: Option<Vec<Entry>>,
}

pub fn begin() -> Window {
    Window {
        prev: ENTRIES.with(|entries| entries.replace(Some(Vec::new()))),
    }
}

impl Window {
    /// The times recorded since [`begin`], in the order the steps ran. Call after the prove returns.
    pub fn take(self) -> Vec<AirTime> {
        let entries = ENTRIES.with(|entries| entries.borrow_mut().take());
        entries
            .unwrap_or_default()
            .into_iter()
            .map(|entry| AirTime {
                us: entry
                    .end
                    .elapsed_ms_since(&entry.start)
                    .ok()
                    .map(|ms| (f64::from(ms) * 1e3).round() as u64),
                air: entry.air,
                step: entry.step,
                path: entry.path,
            })
            .collect()
    }
}

impl Drop for Window {
    fn drop(&mut self) {
        let prev = self.prev.take();
        ENTRIES.with(|entries| *entries.borrow_mut() = prev);
    }
}

fn open() -> bool {
    ENTRIES.with(|entries| entries.borrow().is_some())
}

/// The start of one AIR's work on this thread's stream, when a window is open.
pub(crate) fn start() -> Option<CudaEvent> {
    if !open() {
        return None;
    }
    PATH.with(|path| path.set(None));
    recorded()
}

/// Note the path the current AIR's step is launching, when a window is open.
pub(crate) fn note_path(launched: &'static str) {
    if open() {
        PATH.with(|path| path.set(Some(launched)));
    }
}

/// Close the work `start` opened, for `air` in `step`.
pub(crate) fn stop(start: Option<CudaEvent>, air: &str, step: &'static str) {
    let Some(start) = start else {
        return;
    };
    let path = PATH.with(|path| path.take()).unwrap_or("none");
    let Some(end) = recorded() else {
        return;
    };
    ENTRIES.with(|entries| {
        if let Some(entries) = entries.borrow_mut().as_mut() {
            entries.push(Entry {
                air: air.to_string(),
                step,
                path,
                start,
                end,
            });
        }
    });
}

fn recorded() -> Option<CudaEvent> {
    let event = CudaEvent::new().ok()?;
    event.record_on_this().ok()?;
    Some(event)
}
