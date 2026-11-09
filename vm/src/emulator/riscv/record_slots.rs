//! The bound on how many CPU records a GPU prover process holds at once: the slots of the process's
//! history arena. A chunk's history takes a pinned slot with its first write
//! ([`HistoryArena::take`]), the record that carries it owns it, and it goes back once the record
//! drops and the device copies out of it have run; a writer that finds every slot taken waits for
//! one to come back. That wait is the emulation's backpressure: a pipeline whose emulation runs
//! ahead of proving stops at the bound, and goes on as proving drops records.
//!
//! - A process is unbounded until it asks for the bound ([`bound_records`]), as the GPU prover does
//!   when it sets up a card (`init_mle_gpu_pool`). An unbounded process writes every history on
//!   the heap and pins nothing: one that only emulates, or proves on the CPU, keeps what it holds.
//! - The arena is pinned once: by [`init_record_slots`] at startup, or at the first take, with
//!   [`record_slots_from_env`] slots, each with room for one chunk's history at the census's
//!   capacities ([`HistoryCapacity::CENSUS`], about 0.7 GB a slot). A table past its region spills
//!   to the heap, counted, so a chunk larger than the census measured costs copies and never a row.
//! - The count is `MLE_HISTORY_SLOTS`, [`DEFAULT_RECORD_SLOTS`] when it is unset. The variable's
//!   former name, `MLE_EVENT_POOL_SIZE`, is still read, with a warning; the two set to different
//!   values refuse to start the process, since either could be the one the operator meant.
//! - A caller that holds every record of a run would stop at the bound for good, so it lifts the
//!   bound while it runs ([`unbounded_scope`]), which outweighs [`bound_records`]; the bound is
//!   back once the scope drops. The lift is process-wide while it lasts, so a scope and a GPU
//!   pipeline run ([`bounded_run`]) exclude each other: each waits for the other to end.
//! - [`hold_records_unbounded`] lifts the bound for good, for tools and tests that never prove on
//!   a card: never cleared, so a process that calls it must not also run the GPU pipeline, which
//!   relies on the bound for backpressure.
//! - A clone holds no slot: it is a heap copy, so a clone cannot wait on the bound or return a
//!   slot twice. Segments of one chunk each take a slot, and their fold keeps the first's.
//! - A pipeline run's chunks are granted slots in chunk order, a split chunk's segments as one
//!   ([`order`](super::history_arena::order)): its sequencer passes records on in chunk order, so
//!   a later chunk's record holding the slot an earlier chunk waits for would hold it for good. A
//!   split chunk holds a slot per segment until it is whole, so a pipeline cutting more segments
//!   than the bound ([`bound_in_force`]) is refused before it starts.
//! - The bound counts records, not bytes: each slot has room for the largest chunk the census saw.

use std::{
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Condvar, Mutex, MutexGuard, OnceLock, PoisonError,
    },
    time::{Duration, Instant},
};

use super::history_arena::{HistoryArena, HistoryCapacity, SlotLayout, SpillPolicy, ROW_SHAPES};

/// The variable that sets the slot count.
pub const SLOTS_VAR: &str = "MLE_HISTORY_SLOTS";

/// What [`SLOTS_VAR`] was called while the bound counted pool buffers; scripts and units that still
/// set it keep their count.
pub const LEGACY_SLOTS_VAR: &str = "MLE_EVENT_POOL_SIZE";

/// The bound a bounded process gets when nothing sized it before its first take and neither
/// variable is set. The launch scripts set a count of their own.
pub const DEFAULT_RECORD_SLOTS: usize = 64;

static ARENA: OnceLock<HistoryArena> = OnceLock::new();

/// Set by [`bound_records`]; see the module header.
static BOUNDED: AtomicBool = AtomicBool::new(false);

/// Set by [`hold_records_unbounded`]; see the module header.
static UNBOUNDED: AtomicBool = AtomicBool::new(false);

/// Live [`UnboundedScope`]s, mirrored from [`RUNS`] for the lock-free read in [`lifted`].
static UNBOUNDED_SCOPES: AtomicUsize = AtomicUsize::new(0);

/// Which runs are open: unbounded scopes and a [`BoundedRun`] exclude each other, so an emulation
/// that lifts the bound cannot take the backpressure away from a GPU pipeline running beside it.
struct Runs {
    unbounded: usize,
    bounded: bool,
}
static RUNS: Mutex<Runs> = Mutex::new(Runs {
    unbounded: 0,
    bounded: false,
});
static RUNS_CHANGED: Condvar = Condvar::new();

fn runs() -> MutexGuard<'static, Runs> {
    RUNS.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Serialises [`try_init_record_slots`], so two callers cannot both pin.
static PINNING: Mutex<()> = Mutex::new(());

/// Bounds the process at `count` records and pins their slots, unless its arena is pinned already,
/// and returns the bound in force.
///
/// # Panics
///
/// If `count` is 0, or the slots cannot be pinned.
pub fn init_record_slots(count: usize) -> usize {
    bound_records();
    let _pinning = PINNING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    ARENA.get_or_init(|| pin(count)).stats().slots
}

/// [`init_record_slots`] for a caller that must not panic. The count stays fixed once pinned.
///
/// # Errors
///
/// If the slots cannot be pinned, or this process already pinned a different count.
pub fn try_init_record_slots(count: NonZeroUsize) -> Result<usize, String> {
    let _pinning = PINNING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let pinned = match ARENA.get() {
        Some(arena) => arena.stats().slots,
        None => {
            let arena = try_pin(count.get())?;
            ARENA.get_or_init(|| arena).stats().slots
        }
    };
    if pinned != count.get() {
        return Err(format!(
            "this process already pinned {pinned} history slots and cannot hold {count}; the \
             count is fixed once pinned"
        ));
    }
    bound_records();
    Ok(pinned)
}

/// Slots taken and not yet given back, or `None` while nothing is pinned.
#[must_use]
pub fn slots_outstanding() -> Option<u64> {
    ARENA.get().map(|arena| {
        let stats = arena.stats();
        stats.acquisitions - stats.returns
    })
}

/// One slot's bytes at the census's capacities: what each record held at once pins.
#[must_use]
pub fn slot_bytes() -> usize {
    SlotLayout::new(&HistoryCapacity::CENSUS, &ROW_SHAPES)
        .expect("the census's slot fits the address space")
        .bytes()
}

/// Bounds the process's records from here on, at the size [`init_record_slots`] sets or else the
/// first take's. See the module header.
pub fn bound_records() {
    BOUNDED.store(true, Ordering::Relaxed);
}

/// Lifts the bound for the rest of the process. See the module header.
pub fn hold_records_unbounded() {
    UNBOUNDED.store(true, Ordering::Relaxed);
}

/// Lifts the bound until the returned guard drops; waits for a running [`BoundedRun`] to end.
/// Scopes nest and may overlap across threads. See the module header.
#[must_use = "the bound is back as soon as the scope drops"]
pub fn unbounded_scope() -> UnboundedScope {
    let mut runs = RUNS_CHANGED
        .wait_while(runs(), |runs| runs.bounded)
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    runs.unbounded += 1;
    UNBOUNDED_SCOPES.fetch_add(1, Ordering::SeqCst);
    UnboundedScope(())
}

/// The bound lifted for as long as this lives: [`unbounded_scope`].
pub struct UnboundedScope(());

impl Drop for UnboundedScope {
    fn drop(&mut self) {
        let mut runs = runs();
        runs.unbounded -= 1;
        UNBOUNDED_SCOPES.fetch_sub(1, Ordering::SeqCst);
        RUNS_CHANGED.notify_all();
    }
}

/// A run that relies on the bound for backpressure (the GPU pipeline): while this lives no
/// [`unbounded_scope`] is open. Waits for open scopes and for another bounded run to end.
#[must_use = "the bound holds only while the run lives"]
pub fn bounded_run() -> BoundedRun {
    let mut runs = RUNS_CHANGED
        .wait_while(runs(), |runs| runs.bounded || runs.unbounded > 0)
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    runs.bounded = true;
    BoundedRun(())
}

/// A bounded run in progress: [`bounded_run`].
pub struct BoundedRun(());

impl Drop for BoundedRun {
    fn drop(&mut self) {
        runs().bounded = false;
        RUNS_CHANGED.notify_all();
    }
}

/// Whether the bound is lifted, for good or by a live scope.
fn lifted() -> bool {
    UNBOUNDED.load(Ordering::Relaxed) || UNBOUNDED_SCOPES.load(Ordering::SeqCst) > 0
}

/// The arena a history about to be written takes its slot from: `None` in a process that is not
/// bounded, or whose bound is lifted. Pins the arena if nothing has.
pub(crate) fn history_arena() -> Option<&'static HistoryArena> {
    if lifted() || !BOUNDED.load(Ordering::Relaxed) {
        return None;
    }
    if let Some(arena) = ARENA.get() {
        return Some(arena);
    }
    // Under the lock `try_init_record_slots` pins under, so the two never both pin.
    let _pinning = PINNING
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    Some(ARENA.get_or_init(|| {
        let count = record_slots_from_env().unwrap_or_else(|e| panic!("{e}"));
        pin(count.get())
    }))
}

/// How the slots were used over a stretch of a process, for its log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotOccupancy {
    pub slots: usize,
    pub max_in_use: usize,
    /// Slots taken, those takes that waited for one, and how long they waited.
    pub takes: u64,
    pub blocked_takes: u64,
    pub blocked: Duration,
}

/// The slots' use since the previous call, or since pinning; `None` while nothing is pinned. Pins
/// nothing. One call per pipeline run gives that run's figures.
pub fn take_occupancy() -> Option<SlotOccupancy> {
    static TAKEN: Mutex<(u64, u64, Duration)> = Mutex::new((0, 0, Duration::ZERO));
    let arena = ARENA.get()?;
    // Held across the read and the save, so two callers cannot interleave and leave a saved count
    // ahead of the next one read.
    let mut taken = TAKEN.lock().unwrap_or_else(PoisonError::into_inner);
    let max_in_use = arena.take_max_in_use();
    let stats = arena.stats();
    let (takes, blocked_takes, blocked) = *taken;
    *taken = (stats.acquisitions, stats.blocked_takes, stats.blocked);
    Some(SlotOccupancy {
        slots: stats.slots,
        max_in_use,
        takes: stats.acquisitions - takes,
        blocked_takes: stats.blocked_takes - blocked_takes,
        blocked: stats.blocked.saturating_sub(blocked),
    })
}

/// The bound in force, in records: `None` in a process that is not bounded, or whose bound is
/// lifted; else the slots pinned, or the count the first take will pin. Pins nothing.
///
/// # Errors
///
/// If the slots are not pinned yet and the count the environment asks for cannot be read.
pub fn bound_in_force() -> Result<Option<NonZeroUsize>, String> {
    if lifted() || !BOUNDED.load(Ordering::Relaxed) {
        return Ok(None);
    }
    match ARENA.get() {
        Some(arena) => Ok(NonZeroUsize::new(arena.stats().slots)),
        // Read without the former name's warning, which the pin gives.
        None => resolve_slots(
            std::env::var(SLOTS_VAR).ok().as_deref(),
            std::env::var(LEGACY_SLOTS_VAR).ok().as_deref(),
        )
        .map(|(count, _)| Some(count)),
    }
}

/// The slot count the environment asks for: [`SLOTS_VAR`], else [`LEGACY_SLOTS_VAR`] with a
/// warning, else [`DEFAULT_RECORD_SLOTS`]. The one reader of both variables.
///
/// # Errors
///
/// If a variable that is set is not a positive integer, or the two are set to different counts.
pub fn record_slots_from_env() -> Result<NonZeroUsize, String> {
    let (count, legacy_set) = resolve_slots(
        std::env::var(SLOTS_VAR).ok().as_deref(),
        std::env::var(LEGACY_SLOTS_VAR).ok().as_deref(),
    )?;
    if legacy_set {
        tracing::warn!(
            "{LEGACY_SLOTS_VAR} is the former name of {SLOTS_VAR}; set {SLOTS_VAR} instead \
             (using {count} history slots)"
        );
    }
    Ok(count)
}

/// The count for the two variables' values, and whether the former name was among the ones set.
fn resolve_slots(
    current: Option<&str>,
    legacy: Option<&str>,
) -> Result<(NonZeroUsize, bool), String> {
    fn parse(name: &str, raw: &str) -> Result<NonZeroUsize, String> {
        raw.parse()
            .map_err(|_| format!("{name}={raw:?}: expected a positive integer"))
    }
    let current = current.map(|raw| parse(SLOTS_VAR, raw)).transpose()?;
    let legacy_count = legacy.map(|raw| parse(LEGACY_SLOTS_VAR, raw)).transpose()?;
    let count = match (current, legacy_count) {
        (Some(current), Some(legacy)) if current != legacy => {
            return Err(format!(
                "{SLOTS_VAR}={current} and {LEGACY_SLOTS_VAR}={legacy} name different slot \
                 counts; unset {LEGACY_SLOTS_VAR}"
            ));
        }
        (Some(count), _) | (None, Some(count)) => count,
        (None, None) => NonZeroUsize::new(DEFAULT_RECORD_SLOTS).expect("the default is not 0"),
    };
    Ok((count, legacy.is_some()))
}

/// The arena at `count` slots. Not told the run's chunk size, it takes the census's: a larger chunk
/// shows up as spills, counted per table and in the stage ledger.
fn pin(count: usize) -> HistoryArena {
    try_pin(count).unwrap_or_else(|e| panic!("{e}"))
}

/// [`pin`], with a failure to pin as an `Err`.
fn try_pin(count: usize) -> Result<HistoryArena, String> {
    let slots = NonZeroUsize::new(count).ok_or("the bound on records held at once is 0")?;
    let capacity = HistoryCapacity::CENSUS;
    let start = Instant::now();
    let arena = HistoryArena::pin(slots, capacity.chunk_size(), capacity, SpillPolicy::Spill)
        .map_err(|e| format!("pinning {count} history slots: {e}"))?;
    let stats = arena.stats();
    tracing::info!(
        "pinned {} history slots of {} bytes, {} bytes in all, in {:.3}s",
        stats.slots,
        stats.slot_bytes,
        stats.pinned_bytes(),
        start.elapsed().as_secs_f64()
    );
    tracing::info!(
        target: "bench",
        "[record-slots] {} history slots, granted to a pipeline run's chunks in chunk order",
        stats.slots
    );
    Ok(arena)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bounded_run_waits_for_an_open_unbounded_scope() {
        use std::{sync::mpsc, time::Duration};

        let scope = unbounded_scope();
        let (started, run_started) = mpsc::channel();
        let run = std::thread::spawn(move || {
            let _run = bounded_run();
            started.send(()).expect("the test is waiting");
        });
        assert!(
            run_started
                .recv_timeout(Duration::from_millis(300))
                .is_err(),
            "a bounded run started while an unbounded scope was open"
        );
        drop(scope);
        // Other tests' scopes may still be open; the run starts once they all drop.
        run_started
            .recv_timeout(Duration::from_secs(600))
            .expect("the run starts once the scopes drop");
        run.join().expect("the run thread");
    }

    fn slots(current: Option<&str>, legacy: Option<&str>) -> Result<(usize, bool), String> {
        resolve_slots(current, legacy).map(|(count, legacy_set)| (count.get(), legacy_set))
    }

    #[test]
    fn the_current_name_alone_sets_the_count() {
        assert_eq!(slots(Some("96"), None), Ok((96, false)));
    }

    #[test]
    fn the_former_name_alone_sets_the_count_and_is_reported() {
        assert_eq!(slots(None, Some("96")), Ok((96, true)));
    }

    #[test]
    fn both_names_set_to_one_count_give_it_and_report_the_former_name() {
        assert_eq!(slots(Some("96"), Some("96")), Ok((96, true)));
        assert_eq!(slots(Some("96"), Some("096")), Ok((96, true)));
    }

    #[test]
    fn both_names_set_to_different_counts_are_refused() {
        let err = slots(Some("64"), Some("96")).unwrap_err();
        assert!(
            err.contains(SLOTS_VAR) && err.contains(LEGACY_SLOTS_VAR),
            "{err}"
        );
    }

    #[test]
    fn neither_name_gives_the_default() {
        assert_eq!(slots(None, None), Ok((DEFAULT_RECORD_SLOTS, false)));
        assert_eq!(DEFAULT_RECORD_SLOTS, 64);
    }

    #[test]
    fn a_value_that_is_not_a_positive_integer_is_refused_whichever_name_holds_it() {
        for bad in ["0", "", "-1", "sixty-four", "6.4"] {
            let err = slots(Some(bad), None).unwrap_err();
            assert!(err.contains(SLOTS_VAR), "{err}");
            let err = slots(None, Some(bad)).unwrap_err();
            assert!(err.contains(LEGACY_SLOTS_VAR), "{err}");
        }
    }

    #[test]
    fn both_names_are_ledger_knobs() {
        for name in [SLOTS_VAR, LEGACY_SLOTS_VAR] {
            assert!(crate::mle::ledger::KNOBS.contains(&name), "{name}");
        }
    }
}
