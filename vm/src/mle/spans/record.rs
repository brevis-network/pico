//! Recording what each lane of the pipeline was doing, and when.
//!
//! A lane is in exactly one of three states at any instant: `Busy`, `Idle` (blocked for want of
//! input) or `Wait` (blocked on capacity someone else holds). The glossary defines all of it; the two
//! things a reader of *this* file needs are below.
//!
//! **Nesting comes out flat.** A keygen happens inside a prepare, which is already an open span, and
//! two overlapping spans on one lane would double-count in every interval sweep. So [`open`] keeps a
//! per-thread stack: opening closes the span below, dropping reopens it. `prepare | keygen | prepare`,
//! with neither call site aware of the other. [`validate`] still checks disjointness, because it
//! catches a *missing* close, which the stack cannot.
//!
//! **Granularity must stay per-chunk or coarser — never per-record, never per-kernel.** Two clock
//! reads and a push per span, with no device synchronisation, is what lets collection be always-on;
//! at a few thousand spans a run that is tens of microseconds against tens of seconds. Per-record, the
//! instrumentation would start deciding the numbers it reports.
//!
//! Nothing is recorded until [`set_origin`], which the driver calls when the pipeline window opens —
//! so the one-time setup before it stays outside, deliberately.
use std::{
    cell::{Cell, RefCell},
    marker::PhantomData,
    sync::{Mutex, OnceLock, RwLock},
    time::Instant,
};

/// What a lane was doing. See the module docs for why `Idle` and `Wait` are distinct.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    Busy,
    Idle,
    Wait,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Busy => "busy",
            State::Idle => "idle",
            State::Wait => "wait",
        }
    }
}

/// The kind of work a span represents.
///
/// This is what lets two figures measured on the *same* lane stay distinct — the recursion lane
/// takes convert and combine proves in turn (and under `MLE_RECURSION_LANE=0` the one prover lane
/// takes riscv as well), and only the work kind separates them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum WorkKind {
    /// The emulator's untraced forward pass, which produces the snapshot a worker then replays.
    /// AOT when the AOT factory is registered, the interpreter otherwise — one kind either way,
    /// because what matters here is that it is the serial pass, not which backend ran it.
    Snapshot,
    /// A worker's traced replay of one snapshot: the pass that actually produces records. Always the
    /// interpreter; there is no AOT replay path.
    Emulate,
    /// Restoring a worker's emulator from the snapshot, before the replay can start. Separate from
    /// [`WorkKind::Emulate`] because it is per-batch setup rather than the batch's own work, and the
    /// pipeline's head bubble is where the difference shows.
    EmulateRecover,
    PrepareRiscv,
    PrepareConvert,
    PrepareCombine,
    /// Proving-key generation on a cache miss. Emitted from whichever preparer lane took the miss;
    /// it is GPU work inside an otherwise CPU-bound prepare, which is why it is a kind of its own
    /// rather than part of the prepare that contains it.
    Keygen,
    ProveRiscv,
    ProveConvert,
    ProveCombine,
    /// Routing. Its `Busy` is negligible by construction; what matters is its `Wait`, which is
    /// head-of-line blocking on a full downstream lane.
    Dispatch,
    /// No particular work: the lane was between items. Used for the blocked spans of a lane that
    /// serves several kinds — the recursion lane waits for convert *or* combine work (and for
    /// riscv too when it is the card's only lane), and labelling that wait with any one of them
    /// would assert something untrue about what it was waiting for.
    Unattributed,
}

impl WorkKind {
    /// Whether this work reaches the GPU. Exhaustive on purpose: adding a kind forces an answer
    /// here, where the knowledge is, rather than letting a table in a report layer default a new
    /// kind to "not GPU" and quietly overstate how idle the device-facing lanes were.
    pub fn touches_gpu(self) -> bool {
        match self {
            WorkKind::Keygen
            | WorkKind::ProveRiscv
            | WorkKind::ProveConvert
            | WorkKind::ProveCombine => true,
            WorkKind::PrepareRiscv
            | WorkKind::PrepareConvert
            | WorkKind::PrepareCombine
            | WorkKind::Dispatch
            | WorkKind::Snapshot
            | WorkKind::Emulate
            | WorkKind::EmulateRecover
            | WorkKind::Unattributed => false,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            WorkKind::Snapshot => "snapshot",
            WorkKind::Emulate => "emulate",
            WorkKind::EmulateRecover => "emulate-recover",
            WorkKind::PrepareRiscv => "prepare-riscv",
            WorkKind::PrepareConvert => "prepare-convert",
            WorkKind::PrepareCombine => "prepare-combine",
            WorkKind::Keygen => "keygen",
            WorkKind::ProveRiscv => "prove-riscv",
            WorkKind::ProveConvert => "prove-convert",
            WorkKind::ProveCombine => "prove-combine",
            WorkKind::Dispatch => "dispatch",
            WorkKind::Unattributed => "-",
        }
    }
}

/// A lane's role. Lanes of the same role form a pool whose figures are reported together.
///
/// Adding one means editing the places outside this enum that no compiler checks, which a search
/// for the role names finds; `bench-scripts/draw-mle-timeline.py` is the only one that fails
/// loudly on a name it does not know.
/// (`report.rs`'s `DRAWN` names variants, so that one the compiler does check.)
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Role {
    // Declared upstream-first: `Role` is `Ord`, and every report that groups by role inherits this
    // order, so the emulate stage reads above the preparers it feeds.
    /// The emulator's single snapshot-taking thread.
    Snapshot,
    /// The emulator's traced-replay workers, `NUM_THREADS` of them.
    Emulate,
    RiscvPreparer,
    ConvertPreparer,
    CombinePreparer,
    /// The per-card riscv prover lane — and the card's ONLY prover lane under
    /// `MLE_RECURSION_LANE=0`, where it takes convert and combine too.
    Prove,
    /// The per-card recursion prover lane, serving convert and combine. A second thread rather
    /// than a fourth `select!` arm on `Prove`: one thread can only be inside one prove at a time,
    /// whatever it selects on, so sharing the lane is what kept recursion behind riscv. Absent
    /// under `MLE_RECURSION_LANE=0` — no thread binds it, so no lane of this role exists.
    ProveRecursion,
    Dispatch,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Snapshot => "snapshot",
            Role::Emulate => "emulate",
            Role::RiscvPreparer => "riscv-prep",
            Role::ConvertPreparer => "conv-prep",
            Role::CombinePreparer => "comb-prep",
            Role::Prove => "prove",
            Role::ProveRecursion => "prove-rec",
            Role::Dispatch => "dispatch",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct LaneId {
    pub role: Role,
    pub index: usize,
}

impl LaneId {
    pub fn new(role: Role, index: usize) -> Self {
        Self { role, index }
    }
}

impl std::fmt::Display for LaneId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.role.as_str(), self.index)
    }
}

/// One interval during which one lane was in one state.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Span {
    pub lane: LaneId,
    pub state: State,
    pub work: WorkKind,
    /// The work item this span is about, or `None` where it is about none (an idle wait for the next
    /// one, say). Three key spaces, and they are not interchangeable, so anything joining them has to
    /// say which it means: chunks (the riscv/convert prepare, prove and dispatch lanes),
    /// snapshot batches (the emulate lanes, where one tail batch becomes several chunks), and a combine
    /// node's FIRST chunk, which every node up one side of the tree shares.
    pub item: Option<u32>,
    pub start_us: u64,
    pub end_us: u64,
}

impl Span {
    pub fn duration_us(&self) -> u64 {
        self.end_us.saturating_sub(self.start_us)
    }

    /// Whether this span occupied a GPU-touching lane: a `Busy` span whose work reaches the device.
    /// `Idle` and `Wait` never count, whatever the lane — a blocked thread occupies nothing.
    pub fn is_gpu_busy(&self) -> bool {
        self.state == State::Busy && self.work.touches_gpu()
    }
}

// ------------------------------------------------------------------------------- global collection

static ORIGIN: RwLock<Option<Instant>> = RwLock::new(None);
static SPANS: OnceLock<Mutex<Vec<Span>>> = OnceLock::new();

fn store() -> &'static Mutex<Vec<Span>> {
    SPANS.get_or_init(|| Mutex::new(Vec::with_capacity(1024)))
}

/// Open a recording window, discarding whatever was recorded against the previous one. The driver
/// calls this when the pipeline window opens; everything before it is one-time setup and is
/// deliberately not recorded.
///
/// It rebases rather than keeping the first instant, because `MLE_REPEAT=N` calls the driver N times
/// in one process while the pipeline's lane threads outlive a single call (the scheduler is a
/// singleton). Accumulating across iterations made every figure meaningless: timestamps stayed
/// relative to iteration 1's window, so a lane's unaccounted time was dominated by the wait *between*
/// proofs — the `unbracketed time` warnings that a repeat run used to print were that, not missing
/// instrumentation — and the exported CSV covered the whole process, which no timeline can draw.
///
/// The store therefore holds the current window and no other, and each window is exported under its
/// own name ([`csv_path_for_iteration`]) before the next one opens — so a repeat run leaves one CSV
/// per iteration instead of only the last iteration's, and iteration 1, which pays every process-wide
/// one-shot cost (see the `MLE_REPEAT` comment in `mle_single_node.rs`), stays distinguishable from
/// the steady-state ones that follow it.
///
/// A span still open on another lane when this is called keeps running; it is clamped to the new
/// origin when it closes (see [`Frame::start`]), so it reads as "blocked since the window opened",
/// which is what it was.
pub fn set_origin(t: Instant) {
    // Origin first, then the store: a lane pushing concurrently either lands in the window that is
    // ending (and is cleared with it) or in the new one, never at a timestamp from neither.
    *ORIGIN.write().expect("span origin poisoned") = Some(t);
    store().lock().expect("span store poisoned").clear();
}

/// The current window's origin, or `None` while recording is inactive.
fn origin() -> Option<Instant> {
    *ORIGIN.read().expect("span origin poisoned")
}

/// Microseconds from `origin` to `t`, saturating at zero for an instant that predates it — which is
/// how a span left open across a rebase is clamped into the new window instead of producing a start
/// that sits beyond its own end.
fn us_since(origin: Instant, t: Instant) -> u64 {
    t.saturating_duration_since(origin).as_micros() as u64
}

/// A copy of everything recorded so far, ordered by lane then start.
pub fn snapshot() -> Vec<Span> {
    let mut v = store().lock().expect("span store poisoned").clone();
    v.sort_by_key(|s| (s.lane, s.start_us));
    v
}

fn push(span: Span) {
    // A zero-length span is real (a cache hit, an uncontended gate) but carries no information and
    // would only add rows to the sweep, so it is dropped rather than stored.
    if span.end_us > span.start_us {
        store().lock().expect("span store poisoned").push(span);
    }
}

thread_local! {
    /// The lane this thread is, set once by the thread's own entry point. Spans opened on a thread
    /// that never bound a lane are dropped: that is a real possibility (library code reached from a
    /// path with no lane, tests) and silently attributing them to some other lane would be worse.
    static LANE: Cell<Option<LaneId>> = const { Cell::new(None) };
    /// Open spans, innermost last. See the module docs on why this exists.
    static STACK: RefCell<Vec<Frame>> = const { RefCell::new(Vec::new()) };
}

struct Frame {
    state: State,
    work: WorkKind,
    item: Option<u32>,
    /// Held as an `Instant` rather than as microseconds-from-origin, so a frame that outlives a
    /// rebase ([`set_origin`]) can be clamped into the new window when it closes. Stored the other
    /// way, a lane blocked across the boundary between two `MLE_REPEAT` iterations would close with
    /// a start from the old window and an end from the new one — inverted, so dropped, leaving a
    /// hole in exactly the lanes whose idleness the figures are about.
    start: Instant,
}

/// Declare which lane the calling thread is. Call once, at the top of the thread body, before any
/// span is opened on it.
pub fn bind_lane(lane: LaneId) {
    LANE.with(|l| l.set(Some(lane)));
}

/// Bind `lane` for the duration of `f`, restoring whatever was bound before, on unwind too.
///
/// For threads that are not theirs alone: the replay workers are closures on the shared rayon pool, and
/// a binding left behind would file a later closure's spans under this lane. [`validate`] cannot catch
/// that — it checks that a lane's spans do not overlap, not that they belong to it.
pub fn with_lane<R>(lane: LaneId, f: impl FnOnce() -> R) -> R {
    struct Restore {
        prev: Option<LaneId>,
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            LANE.with(|l| l.set(self.prev));
        }
    }
    let _restore = Restore {
        prev: LANE.with(|l| l.replace(Some(lane))),
    };
    f()
}

/// An open span; records on drop. Deliberately neither `Send` nor `Sync`: the stack it pops from is
/// per-thread, so a guard crossing threads would corrupt another lane's spans.
pub struct Guard {
    /// The stack depth this guard sits at, so a drop out of nesting order is caught rather than
    /// silently closing somebody else's span. RAII in a lexical scope is LIFO by construction, but
    /// nothing stops a caller from `drop()`-ing an outer guard first, and the resulting spans would be
    /// wrong in a way [`validate`] cannot see — it checks that a lane's spans do not overlap, not that
    /// they were attributed to the right work.
    depth: Option<usize>,
    _not_send: PhantomData<*const ()>,
}

/// Say once, not per occurrence, that a guard was dropped out of nesting order. The recovery leaves the
/// data usable, so this is a bug report about the instrumentation rather than a fact about the run — and
/// a message repeated a few hundred times inside `Drop` would bury the log it is trying to warn in.
fn report_disorder(lane: LaneId, opened_at: usize, found: usize) {
    static TOLD: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if !TOLD.swap(true, std::sync::atomic::Ordering::Relaxed) {
        tracing::warn!(
            "MLE spans: a guard on lane {lane} was dropped out of nesting order (opened at depth \
             {opened_at}, found {found}) — inner guards leaked; their spans are discarded and the \
             enclosing span resumes. Figures for that lane are incomplete, not wrong."
        );
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        let Some(depth) = self.depth else { return };
        let Some(lane) = LANE.with(|l| l.get()) else {
            return;
        };
        let Some(origin) = origin() else { return };
        let now = Instant::now();
        let now_us = us_since(origin, now);
        STACK.with(|s| {
            let mut stack = s.borrow_mut();
            // Out of nesting order: guards inside this one leaked, or something popped past it. Recover
            // by discarding this frame and everything above it, then resuming the outer — the leaked
            // frames cannot be attributed to anything, and *leaving* them is the worse failure: a stale
            // frame becomes `last_mut()` for every later `open()`, so its work kind then claims every
            // interval on that lane, and it keeps the timeline contiguous so neither the overlap check
            // nor the gap total notices. Deliberately no panic: this runs in `Drop`, possibly while
            // another unwind is in flight, and instrumentation must not be what takes a run down.
            if stack.len() < depth {
                return; // already gone; nothing of ours left to close
            }
            if stack.len() > depth {
                report_disorder(lane, depth, stack.len());
                stack.truncate(depth);
            }
            if let Some(frame) = stack.pop() {
                push(Span {
                    lane,
                    state: frame.state,
                    work: frame.work,
                    item: frame.item,
                    start_us: us_since(origin, frame.start),
                    end_us: now_us,
                });
            }
            // Resume the span this one interrupted, starting now — so the lane's spans stay
            // contiguous instead of leaving the inner span's extent charged to the outer one too.
            if let Some(outer) = stack.last_mut() {
                outer.start = now;
            }
        });
    }
}

/// Open a span on the calling thread's lane. Closes whatever span is currently open on it and
/// reopens that one when this guard drops (see the module docs).
///
/// A no-op — returning an inert guard — when recording is inactive or the thread bound no lane, so
/// call sites need no `if enabled` of their own.
pub fn open(state: State, work: WorkKind, item: Option<u32>) -> Guard {
    let inert = Guard {
        depth: None,
        _not_send: PhantomData,
    };
    let Some(lane) = LANE.with(|l| l.get()) else {
        return inert;
    };
    let Some(origin) = origin() else { return inert };
    let now = Instant::now();
    let now_us = us_since(origin, now);
    let depth = STACK.with(|s| {
        let mut stack = s.borrow_mut();
        // Close the enclosing span at this instant; its remainder resumes when this one drops.
        if let Some(outer) = stack.last_mut() {
            push(Span {
                lane,
                state: outer.state,
                work: outer.work,
                item: outer.item,
                start_us: us_since(origin, outer.start),
                end_us: now_us,
            });
            outer.start = now;
        }
        stack.push(Frame {
            state,
            work,
            item,
            start: now,
        });
        stack.len()
    });
    Guard {
        depth: Some(depth),
        _not_send: PhantomData,
    }
}

/// Shorthand for the common cases.
pub fn busy(work: WorkKind, item: Option<u32>) -> Guard {
    open(State::Busy, work, item)
}
pub fn idle(work: WorkKind) -> Guard {
    open(State::Idle, work, None)
}
pub fn wait(work: WorkKind, item: Option<u32>) -> Guard {
    open(State::Wait, work, item)
}

// ------------------------------------------------------------------------------------- validation

/// What [`validate`] found. A violation voids a run's span data outright: every figure derived from
/// spans is cross-lane, so one broken lane leaves the rest untrustworthy rather than merely
/// incomplete, and reporting the survivors would mean publishing three plausible wrong numbers.
#[derive(Debug, PartialEq, Eq)]
pub enum Violation {
    /// Two spans on one lane cover the same instant — a lane was in two states at once, which
    /// means a span was opened without the stack (bypassing [`open`]) or a guard leaked.
    Overlap {
        lane: LaneId,
        first_end_us: u64,
        second_start_us: u64,
    },
    /// A span ends after it starts nowhere, i.e. the clock went backwards.
    Inverted { lane: LaneId, start_us: u64 },
}

/// Per-lane gaps: time inside a lane's life that no span accounts for. Small totals are the loop
/// overhead between one guard dropping and the next opening; a large one means a blocking call
/// nobody bracketed, so it is reported rather than tolerated silently.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct GapReport {
    pub lane_gaps: Vec<(LaneId, u64)>,
}

impl GapReport {
    /// Lanes whose unaccounted time exceeds `frac` of their own life.
    pub fn significant(&self, lifetimes: &[(LaneId, u64)], frac: f64) -> Vec<(LaneId, u64, f64)> {
        self.lane_gaps
            .iter()
            .filter_map(|&(lane, gap)| {
                let life = lifetimes
                    .iter()
                    .find(|(l, _)| *l == lane)
                    .map(|(_, v)| *v)?;
                if life == 0 {
                    return None;
                }
                let r = gap as f64 / life as f64;
                (r > frac).then_some((lane, gap, r))
            })
            .collect()
    }
}

/// Check the one invariant the stack cannot enforce: a lane's spans must not overlap. Also totals
/// the gaps, which is how a *missing* span shows up — the stack keeps what it sees contiguous, so
/// unaccounted time means a blocking call that was never bracketed.
///
/// `spans` must be sorted by `(lane, start_us)`; [`snapshot`] returns them that way.
pub fn validate(spans: &[Span]) -> Result<GapReport, Violation> {
    let mut report = GapReport::default();
    let mut i = 0;
    while i < spans.len() {
        let lane = spans[i].lane;
        let mut gap = 0u64;
        let mut prev_end: Option<u64> = None;
        while i < spans.len() && spans[i].lane == lane {
            let s = &spans[i];
            if s.end_us < s.start_us {
                return Err(Violation::Inverted {
                    lane,
                    start_us: s.start_us,
                });
            }
            if let Some(pe) = prev_end {
                if s.start_us < pe {
                    return Err(Violation::Overlap {
                        lane,
                        first_end_us: pe,
                        second_start_us: s.start_us,
                    });
                }
                gap += s.start_us - pe;
            }
            prev_end = Some(s.end_us);
            i += 1;
        }
        report.lane_gaps.push((lane, gap));
    }
    Ok(report)
}

// ----------------------------------------------------------------------------------------- export

/// Where iteration `n` of an `MLE_REPEAT` run writes.
///
/// Every iteration exports its own window now ([`set_origin`] clears the store), so one shared path
/// would leave only the last of them on disk — and a figure taken from whichever iteration proved
/// fastest can only be explained by that iteration's own timeline.
///
/// Appended rather than inserted before the extension, so that `single_node_mle.sh` — which has to
/// find these files afterwards, and cannot call this — can mirror the rule with string concatenation
/// and no way to disagree. Inserting it needs the same notion of "extension" on both sides, and the
/// two do not have one: `Path` reads it off the file name, so a dot in a directory, the leading dot
/// of a hidden file, and a trailing slash each mean something different to a shell's `%.*`.
pub fn csv_path_for_iteration(path: &str, iteration: usize) -> String {
    format!("{path}.iter{iteration}")
}

/// Write the spans as CSV, validating first. `Err` on a violation, so the caller voids the run's
/// derived figures rather than exporting data it has just been told not to trust.
pub fn export_csv(path: &str, spans: &[Span]) -> std::io::Result<GapReport> {
    use std::io::Write;
    let report = validate(spans).map_err(|v| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("span invariant violated: {v:?}"),
        )
    })?;
    let mut f = std::io::BufWriter::new(std::fs::File::create(path)?);
    writeln!(f, "lane,index,state,work,item,start_us,end_us")?;
    for s in spans {
        writeln!(
            f,
            "{},{},{},{},{},{},{}",
            s.lane.role.as_str(),
            s.lane.index,
            s.state.as_str(),
            s.work.as_str(),
            s.item.map(|c| c.to_string()).unwrap_or_default(),
            s.start_us,
            s.end_us
        )?;
    }
    f.flush()?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shared by every test that drives the *real* recording path, because the origin and the span
    /// store are process-globals: two such tests in parallel would clear each other's window. Tests
    /// that only build `Span` values by hand need not take it.
    static SERIAL: Mutex<()> = Mutex::new(());

    fn span(lane: LaneId, state: State, work: WorkKind, start_us: u64, end_us: u64) -> Span {
        Span {
            lane,
            state,
            work,
            item: None,
            start_us,
            end_us,
        }
    }

    fn prove_lane() -> LaneId {
        LaneId::new(Role::Prove, 0)
    }

    /// The property the emulator's replay workers depend on: a rayon thread must leave the pool with
    /// whatever binding it arrived with, or a later span from unrelated work lands on this lane.
    #[test]
    fn with_lane_restores_the_previous_binding() {
        let outer = LaneId::new(Role::Prove, 3);
        let inner = LaneId::new(Role::Emulate, 7);
        bind_lane(outer);
        with_lane(inner, || {
            assert_eq!(LANE.with(|l| l.get()), Some(inner));
        });
        assert_eq!(LANE.with(|l| l.get()), Some(outer));
    }

    /// Same property from the state the workers actually start in: a pool thread that never bound a
    /// lane must go back to having none, not to the last worker's lane.
    #[test]
    fn with_lane_leaves_an_unbound_thread_unbound() {
        let inner = LaneId::new(Role::Emulate, 2);
        assert_eq!(LANE.with(|l| l.get()), None, "test threads start unbound");
        with_lane(inner, || {
            assert_eq!(LANE.with(|l| l.get()), Some(inner));
        });
        assert_eq!(LANE.with(|l| l.get()), None);
    }

    /// A panicking closure must not leave the lane bound: the pipeline takes the process down on a
    /// worker panic, but the recovery path runs enough code first for a stale binding to matter.
    #[test]
    fn with_lane_unbinds_on_unwind() {
        let inner = LaneId::new(Role::Emulate, 5);
        let caught = std::panic::catch_unwind(|| {
            with_lane(inner, || panic!("boom"));
        });
        assert!(caught.is_err());
        assert_eq!(LANE.with(|l| l.get()), None);
    }

    #[test]
    fn contiguous_spans_validate_with_no_gap() {
        let l = prove_lane();
        let spans = vec![
            span(l, State::Idle, WorkKind::ProveRiscv, 0, 100),
            span(l, State::Busy, WorkKind::ProveRiscv, 100, 500),
            span(l, State::Idle, WorkKind::ProveRiscv, 500, 600),
        ];
        let r = validate(&spans).expect("contiguous spans are valid");
        assert_eq!(r.lane_gaps, vec![(l, 0)]);
    }

    #[test]
    fn overlap_is_a_violation() {
        let l = prove_lane();
        let spans = vec![
            span(l, State::Busy, WorkKind::ProveRiscv, 100, 500),
            span(l, State::Busy, WorkKind::Keygen, 400, 450),
        ];
        assert_eq!(
            validate(&spans),
            Err(Violation::Overlap {
                lane: l,
                first_end_us: 500,
                second_start_us: 400
            })
        );
    }

    #[test]
    fn a_missing_span_shows_up_as_a_gap() {
        // The 300us between 500 and 800 is a blocking call nobody bracketed.
        let l = prove_lane();
        let spans = vec![
            span(l, State::Busy, WorkKind::ProveRiscv, 100, 500),
            span(l, State::Busy, WorkKind::ProveRiscv, 800, 900),
        ];
        let r = validate(&spans).expect("a gap is not a violation");
        assert_eq!(r.lane_gaps, vec![(l, 300)]);
        assert_eq!(r.significant(&[(l, 800)], 0.10), vec![(l, 300, 0.375)]);
        assert!(r.significant(&[(l, 800)], 0.50).is_empty());
    }

    #[test]
    fn lanes_are_validated_independently() {
        // Two lanes busy over the same instants is the normal case, not an overlap.
        let a = LaneId::new(Role::ConvertPreparer, 0);
        let b = prove_lane();
        let spans = vec![
            span(a, State::Busy, WorkKind::Keygen, 0, 500),
            span(b, State::Busy, WorkKind::ProveRiscv, 100, 400),
        ];
        let r = validate(&spans).expect("different lanes may overlap");
        assert_eq!(r.lane_gaps.len(), 2);
    }

    #[test]
    fn gpu_busy_excludes_blocked_states_and_cpu_work() {
        let l = prove_lane();
        assert!(span(l, State::Busy, WorkKind::ProveRiscv, 0, 1).is_gpu_busy());
        assert!(span(l, State::Busy, WorkKind::Keygen, 0, 1).is_gpu_busy());
        // Blocked on a gate is not occupying the device, even on a GPU-touching lane.
        assert!(!span(l, State::Wait, WorkKind::Keygen, 0, 1).is_gpu_busy());
        assert!(!span(l, State::Idle, WorkKind::ProveRiscv, 0, 1).is_gpu_busy());
        // CPU work on a preparer never counts.
        assert!(!span(l, State::Busy, WorkKind::PrepareRiscv, 0, 1).is_gpu_busy());
    }

    /// A guard dropped out of nesting order must not leave its frame behind. If it did, that frame
    /// becomes the stack top for every later `open()`, so its work kind silently claims every
    /// subsequent interval on the lane — and because the timeline stays contiguous, neither
    /// [`validate`] nor the gap total would notice.
    ///
    /// Driven through the real recording path rather than synthetic spans, since the behaviour under
    /// test is the stack discipline itself. Serialised on a mutex because the lane and the stack are
    /// thread-locals and `cargo test` shares threads between tests.
    #[test]
    fn a_guard_dropped_out_of_order_does_not_leak_its_frame() {
        let _lock = SERIAL.lock().expect("serial mutex poisoned");
        set_origin(Instant::now());
        bind_lane(LaneId::new(Role::Prove, 99));
        STACK.with(|s| s.borrow_mut().clear());

        let outer = open(State::Busy, WorkKind::ProveRiscv, None);
        let inner = open(State::Busy, WorkKind::Keygen, None);
        assert_eq!(STACK.with(|s| s.borrow().len()), 2);

        // Out of order on purpose: the outer goes first, with the inner still open.
        drop(outer);
        // Both frames are gone — the outer's own span was recorded and the leaked inner discarded —
        // so nothing is left to mis-attribute later intervals to.
        assert_eq!(
            STACK.with(|s| s.borrow().len()),
            0,
            "the refused frame must not survive the drop"
        );
        // Dropping the stale guard afterwards is a no-op rather than a panic or a stray span.
        drop(inner);
        assert_eq!(STACK.with(|s| s.borrow().len()), 0);

        // And the lane is usable again: a fresh span opens at depth 1, not on top of a leaked frame.
        let after = open(State::Busy, WorkKind::ProveConvert, None);
        assert_eq!(STACK.with(|s| s.borrow().len()), 1);
        drop(after);
        STACK.with(|s| s.borrow_mut().clear());
        LANE.with(|l| l.set(None));
    }

    /// What `MLE_REPEAT` does to a long-lived lane. The scheduler is a singleton, so a preparer
    /// blocked when one proof ends is still blocked when the driver opens the next window, and its
    /// span closes on the far side of a [`set_origin`]. It has to land *inside* the new window,
    /// clamped to its origin — held as microseconds-from-origin instead, the span would close with a
    /// start from the old window and an end from the new one, be inverted, and be dropped by
    /// [`push`], leaving the lane's idleness unaccounted for. That hole is what used to make every
    /// lane of a repeat run report ~74% "unbracketed time".
    #[test]
    fn a_span_open_across_a_rebase_is_clamped_into_the_new_window() {
        let _lock = SERIAL.lock().expect("serial mutex poisoned");
        let lane = LaneId::new(Role::Prove, 77);
        set_origin(Instant::now());
        bind_lane(lane);
        STACK.with(|s| s.borrow_mut().clear());

        // Blocked while the previous window was still open...
        let blocked = idle(WorkKind::ProveRiscv);
        // ...the driver starts the next proof, which rebases the origin and clears the store...
        set_origin(Instant::now());
        // ...the lane stays blocked a measurable while into it (a span of zero microseconds is
        // dropped on purpose, so the assertions below need one that lasts)...
        std::thread::sleep(std::time::Duration::from_millis(2));
        // ...and only then does it wake up.
        drop(blocked);

        let recorded: Vec<_> = snapshot().into_iter().filter(|s| s.lane == lane).collect();
        assert_eq!(
            recorded.len(),
            1,
            "the span must survive the rebase, not be dropped as inverted"
        );
        assert_eq!(
            recorded[0].start_us, 0,
            "a span that predates the window starts at its origin"
        );
        assert_eq!(recorded[0].state, State::Idle);

        STACK.with(|s| s.borrow_mut().clear());
        LANE.with(|l| l.set(None));
    }

    /// The other half of the rebase contract: opening a window discards the previous one's spans, so
    /// what a repeat run exports is one proof rather than every proof since process start.
    #[test]
    fn opening_a_window_discards_the_previous_one() {
        let _lock = SERIAL.lock().expect("serial mutex poisoned");
        let lane = LaneId::new(Role::Prove, 78);
        set_origin(Instant::now());
        bind_lane(lane);
        STACK.with(|s| s.borrow_mut().clear());

        let working = busy(WorkKind::ProveRiscv, Some(0));
        // Long enough to be recorded at all: `push` drops a span of zero microseconds.
        std::thread::sleep(std::time::Duration::from_millis(2));
        drop(working);
        assert!(
            snapshot().iter().any(|s| s.lane == lane),
            "the first window recorded nothing to discard"
        );

        set_origin(Instant::now());
        assert!(
            !snapshot().iter().any(|s| s.lane == lane),
            "the previous window's spans outlived it"
        );

        LANE.with(|l| l.set(None));
    }

    /// The naming a repeat run's exports rely on. Iteration 1 is named too, so a repeat run's files
    /// form one series rather than a bare path plus some suffixed ones.
    #[test]
    fn a_repeat_iteration_gets_its_own_csv_path() {
        assert_eq!(
            csv_path_for_iteration("logs/run.spans.csv", 2),
            "logs/run.spans.csv.iter2"
        );
        assert_eq!(
            csv_path_for_iteration("logs/run.spans.csv", 1),
            "logs/run.spans.csv.iter1"
        );
    }

    /// A directory under the system temp dir, removed when the test that made it ends. Hand-rolled
    /// rather than a dev-dependency on `tempfile`, which no crate here declares today.
    struct TempDir(std::path::PathBuf);

    impl TempDir {
        fn new(tag: &str) -> Self {
            let p = std::env::temp_dir().join(format!("pico-spans-{tag}-{}", std::process::id()));
            std::fs::create_dir_all(&p).expect("temp dir");
            Self(p)
        }

        fn path(&self, name: &str) -> String {
            self.0.join(name).to_string_lossy().into_owned()
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The export half of the per-iteration guarantee: two windows in one process land in two files,
    /// each carrying only its own spans. [`opening_a_window_discards_the_previous_one`] already covers
    /// the store; nothing covered what reaches disk.
    #[test]
    fn consecutive_windows_export_to_separate_files() {
        let _lock = SERIAL.lock().expect("serial mutex poisoned");
        let dir = TempDir::new("iters");
        let base = dir.path("run.spans.csv");
        let lane = LaneId::new(Role::Prove, 91);

        set_origin(Instant::now());
        bind_lane(lane);
        STACK.with(|s| s.borrow_mut().clear());
        {
            // Long enough to be recorded at all: `push` drops a span of zero microseconds.
            let _b = busy(WorkKind::ProveRiscv, Some(11));
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let first = csv_path_for_iteration(&base, 1);
        export_csv(&first, &snapshot()).expect("first window exports");

        set_origin(Instant::now());
        {
            let _b = busy(WorkKind::ProveConvert, Some(22));
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        let second = csv_path_for_iteration(&base, 2);
        export_csv(&second, &snapshot()).expect("second window exports");

        let c1 = std::fs::read_to_string(&first).expect("first csv readable");
        let c2 = std::fs::read_to_string(&second).expect("second csv readable");
        assert!(
            c1.contains("prove-riscv") && !c1.contains("prove-convert"),
            "the first window's file gained the second window's work: {c1}"
        );
        assert!(
            c2.contains("prove-convert") && !c2.contains("prove-riscv"),
            "the second window's file still carries the first window's work: {c2}"
        );

        LANE.with(|l| l.set(None));
    }

    #[test]
    fn inverted_span_is_a_violation() {
        let l = prove_lane();
        let spans = vec![span(l, State::Busy, WorkKind::ProveRiscv, 500, 100)];
        assert_eq!(
            validate(&spans),
            Err(Violation::Inverted {
                lane: l,
                start_us: 500
            })
        );
    }
}
