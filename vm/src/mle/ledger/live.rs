//! The recording half of [`super`]: the sink, the window, the stage hooks, the envelope and the
//! precompile timers. Built only with the `stage-ledger` feature; `off` has the same functions as
//! no-ops.

use std::{
    cell::Cell,
    collections::BTreeSet,
    fs::{File, OpenOptions},
    io::{BufWriter, Read, Seek, SeekFrom, Write},
    path::Path,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Mutex, OnceLock, PoisonError, RwLock,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use serde_json::{json, Map, Value};

use super::{
    At, Context, Driver, FileId, Lane, ProveSlot, Setup, FEATURES, KNOBS, RESERVED_STAGES,
    SCHEMA_VERSION,
};
use crate::mle::spans::{self, LaneId, Role};

mod timers;

pub use timers::{
    deferred_extend, deferred_memory_extend, drain_cpu_window, precompile_compute,
    precompile_event_path, precompile_start, take_timers, timer_start, SplitPhases, TimerStart,
    Timers,
};

/// The prove side, written as skipped for every chunk of an arm that only emulates.
const PROVE_STAGES: &[&str] = &[
    "prove.augment.clone",
    "prove.augment.*",
    "prove.shape",
    "prove.tracegen.*",
    "prove.build_ctx_gpu",
    "prove.prove",
    "prove.verify",
];

/// The host prove stages a `cuda-mle` build never runs, written as skipped for every chunk of an
/// arm that proves: the device generates the traces, so the extra-record pass and the per-chip
/// host trace generation have no producer on it.
#[cfg(feature = "cuda")]
const HOST_TRACEGEN_STAGES: &[&str] =
    &["prove.augment.clone", "prove.augment.*", "prove.tracegen.*"];

type Sink = Mutex<BufWriter<File>>;

static SINK: OnceLock<Option<Sink>> = OnceLock::new();

fn sink() -> Option<&'static Sink> {
    SINK.get_or_init(|| {
        let path = std::env::var_os("MLE_LEDGER")?;
        match open_for_append(Path::new(&path)) {
            Ok(file) => Some(Mutex::new(BufWriter::with_capacity(1 << 16, file))),
            Err(err) => {
                tracing::warn!(
                    "MLE_LEDGER={}: {err}; the ledger records nothing",
                    Path::new(&path).display()
                );
                None
            }
        }
    })
    .as_ref()
}

/// Opens `path` for appending, ending a line a killed run left unfinished first, so that line stays
/// one torn line and this run's first does not join it.
fn open_for_append(path: &Path) -> std::io::Result<File> {
    let mut file = OpenOptions::new()
        .create(true)
        .read(true)
        .append(true)
        .open(path)?;
    if file.metadata()?.len() > 0 {
        let mut last = [0u8; 1];
        file.seek(SeekFrom::End(-1))?;
        file.read_exact(&mut last)?;
        if last[0] != b'\n' {
            file.write_all(b"\n")?;
        }
    }
    Ok(file)
}

/// Whether `MLE_LEDGER` names a file the ledger could open.
pub fn enabled() -> bool {
    sink().is_some()
}

fn write_line(sink: &Sink, line: &Value) {
    // Formatted outside the lock: sixteen workers finishing a batch together should queue on a
    // `write` of a finished line, not on each other's formatting.
    let mut text = line.to_string();
    text.push('\n');
    let mut out = sink.lock().unwrap_or_else(PoisonError::into_inner);
    if let Err(err) = out.write_all(text.as_bytes()) {
        tracing::warn!("MLE_LEDGER write failed: {err}");
    }
}

/// `MLE_LEDGER_DIGESTS=1`: the per-chip trace digest and the execution history's, the facts that
/// read the data itself.
pub fn digests_enabled() -> bool {
    static ON: OnceLock<bool> = OnceLock::new();
    *ON.get_or_init(|| std::env::var("MLE_LEDGER_DIGESTS").is_ok_and(|v| v == "1"))
}

struct Head {
    run: String,
    arm: Value,
    origin: Instant,
    /// The provisional envelope, kept so [`finish`] writes the same fields again beside the ones
    /// only the end knows.
    envelope: Map<String, Value>,
    /// Whether stages are written: from the window's opening until its emulation fails, its records
    /// drop, or another window overlaps it.
    recording: bool,
}

static HEAD: RwLock<Option<Head>> = RwLock::new(None);

/// Per-window state the hooks update. Cleared when a window opens.
#[derive(Default)]
struct Seen {
    chunks: BTreeSet<u64>,
    /// Where the snapshot thread's emulator setup ended: the phase walls start here, so the setup
    /// the envelope reports apart is in none of them.
    emulate_start: Option<Instant>,
    emulate_end: Option<Instant>,
    /// VmHWM when the emulation ended, and whether it was then reset, so that a reading at the
    /// close holds only what came after.
    emulation_peak_kib: Option<u64>,
    peak_reset: bool,
    dropped: bool,
    finished: bool,
}

static SEEN: Mutex<Option<Seen>> = Mutex::new(None);

/// Microseconds from the origin of the earliest and latest prove-stage instants, for the riscv
/// phase's wall.
static PROVE_FIRST_US: AtomicU64 = AtomicU64::new(u64::MAX);
static PROVE_LAST_US: AtomicU64 = AtomicU64::new(0);

/// Between a window's opening and the end of its emulation, with either instrument on.
static EMULATING: AtomicBool = AtomicBool::new(false);
/// Prove jobs inside [`with_prove_slot`] anywhere in the process, whatever window they belong to.
static ACTIVE_PROVE_SLOTS: AtomicUsize = AtomicUsize::new(0);
/// Set when two windows overlapped; both instruments stay off for the rest of the process.
static OVERLAPPED: AtomicBool = AtomicBool::new(false);
/// A span recording the window opened and nobody has exported yet.
static SPANS_PENDING: AtomicBool = AtomicBool::new(false);

static DRIVER: Mutex<Option<Driver>> = Mutex::new(None);

/// Record what the driver knows about this run, and that it will call [`finish`] after its timer.
/// Call before the timed work.
pub fn set_driver(driver: Driver) {
    *DRIVER.lock().unwrap_or_else(PoisonError::into_inner) = Some(driver);
}

fn driver() -> Driver {
    DRIVER
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .clone()
        .unwrap_or_default()
}

fn driven() -> bool {
    DRIVER
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .is_some()
}

/// `MLE_SPANS=<path>`: where the span recorder's CSV goes.
fn spans_path() -> Option<String> {
    std::env::var("MLE_SPANS").ok().filter(|p| !p.is_empty())
}

/// Ends the emulation half of the window it is returned for when dropped (see [`close_emulation`]),
/// and the window itself when the drop is an unwind: a panicked emulation has no prove to follow.
#[must_use = "the window's emulation ends when this drops"]
pub struct EmulationWindow(());

impl Drop for EmulationWindow {
    fn drop(&mut self) {
        close_emulation(Instant::now());
        if std::thread::panicking() {
            close_window();
        }
    }
}

/// Open a recording window for both instruments at `t`, if either is asked for: the span recorder
/// when `MLE_SPANS` is set, the ledger when `MLE_LEDGER` is. With neither, nothing is recorded,
/// which is how both stay inert in production.
///
/// `snapshot_main`, `worker_kind` and `workers` describe the arm; they go into the envelope because
/// the engine that ran is a property of the types, not of the arm's label.
pub fn open_window(
    t: Instant,
    snapshot_main: &str,
    worker_kind: &str,
    workers: usize,
) -> EmulationWindow {
    let window = EmulationWindow(());
    let ledger = sink();
    let spans_on = spans_path().is_some();
    if (ledger.is_none() && !spans_on) || OVERLAPPED.load(Ordering::Relaxed) {
        return window;
    }
    let mut head = HEAD.write().unwrap_or_else(PoisonError::into_inner);
    let emulating = EMULATING.swap(true, Ordering::Relaxed);
    let open_run_proved = head.as_ref().is_some_and(|head| head.recording)
        && PROVE_FIRST_US.load(Ordering::Relaxed) != u64::MAX;
    if opens_over_a_run(
        emulating,
        ACTIVE_PROVE_SLOTS.load(Ordering::Relaxed),
        open_run_proved,
    ) {
        overlap(ledger, head.as_mut());
        return window;
    }
    if spans_on {
        spans::set_origin(t);
        SPANS_PENDING.store(true, Ordering::Relaxed);
    }
    let Some(sink) = ledger else {
        return window;
    };
    let run = run_id();
    let driver = driver();
    let arm = driver.arm.map_or(Value::Null, Value::String);
    let mut envelope = Map::new();
    envelope.insert("v".into(), json!(SCHEMA_VERSION));
    envelope.insert("kind".into(), json!("envelope"));
    envelope.insert("run".into(), json!(run));
    envelope.insert("arm".into(), arm.clone());
    envelope.insert("label".into(), json!(driver.label));
    envelope.insert("rep".into(), json!(driver.rep));
    envelope.insert("warmup".into(), json!(driver.warmup));
    envelope.insert("complete".into(), json!(false));
    envelope.insert("features".into(), json!(features()));
    envelope.insert(
        "degree_bound".into(),
        json!(pico_mle_core::config::soundness::DEGREE_BOUND),
    );
    envelope.insert("knobs".into(), knobs());
    envelope.insert("snapshot_main".into(), json!(snapshot_main));
    envelope.insert("worker_kind".into(), json!(worker_kind));
    envelope.insert("representation".into(), json!(representation()));
    envelope.insert("producer".into(), json!("cpu"));
    envelope.insert("workers".into(), json!(workers));
    envelope.insert("split".into(), split());
    envelope.insert("loadavg".into(), loadavg());
    envelope.insert(
        "cpus_allowed_list".into(),
        proc_status_field("Cpus_allowed_list").map_or(Value::Null, Value::String),
    );
    envelope.insert(
        "mems_allowed_list".into(),
        proc_status_field("Mems_allowed_list").map_or(Value::Null, Value::String),
    );
    envelope.insert("lock_held".into(), json!(lock_held()));
    if timers::precompile_timers_on() {
        envelope.insert("timer_calibration".into(), timers::calibration());
    }
    write_line(sink, &Value::Object(envelope.clone()));
    PROVE_FIRST_US.store(u64::MAX, Ordering::Relaxed);
    PROVE_LAST_US.store(0, Ordering::Relaxed);
    *SEEN.lock().unwrap_or_else(PoisonError::into_inner) = Some(Seen::default());
    *head = Some(Head {
        run,
        arm,
        origin: t,
        envelope,
        recording: true,
    });
    window
}

/// Whether a window opening now would share the process with another run: one still emulating,
/// one with a riscv prove job in flight, or an open run that has proved and not yet dropped its
/// records, which is in its recursion phase or between prove batches.
fn opens_over_a_run(emulating: bool, active_prove_slots: usize, open_run_proved: bool) -> bool {
    emulating || active_prove_slots > 0 || open_run_proved
}

/// A second window while a run is in flight: the two runs' hooks cannot be told apart, so both
/// instruments stop for the rest of the process and the open run is marked.
fn overlap(ledger: Option<&Sink>, head: Option<&mut Head>) {
    OVERLAPPED.store(true, Ordering::Relaxed);
    spans::stop();
    let run = match (ledger, head) {
        (Some(sink), Some(head)) => {
            head.recording = false;
            head.envelope.insert("overlapped".into(), json!(true));
            write_line(sink, &Value::Object(head.envelope.clone()));
            flush();
            head.run.clone()
        }
        _ => "-".into(),
    };
    tracing::warn!(
        "MLE_LEDGER/MLE_SPANS: a second pipeline opened while run {run} was still emulating or \
         proving; both instruments stop here, the open run is marked overlapped and no span CSV is \
         written"
    );
}

/// The snapshot thread's emulator is set up at `t`: the phase walls start here.
pub fn emulation_starts(t: Instant) {
    if let Some(seen) = SEEN.lock().unwrap_or_else(PoisonError::into_inner).as_mut() {
        seen.emulate_start.get_or_insert(t);
    }
}

/// Close the emulation half of the window at `t`: the end of the emulate phase's wall, the
/// emulation's peak RSS, a flush, and, with no driver, the span CSV. The window stays open for the
/// prove stages that follow.
///
/// The peak is VmHWM, which is then reset to the current RSS, so the close line can report the
/// emulation's peak and that of everything after it apart. The reset is process-wide: any later
/// VmHWM read in the process holds only what came after it.
pub fn close_emulation(t: Instant) {
    EMULATING.store(false, Ordering::Relaxed);
    if OVERLAPPED.load(Ordering::Relaxed) {
        return;
    }
    if let Some(seen) = SEEN.lock().unwrap_or_else(PoisonError::into_inner).as_mut() {
        if seen.emulate_end.is_none() {
            seen.emulate_end = Some(t);
            seen.emulation_peak_kib = vmhwm_kib();
            seen.peak_reset = seen.emulation_peak_kib.is_some() && reset_vmhwm();
        }
    }
    if !driven() {
        export_spans();
    }
    flush();
}

/// Stop the window recording: its run has ended, so nothing later is written under it. [`finish`]
/// still completes its envelope.
pub(crate) fn close_window() {
    if let Some(head) = HEAD
        .write()
        .unwrap_or_else(PoisonError::into_inner)
        .as_mut()
    {
        head.recording = false;
    }
}

/// Write the span CSV once per window, unless the window overlapped another.
fn export_spans() {
    if !SPANS_PENDING.swap(false, Ordering::Relaxed) || OVERLAPPED.load(Ordering::Relaxed) {
        return;
    }
    let Some(path) = spans_path() else {
        return;
    };
    spans::stop();
    let recorded = spans::snapshot();
    match spans::export_csv(&path, &recorded) {
        Ok(gaps) => {
            tracing::info!("MLE_SPANS: {} span(s) written to {path}", recorded.len());
            for (lane, gap_us) in gaps.lane_gaps {
                if gap_us > 0 {
                    tracing::info!("MLE_SPANS: lane {lane} has {gap_us} us unbracketed");
                }
            }
        }
        Err(err) => tracing::warn!("MLE_SPANS: no CSV written to {path}: {err}"),
    }
}

/// Write the span CSV, the complete envelope for the window, and the skipped lines for every chunk
/// it saw: the reserved stages always, and the prove stages when the driver said the arm does not
/// prove. Then flush and close the window. Call once the driver's work is done, outside its timer;
/// a second call for the same window writes nothing.
pub fn finish() {
    export_spans();
    let Some(sink) = sink() else {
        return;
    };
    let mut head = HEAD.write().unwrap_or_else(PoisonError::into_inner);
    let Some(open) = head.as_ref() else {
        return;
    };
    let (chunks, emulate_start, emulate_end, dropped, emulation_peak_kib, peak_reset) = {
        let mut seen = SEEN.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(seen) = seen.as_mut() else {
            return;
        };
        if std::mem::replace(&mut seen.finished, true) {
            return;
        }
        (
            std::mem::take(&mut seen.chunks),
            seen.emulate_start,
            seen.emulate_end,
            seen.dropped,
            seen.emulation_peak_kib,
            seen.peak_reset,
        )
    };
    let driver = driver();
    for &chunk in &chunks {
        let at = At::chunk(chunk);
        for &stage in RESERVED_STAGES {
            // A `cuda-mle` build generates its traces on the device, which the `gpu.*` names are
            // for: not absent by design, so not written until a hook fills them.
            if cfg!(feature = "cuda") && stage.starts_with("gpu.") {
                continue;
            }
            write_line(sink, &skipped_line(open, stage, at, reserved_lane(stage)));
        }
        if driver.proves == Some(false) {
            for &stage in PROVE_STAGES {
                write_line(
                    sink,
                    &skipped_line(open, stage, at, LaneId::new(Role::Prove, 0).into()),
                );
            }
        }
        #[cfg(feature = "cuda")]
        if driver.proves != Some(false) {
            for &stage in HOST_TRACEGEN_STAGES {
                write_line(
                    sink,
                    &skipped_line(open, stage, at, LaneId::new(Role::Prove, 0).into()),
                );
            }
        }
    }

    if driver.proves == Some(false) && !dropped {
        write_line(
            sink,
            &skipped_line(open, "prove.drop_record", At::default(), Lane::DRIVER),
        );
    }

    let mut envelope = open.envelope.clone();
    envelope.insert("complete".into(), json!(true));
    let (branch, commit, dirty) = provenance();
    envelope.insert("branch".into(), branch);
    envelope.insert("commit".into(), commit);
    envelope.insert("dirty".into(), dirty);
    envelope.insert("host".into(), host());
    envelope.insert("elf".into(), file_id(driver.elf.as_ref()));
    envelope.insert("input".into(), file_id(driver.input.as_ref()));
    envelope.insert("loadavg_end".into(), loadavg());
    envelope.insert("mempolicy".into(), mempolicy());
    let peaks = Peaks::read(emulation_peak_kib, peak_reset, vmhwm_kib());
    envelope.insert(
        "peak_rss_kib".into(),
        peaks.whole_run_kib.map_or(Value::Null, |v| json!(v)),
    );
    if let Some(kib) = peaks.emulation_kib {
        envelope.insert("vmhwm_emulation_kib".into(), json!(kib));
    }
    if let Some(kib) = peaks.tracegen_kib {
        envelope.insert("vmhwm_tracegen_kib".into(), json!(kib));
    }
    let mut setup = SETUP.lock().unwrap_or_else(PoisonError::into_inner);
    let setup_us = std::mem::take(&mut *setup);
    drop(setup);
    envelope.insert(
        "setup_us".into(),
        json!({
            "keygen": setup_us[Setup::Keygen as usize],
            "emulator_setup": setup_us[Setup::EmulatorSetup as usize],
            "aot_build": null,
        }),
    );
    let start_us = emulate_start.map_or(0, |t| us_since(open.origin, t));
    let first = PROVE_FIRST_US.load(Ordering::Relaxed);
    let last = PROVE_LAST_US.load(Ordering::Relaxed);
    let proved = first != u64::MAX;
    envelope.insert(
        "stage_walls_us".into(),
        json!({
            "emulate": emulate_end.map(|t| us_since(open.origin, t).saturating_sub(start_us)),
            "riscv": proved.then(|| last.saturating_sub(first)),
            // The end of the emulator's setup to the end of the riscv phase's last stage: emulate,
            // prove and verify.
            "e2e": proved.then(|| last.saturating_sub(start_us)),
        }),
    );
    write_line(sink, &Value::Object(envelope));
    *head = None;
    flush();
}

/// Push the buffered lines to the file. Nothing flushes a static at exit, so a driver that never
/// calls [`finish`] keeps what was flushed: at the end of emulation and after the records drop.
fn flush() {
    if let Some(sink) = sink() {
        if let Err(err) = sink.lock().unwrap_or_else(PoisonError::into_inner).flush() {
            tracing::warn!("MLE_LEDGER flush failed: {err}");
        }
    }
}

fn reserved_lane(stage: &str) -> Lane {
    if stage.starts_with("history.") {
        LaneId::new(Role::Emulate, 0).into()
    } else {
        LaneId::new(Role::Prove, 0).into()
    }
}

/// Whether a lane's stages belong to the riscv phase's wall rather than the emulation's.
fn proves(lane: Lane) -> bool {
    lane.role == Role::Prove.as_str() || lane == Lane::VERIFY
}

/// Whether a stage written now would be recorded: the ledger is on and a window is recording. For a
/// hook whose facts cost something to gather.
pub fn active() -> bool {
    enabled()
        && HEAD
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .is_some_and(|head| head.recording)
}

fn us_since(origin: Instant, t: Instant) -> u64 {
    t.saturating_duration_since(origin).as_micros() as u64
}

fn header(head: &Head, stage: &str, at: At, lane: Lane) -> Map<String, Value> {
    let mut line = Map::new();
    line.insert("v".into(), json!(SCHEMA_VERSION));
    line.insert("run".into(), json!(head.run));
    line.insert("arm".into(), head.arm.clone());
    line.insert("chunk".into(), json!(at.chunk));
    line.insert("batch".into(), json!(at.batch));
    line.insert("seg".into(), json!(at.seg.map(|(i, n)| [i, n])));
    line.insert("record".into(), json!(at.record));
    line.insert("stage".into(), json!(stage));
    line.insert("lane".into(), json!({"role": lane.role, "idx": lane.idx}));
    line
}

fn skipped_line(head: &Head, stage: &str, at: At, lane: Lane) -> Value {
    let mut line = header(head, stage, at, lane);
    line.insert("skipped".into(), json!(true));
    Value::Object(line)
}

/// One stage of one chunk, from `t0` to `t1` on `lane`. `facts` is evaluated only when the line is
/// written.
pub fn stage(
    name: &str,
    at: At,
    lane: impl Into<Lane>,
    t0: Instant,
    t1: Instant,
    facts: impl FnOnce() -> Value,
) {
    let Some(sink) = sink() else {
        return;
    };
    let head = HEAD.read().unwrap_or_else(PoisonError::into_inner);
    let Some(head) = head.as_ref().filter(|head| head.recording) else {
        return;
    };
    let t0_us = us_since(head.origin, t0);
    let t1_us = us_since(head.origin, t1).max(t0_us);
    let lane = lane.into();
    if proves(lane) {
        PROVE_FIRST_US.fetch_min(t0_us, Ordering::Relaxed);
        PROVE_LAST_US.fetch_max(t1_us, Ordering::Relaxed);
    }
    if let Some(chunk) = at.chunk {
        if let Some(seen) = SEEN.lock().unwrap_or_else(PoisonError::into_inner).as_mut() {
            seen.chunks.insert(chunk);
        }
    }
    let mut line = header(head, name, at, lane);
    line.insert("t0_us".into(), json!(t0_us));
    line.insert("t1_us".into(), json!(t1_us));
    line.insert("dur_us".into(), json!(t1_us - t0_us));
    line.insert("facts".into(), facts());
    write_line(sink, &Value::Object(line));
}

/// A stage this arm lacks by design, for one chunk.
pub fn skipped(name: &str, at: At, lane: impl Into<Lane>) {
    let Some(sink) = sink() else {
        return;
    };
    let head = HEAD.read().unwrap_or_else(PoisonError::into_inner);
    if let Some(head) = head.as_ref().filter(|head| head.recording) {
        write_line(sink, &skipped_line(head, name, at, lane.into()));
    }
}

thread_local! {
    static PROVE_SLOT: Cell<Option<ProveSlot>> = const { Cell::new(None) };
    /// Microseconds this thread has spent running a prove job nested inside another one's wait.
    static NESTED_US: Cell<u64> = const { Cell::new(0) };
}

/// The slot the calling job holds, if it is inside [`with_prove_slot`].
pub fn current_prove_slot() -> Option<ProveSlot> {
    PROVE_SLOT.with(Cell::get)
}

/// Run `f` as `slot`, restoring whatever was set before, on unwind too. Restored rather than
/// cleared because rayon may run another record's job on this thread while this one waits inside
/// the prover, and that job must not leave its slot behind.
///
/// Such a nested job's whole wall is added to the thread's nested time, which [`prove_stage`] takes
/// out of the stage it interrupted: the stage's interval holds it, its own work does not. A smaller
/// task of another record's prove that the waiting thread steals is not a job and is not taken
/// out, so with more than one proof in flight a stage's own time is an upper bound.
pub fn with_prove_slot<R>(slot: ProveSlot, f: impl FnOnce() -> R) -> R {
    struct Restore {
        prev: Option<ProveSlot>,
        /// When this job started and the nested time before it, if it nests in another job.
        nested_from: Option<(Instant, u64)>,
    }
    impl Drop for Restore {
        fn drop(&mut self) {
            PROVE_SLOT.with(|s| s.set(self.prev));
            if let Some((t0, before)) = self.nested_from {
                // Set, not added: the job's wall already holds whatever nested inside it.
                NESTED_US.with(|n| n.set(before + t0.elapsed().as_micros() as u64));
            }
            ACTIVE_PROVE_SLOTS.fetch_sub(1, Ordering::Relaxed);
        }
    }
    ACTIVE_PROVE_SLOTS.fetch_add(1, Ordering::Relaxed);
    let prev = PROVE_SLOT.with(|s| s.replace(Some(slot)));
    let _restore = Restore {
        prev,
        nested_from: prev.map(|_| (Instant::now(), NESTED_US.with(Cell::get))),
    };
    f()
}

/// Where a prove stage starts: the instant, and the calling thread's nested time so far.
#[derive(Clone, Copy, Debug)]
pub struct ProveMark {
    t: Instant,
    nested_us: u64,
}

impl ProveMark {
    pub fn now() -> Self {
        Self {
            t: Instant::now(),
            nested_us: NESTED_US.with(Cell::get),
        }
    }
}

/// A prove stage of the record the calling job is on, from `since` to now. Nothing outside
/// [`with_prove_slot`]. Its facts gain `nested_us`, the part of the interval this thread spent on
/// another record's whole prove job (see [`with_prove_slot`] for what it leaves in).
pub fn prove_stage(name: &str, since: ProveMark, facts: impl FnOnce() -> Value) {
    prove_stage_until(name, since, ProveMark::now(), facts);
}

/// [`prove_stage`] for a stage that ended at `until`, its facts gathered now: device times can only
/// be read once the device has run past the work they time, after the stage.
pub fn prove_stage_until(
    name: &str,
    since: ProveMark,
    until: ProveMark,
    facts: impl FnOnce() -> Value,
) {
    let nested_us = until.nested_us.saturating_sub(since.nested_us);
    if let Some(slot) = PROVE_SLOT.with(Cell::get) {
        stage(name, slot.at(), slot.lane(), since.t, until.t, || {
            let mut facts = facts();
            if let Value::Object(map) = &mut facts {
                map.insert("nested_us".into(), json!(nested_us));
            }
            facts
        });
    }
}

/// Whether the calling job is inside [`with_prove_slot`] with the ledger recording.
pub fn in_prove_slot() -> bool {
    PROVE_SLOT.with(Cell::get).is_some() && active()
}

thread_local! {
    static CONTEXT: Cell<Option<Context>> = const { Cell::new(None) };
}

/// Run `f` under `context`, restoring the previous one on unwind too.
pub fn with_context<R>(context: Context, f: impl FnOnce() -> R) -> R {
    struct Restore(Option<Context>);
    impl Drop for Restore {
        fn drop(&mut self) {
            CONTEXT.with(|c| c.set(self.0));
        }
    }
    let _restore = Restore(CONTEXT.with(|c| c.replace(Some(context))));
    f()
}

/// The batch the calling thread works for, as a span item.
pub fn context_batch() -> Option<u32> {
    CONTEXT
        .with(Cell::get)
        .and_then(|c| c.at.batch)
        .map(|b| b as u32)
}

/// A wait on the snapshot memory pool from `t0` to `t1`: the `snapshot.pool_wait` stage of the batch
/// the calling thread works for. Nothing outside [`with_context`].
pub fn pool_wait(t0: Instant, t1: Instant, warned: bool) {
    if let Some(context) = CONTEXT.with(Cell::get) {
        stage(
            "snapshot.pool_wait",
            context.at,
            context.lane,
            t0,
            t1,
            || json!({ "wait_us": t1.saturating_duration_since(t0).as_micros() as u64, "warned": warned }),
        );
    }
}

/// Drop a run's records inside the `prove.drop_record` stage: freeing every chunk's history and events
/// is work inside the caller's timer, and unnamed it would read as a gap. The run ends here, so the
/// window stops recording.
pub fn drop_records(records: Vec<crate::emulator::riscv::record::EmulationRecord>) {
    let t0 = Instant::now();
    let counted = active().then(|| {
        (
            records.len(),
            records
                .iter()
                .map(crate::emulator::riscv::record_digest::record_bytes)
                .sum::<usize>(),
        )
    });
    drop(records);
    stage(
        "prove.drop_record",
        At::default(),
        Lane::DRIVER,
        t0,
        Instant::now(),
        || match counted {
            Some((records, bytes)) => json!({ "records": records, "record_bytes": bytes }),
            None => json!({}),
        },
    );
    if counted.is_some() {
        if let Some(seen) = SEEN.lock().unwrap_or_else(PoisonError::into_inner).as_mut() {
            seen.dropped = true;
        }
    }
    close_window();
    flush();
}

static SETUP: Mutex<[Option<u64>; 2]> = Mutex::new([None; 2]);

/// Add `d` to the `kind` setup time since the last [`finish`], which reports it and starts the next
/// run's from zero. Recorded whether or not a window is open: keygen runs before the pipeline's
/// window does.
pub fn add_setup(kind: Setup, d: Duration) {
    if !enabled() {
        return;
    }
    let mut setup = SETUP.lock().unwrap_or_else(PoisonError::into_inner);
    let slot = &mut setup[kind as usize];
    *slot = Some(slot.unwrap_or(0) + d.as_micros() as u64);
}

/// The snapshot thread's effective segmentation: how many segments a split chunk's replay is cut
/// into, and how many leading chunks are split, or, under `MLE_SPLIT_FROM_CHUNK`, the chunk the
/// split starts from, with no leading count. Unset knobs are not "off" — the card count and the
/// worker count can turn the split on — so the values the run used are recorded, not the knobs.
fn split() -> Value {
    #[cfg(feature = "aot-emulator")]
    {
        let segments = crate::emulator::aot::split_segments();
        match crate::emulator::aot::split_from_chunk() {
            Some(from) => json!({ "segments": segments, "from_chunk": from, "chunks": null }),
            None => json!({
                "segments": segments,
                "chunks": crate::emulator::aot::split_chunks(),
            }),
        }
    }
    #[cfg(not(feature = "aot-emulator"))]
    {
        Value::Null
    }
}

fn run_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!("{nanos:x}-{:x}", std::process::id())
}

/// The features `pico-vm` was built with, as the compiler saw them. A `pico-mle-core` feature
/// another crate turns on directly is not among them; the envelope's `degree_bound` is the one of
/// those that changes a proof.
fn features() -> Vec<&'static str> {
    let mut on: Vec<&str> = FEATURES
        .iter()
        .filter(|(_, built)| *built)
        .map(|(name, _)| *name)
        .collect();
    if cfg!(debug_assertions) {
        on.push("debug-assertions");
    }
    on
}

fn knobs() -> Value {
    Value::Object(
        KNOBS
            .iter()
            .map(|&name| {
                (
                    name.to_string(),
                    std::env::var(name).map_or(Value::Null, Value::String),
                )
            })
            .collect(),
    )
}

fn loadavg() -> Value {
    let Ok(text) = std::fs::read_to_string("/proc/loadavg") else {
        return Value::Null;
    };
    let loads: Vec<f64> = text
        .split_whitespace()
        .take(3)
        .filter_map(|v| v.parse().ok())
        .collect();
    if loads.len() == 3 {
        json!(loads)
    } else {
        Value::Null
    }
}

/// How many of the process's mappings carry each memory policy, from `/proc/self/numa_maps`.
/// `numactl --membind` sets a policy, which `Mems_allowed_list` (the cpuset) never shows: a run bound
/// to node 1 reads `bind:1` here and `0-1` there. Read at [`finish`], outside any timer, since the
/// walk is over every mapping.
fn mempolicy() -> Value {
    let Ok(text) = std::fs::read_to_string("/proc/self/numa_maps") else {
        return Value::Null;
    };
    let mut policies: std::collections::BTreeMap<&str, u64> = std::collections::BTreeMap::new();
    for line in text.lines() {
        if let Some(policy) = line.split_whitespace().nth(1) {
            *policies.entry(policy).or_default() += 1;
        }
    }
    json!(policies)
}

/// The calling thread's minor and major page faults so far, the counters `getrusage(RUSAGE_THREAD)`
/// reports, read from `/proc/thread-self/stat`; `None` where that cannot be read.
pub fn thread_page_faults() -> Option<(u64, u64)> {
    let stat = std::fs::read_to_string("/proc/thread-self/stat").ok()?;
    // The command name, in parentheses, may hold spaces and parentheses itself, so the fields are
    // read after its last `)`: the state (field 3), then `minflt` (10) and `majflt` (12).
    let mut fields = stat.rsplit_once(')')?.1.split_whitespace();
    let minor = fields.nth(7)?.parse().ok()?;
    let major = fields.nth(1)?.parse().ok()?;
    Some((minor, major))
}

thread_local! {
    /// This thread's record-slot takes that had to wait, and their time, since the last
    /// [`take_record_slot_waits`].
    static RECORD_SLOT_WAITS: Cell<(u64, Duration)> = const { Cell::new((0, Duration::ZERO)) };
}

/// `wait`, the wait of a record-slot take that found no slot free or had to wait for its turn,
/// counted and timed for the work it holds up.
pub fn record_slot_wait<T>(wait: impl FnOnce() -> T) -> T {
    let t0 = Instant::now();
    let item = wait();
    let waited = t0.elapsed();
    RECORD_SLOT_WAITS.with(|waits| {
        let (count, total) = waits.get();
        waits.set((count + 1, total + waited));
    });
    item
}

/// The record-slot takes that waited on this thread since the last call, and their time in all.
pub fn take_record_slot_waits() -> (u64, Duration) {
    RECORD_SLOT_WAITS.with(|waits| waits.replace((0, Duration::ZERO)))
}

fn proc_status_field(name: &str) -> Option<String> {
    let text = std::fs::read_to_string("/proc/self/status").ok()?;
    text.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key == name).then(|| value.trim().to_string())
    })
}

/// The close line's peak RSS fields, in KiB, each absent where VmHWM could not be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Peaks {
    /// The whole run's: `peak_rss_kib`, as a run with no reset reads it.
    whole_run_kib: Option<u64>,
    /// When the emulation ended, before the reset.
    emulation_kib: Option<u64>,
    /// At the close, since the reset; absent if the reset failed, when it would hold the
    /// emulation's peak too.
    tracegen_kib: Option<u64>,
}

impl Peaks {
    /// From VmHWM when the emulation ended, whether it was then reset, and VmHWM at the close.
    fn read(at_emulation: Option<u64>, reset: bool, at_close: Option<u64>) -> Self {
        Self {
            // Without a reset the close reading is already the larger.
            whole_run_kib: at_close.map(|close| at_emulation.map_or(close, |at| at.max(close))),
            emulation_kib: at_emulation,
            tracegen_kib: at_close.filter(|_| reset),
        }
    }
}

/// The process's peak RSS since it started or since the last [`reset_vmhwm`].
fn vmhwm_kib() -> Option<u64> {
    proc_status_field("VmHWM").and_then(|v| v.trim_end_matches("kB").trim().parse().ok())
}

/// Resets VmHWM to the current RSS: `5` into `clear_refs`, Linux 4.0 and later. False when the
/// kernel refused it, and then no later VmHWM read may stand for the peak since now.
fn reset_vmhwm() -> bool {
    OpenOptions::new()
        .write(true)
        .open("/proc/self/clear_refs")
        .and_then(|mut file| file.write_all(b"5"))
        .is_ok()
}

fn representation() -> &'static str {
    "history"
}

/// Told by the launcher, which is the only party that can know: `MLE_LEDGER_LOCK_HELD=1` from a
/// launcher that checked the host lock reads as its own before starting the run, or
/// `GPUBENCH_LOCK_HELD_BY` where the lock wrapper runs in the same process tree. A claim, not a
/// check: it says the lock was held when the run started.
fn lock_held() -> bool {
    std::env::var("MLE_LEDGER_LOCK_HELD").is_ok_and(|v| v == "1")
        || std::env::var_os("GPUBENCH_LOCK_HELD_BY").is_some()
}

fn host() -> Value {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|h| h.trim().to_string())
        .or_else(|| std::env::var("HOSTNAME").ok())
        .or_else(|| command_output("hostname", &[]))
        .map_or(Value::Null, Value::String)
}

/// Branch, commit and whether the tree was dirty. A copy synced by `rsync` has no git,
/// so the launcher's `MLE_LEDGER_BRANCH` / `MLE_LEDGER_COMMIT` / `MLE_LEDGER_DIRTY` come first.
fn provenance() -> (Value, Value, Value) {
    let env = |name: &str| std::env::var(name).ok().filter(|v| !v.is_empty());
    let branch = env("MLE_LEDGER_BRANCH")
        .or_else(|| command_output("git", &["rev-parse", "--abbrev-ref", "HEAD"]));
    let commit = env("MLE_LEDGER_COMMIT")
        .or_else(|| command_output("git", &["rev-parse", "--short=9", "HEAD"]));
    let dirty = match env("MLE_LEDGER_DIRTY") {
        Some(v) => Some(v == "1" || v == "true"),
        None => command_output("git", &["status", "--porcelain", "--untracked-files=no"])
            .map(|s| !s.is_empty()),
    };
    (
        branch.map_or(Value::Null, Value::String),
        commit.map_or(Value::Null, Value::String),
        dirty.map_or(Value::Null, Value::Bool),
    )
}

fn command_output(program: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(program)
        .args(args)
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn file_id(id: Option<&FileId>) -> Value {
    id.map_or(Value::Null, |f| json!({"path": f.path, "sha256": f.sha256}))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A job nested in another's wait is taken out of the outer stage once, its own nesting
    /// included: the outer stage loses no more than the nested job's wall, and the nested job's
    /// stage loses what nested in it.
    #[test]
    fn a_nested_prove_job_is_taken_out_of_the_stage_it_interrupted() {
        let slot = |record| ProveSlot {
            record,
            chunk: Some(record),
            slot: 0,
        };
        let (outer, inner, middle_wall_us) = with_prove_slot(slot(0), || {
            let outer = ProveMark::now();
            let t_middle = Instant::now();
            let inner = with_prove_slot(slot(1), || {
                let inner = ProveMark::now();
                with_prove_slot(slot(2), || std::thread::sleep(Duration::from_millis(5)));
                NESTED_US.with(Cell::get) - inner.nested_us
            });
            let middle_wall_us = t_middle.elapsed().as_micros() as u64;
            (
                NESTED_US.with(Cell::get) - outer.nested_us,
                inner,
                middle_wall_us,
            )
        });
        assert!(
            inner >= 5_000,
            "the innermost job was not taken out: {inner}"
        );
        assert!(
            inner <= outer && outer <= middle_wall_us,
            "nested {outer} us out of a {middle_wall_us} us job holding {inner} us"
        );
        assert!(current_prove_slot().is_none());
    }

    /// `peak_rss_kib` keeps the meaning it has in a run that never resets: the whole run's peak,
    /// which after a reset is the larger of the two readings, whichever half it fell in.
    #[test]
    fn the_whole_run_peak_is_the_larger_reading() {
        for (emulation, close) in [(100, 60), (100, 150), (100, 100)] {
            let peaks = Peaks::read(Some(emulation), true, Some(close));
            assert_eq!(peaks.emulation_kib, Some(emulation));
            assert_eq!(peaks.tracegen_kib, Some(close));
            assert_eq!(peaks.whole_run_kib, Some(emulation.max(close)));
        }
        assert_eq!(
            Peaks::read(Some(100), false, Some(120)),
            Peaks {
                whole_run_kib: Some(120),
                emulation_kib: Some(100),
                tracegen_kib: None,
            },
            "a failed reset leaves no trace generation reading"
        );
        assert_eq!(
            Peaks::read(None, false, None),
            Peaks {
                whole_run_kib: None,
                emulation_kib: None,
                tracegen_kib: None,
            },
            "where VmHWM cannot be read, nothing is filled in"
        );
    }

    #[test]
    fn the_representation_names_the_history() {
        assert_eq!(representation(), "history");
    }

    /// Absent rather than zero off Linux, and on Linux a reset that leaves the peak where it was
    /// would report the emulation's peak as trace generation's.
    #[test]
    fn a_vmhwm_reset_brings_the_peak_down_to_the_current_rss() {
        const BYTES: usize = 256 << 20;
        drop(std::hint::black_box(vec![1u8; BYTES]));
        let before = vmhwm_kib();
        let reset = reset_vmhwm();
        let after = vmhwm_kib();
        if !cfg!(target_os = "linux") {
            assert_eq!((before, reset, after), (None, false, None));
            return;
        }
        let (before, after) = (before.expect("VmHWM"), after.expect("VmHWM"));
        assert!(reset, "the kernel refused the VmHWM reset");
        assert!(
            after + (BYTES >> 11) as u64 <= before,
            "VmHWM {before} KiB before the reset and {after} KiB after it"
        );
    }

    /// Absent rather than zero off Linux; on Linux the minor count moves when the thread touches
    /// fresh pages, which a misread field would not.
    #[test]
    fn a_thread_reads_its_own_page_faults() {
        let before = thread_page_faults();
        if !cfg!(target_os = "linux") {
            assert_eq!(before, None);
            return;
        }
        let (minor, _) = before.expect("/proc/thread-self/stat");
        drop(std::hint::black_box(vec![1u8; 64 << 20]));
        let (minor_after, _) = thread_page_faults().expect("/proc/thread-self/stat");
        assert!(
            minor_after > minor,
            "minor faults {minor} before touching 64 MiB and {minor_after} after"
        );
    }

    /// The arena calls the hook only for a take that waits; each call is one wait, and taking the
    /// counts starts them again.
    #[test]
    fn each_slot_wait_is_counted_and_timed() {
        take_record_slot_waits();
        assert_eq!(record_slot_wait(|| 1u8), 1);
        record_slot_wait(|| std::thread::sleep(Duration::from_millis(100)));
        let (count, waited) = take_record_slot_waits();
        assert_eq!(count, 2);
        assert!(waited >= Duration::from_millis(50), "waited {waited:?}");
        assert_eq!(take_record_slot_waits(), (0, Duration::ZERO));
    }

    #[test]
    fn a_window_over_a_run_in_flight_is_an_overlap() {
        assert!(
            !opens_over_a_run(false, 0, false),
            "a run after the last one ended"
        );
        assert!(opens_over_a_run(true, 0, false), "a run still emulating");
        assert!(opens_over_a_run(false, 2, false), "a riscv prove in flight");
        assert!(
            opens_over_a_run(false, 0, true),
            "a run in its recursion or between prove batches"
        );
    }
}
