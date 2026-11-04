//! The device readings with the `stage-ledger` feature on. A chunk's readings live in a
//! thread-local from [`begin`] to [`Session::finish`]: the orchestrator and every chip wrapper run
//! on the chunk's thread, so the hooks they call need no handle.

use std::{
    cell::RefCell, collections::BTreeMap, ffi::c_void, mem::MaybeUninit, panic::Location,
    sync::OnceLock, time::Instant,
};

use cudart::{
    device::{device_get_attribute, get_device_count},
    event::{elapsed_time, CudaEvent},
    result::CudaResult,
    stream::CudaStream,
};
use cudart_sys::{
    cudaEventRecord, cudaEvent_t, cudaPointerGetAttributes, cudaStream_t, CudaDeviceAttr,
    CudaError, CudaMemoryType, CudaPointerAttributes,
};
use pico_gpu_api::step_events::StepEvents;
use serde_json::{json, Map, Value};

use super::{covered, uncovered, Readout, LARGE_COPY, OVERLAPPABLE_CHIPS, TARGET};

/// CUDA's `cudaStreamPerThread`, the prover thread's own stream, where the bridge transposes the
/// traces and uploads the host-generated ones.
const PER_THREAD_STREAM: usize = 0x2;

/// Stream roles inside one chip, in the order the chip first brackets work on each stream.
const CHIP_STREAMS: [&str; 4] = ["s1", "s2", "s3", "s4+"];

/// What a bracketed interval holds.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Copy,
    Kernel,
    Fill,
    /// A launcher's own step, inside the chip's kernel bracket and kept out of the facts that
    /// bracket feeds.
    Step,
    Transpose,
    FallbackUpload,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Copy => "copy",
            Kind::Kernel => "kernel",
            Kind::Fill => "fill",
            Kind::Step => "step",
            Kind::Transpose => "transpose",
            Kind::FallbackUpload => "fallback_upload",
        }
    }
}

struct Interval {
    kind: Kind,
    chip: Option<String>,
    stream: &'static str,
    /// What a copy carried, or which step of the chip a kernel or launcher step was.
    what: Option<&'static str>,
    /// For a copy, the bytes and whether they came from pageable memory, when the site knows them.
    source: Option<(usize, bool)>,
    start: CudaEvent,
    end: CudaEvent,
}

struct Readings {
    chunk: u64,
    cpu: bool,
    device: usize,
    t0: Instant,
    /// The chunk's first event; every elapsed time is read against it.
    origin: Option<CudaEvent>,
    /// The chip the orchestrator is running, which a bracket is charged to.
    chip: Option<String>,
    /// The orchestrator's own stream, by handle.
    orchestrator: Option<usize>,
    /// The streams the current chip has bracketed work on, by handle, in first-use order.
    chip_streams: Vec<usize>,
    waits: u64,
    wait_us: u64,
    final_wait_us: Option<u64>,
    intervals: Vec<Interval>,
}

impl Readings {
    fn stream_role(&mut self, handle: usize) -> &'static str {
        if handle == PER_THREAD_STREAM {
            return "prover";
        }
        if Some(handle) == self.orchestrator {
            return "orchestrator";
        }
        let index = match self.chip_streams.iter().position(|&h| h == handle) {
            Some(index) => index,
            None => {
                self.chip_streams.push(handle);
                self.chip_streams.len() - 1
            }
        };
        CHIP_STREAMS[index.min(CHIP_STREAMS.len() - 1)]
    }
}

thread_local! {
    static CHUNK: RefCell<Option<Readings>> = const { RefCell::new(None) };
}

fn with_readings<R>(f: impl FnOnce(&mut Readings) -> R) -> Option<R> {
    CHUNK.with(|chunk| chunk.borrow_mut().as_mut().map(f))
}

fn recording() -> bool {
    CHUNK.with(|chunk| chunk.borrow().is_some())
}

/// One chunk's readings on the calling thread. Dropping it puts back whatever the thread was
/// recording before, on unwind too: rayon can run another record's prove job on a thread whose own
/// job waits inside the prover.
#[must_use = "the chunk's readings stop when the session drops"]
pub struct Session {
    prev: Option<Readings>,
    records: bool,
}

impl Drop for Session {
    fn drop(&mut self) {
        let prev = self.prev.take();
        CHUNK.with(|chunk| *chunk.borrow_mut() = prev);
    }
}

/// Whether the readings are switched on: [`TARGET`] enabled at debug level.
pub fn switched_on() -> bool {
    tracing::enabled!(target: TARGET, tracing::Level::DEBUG)
}

/// Start chunk `chunk`'s readings on the calling thread, if the switch is on. `cpu` and `device`
/// are for the summary line.
pub fn begin(chunk: u64, cpu: bool, device: usize) -> Session {
    let readings = switched_on().then(|| Readings {
        chunk,
        cpu,
        device,
        t0: Instant::now(),
        origin: None,
        chip: None,
        orchestrator: None,
        chip_streams: Vec::new(),
        waits: 0,
        wait_us: 0,
        final_wait_us: None,
        intervals: Vec::new(),
    });
    let records = readings.is_some();
    Session {
        prev: CHUNK.with(|c| c.replace(readings)),
        records,
    }
}

impl Session {
    /// Whether the chunk's readings are on, for a site that gathers something only for them.
    pub fn records(&self) -> bool {
        self.records
    }

    /// Read the chunk's events, log its summary and its brackets and return both, or `None` when
    /// it recorded nothing. Called after the chunk's last synchronisation, so reading waits on
    /// nothing.
    pub fn finish(self) -> Option<Readout> {
        let readings = CHUNK.with(|chunk| chunk.borrow_mut().take())?;
        let (chunk, cpu, device) = (readings.chunk, readings.cpu, readings.device);
        let wall_us = readings.t0.elapsed().as_micros();
        let (facts, brackets) = readings.summarise();
        let line = |facts: &Map<String, Value>| {
            facts
                .iter()
                .map(|(key, value)| format!("{key}={value}"))
                .collect::<Vec<_>>()
                .join(" ")
        };
        tracing::info!(
            target: TARGET,
            "[gpu-tracegen] chunk={chunk} cpu={cpu} device={device} wall_us={wall_us} {}",
            line(&facts)
        );
        tracing::info!(
            target: TARGET,
            "[gpu-tracegen-brackets] chunk={chunk} cpu={cpu} device={device} wall_us={wall_us} {}",
            line(&brackets)
        );
        Some(Readout {
            device: Value::Object(facts),
            brackets: Value::Object(brackets),
        })
    }
}

/// `event`'s time in microseconds after `origin`; `None` while either is pending, since
/// `cudaEventElapsedTime` reports not-ready rather than waiting.
fn since(origin: &CudaEvent, event: &CudaEvent) -> Option<f64> {
    elapsed_time(origin, event)
        .ok()
        .map(|ms| f64::from(ms) * 1e3)
}

impl Readings {
    /// The context build's facts and the trace generator's brackets.
    fn summarise(self) -> (Map<String, Value>, Map<String, Value>) {
        let Readings {
            chunk,
            device,
            origin,
            waits,
            wait_us,
            final_wait_us,
            intervals,
            ..
        } = self;
        let mut unread = 0usize;
        let mut read: Vec<(&Interval, (f64, f64))> = Vec::with_capacity(intervals.len());
        for interval in &intervals {
            let pair = origin.as_ref().and_then(|origin| {
                Some((
                    since(origin, &interval.start)?,
                    since(origin, &interval.end)?,
                ))
            });
            match pair {
                Some(pair) => {
                    tracing::debug!(
                        target: TARGET,
                        "[device-interval] chunk={chunk} kind={} chip={} what={} stream={} \
                         t0_us={:.1} t1_us={:.1}",
                        interval.kind.as_str(),
                        interval.chip.as_deref().unwrap_or("-"),
                        interval.what.unwrap_or("-"),
                        interval.stream,
                        pair.0,
                        pair.1
                    );
                    read.push((interval, pair));
                }
                None => unread += 1,
            }
        }
        let of_kind = |kind: Kind| -> Vec<(f64, f64)> {
            read.iter()
                .filter(|(interval, _)| interval.kind == kind)
                .map(|(_, pair)| *pair)
                .collect()
        };
        let per_chip = |kind: Kind| {
            let mut chips: BTreeMap<&str, Vec<(f64, f64)>> = BTreeMap::new();
            for (interval, pair) in read.iter().filter(|(interval, _)| interval.kind == kind) {
                chips
                    .entry(interval.chip.as_deref().unwrap_or("-"))
                    .or_default()
                    .push(*pair);
            }
            chips
        };
        let copies = of_kind(Kind::Copy);
        let others: Vec<(f64, f64)> = read
            .iter()
            .filter(|(interval, _)| !matches!(interval.kind, Kind::Copy | Kind::Step))
            .map(|(_, pair)| *pair)
            .collect();
        let all: Vec<(f64, f64)> = read
            .iter()
            .filter(|(interval, _)| interval.kind != Kind::Step)
            .map(|(_, pair)| *pair)
            .collect();
        let span = all.iter().map(|(_, end)| *end).fold(0.0, f64::max);
        let busy = covered(&all);
        let kernels = per_chip(Kind::Kernel);
        let overlappable: Vec<(f64, f64)> = OVERLAPPABLE_CHIPS
            .iter()
            .filter_map(|chip| kernels.get(chip))
            .flatten()
            .copied()
            .collect();

        let sized: Vec<(usize, bool)> = intervals.iter().filter_map(|i| i.source).collect();
        let large = || sized.iter().filter(|(bytes, _)| *bytes > LARGE_COPY);
        let us = |t: f64| t.round() as u64;
        let mut facts = Map::new();
        facts.insert("host_waits".into(), json!(waits));
        facts.insert("host_wait_us".into(), json!(wait_us));
        facts.insert("host_wait_final_us".into(), json!(final_wait_us));
        facts.insert("device.span_us".into(), json!(us(span)));
        facts.insert("device.busy_us".into(), json!(us(busy)));
        facts.insert("device.idle_us".into(), json!(us((span - busy).max(0.0))));
        facts.insert(
            "device.transpose_us".into(),
            json!(us(covered(&of_kind(Kind::Transpose)))),
        );
        facts.insert(
            "device.fallback_upload_us".into(),
            json!(us(covered(&of_kind(Kind::FallbackUpload)))),
        );
        facts.insert("h2d.copies".into(), json!(copies.len()));
        facts.insert(
            "h2d.copy_us".into(),
            json!(us(copies.iter().map(|(a, b)| b - a).sum())),
        );
        facts.insert("h2d.copy_union_us".into(), json!(us(covered(&copies))));
        facts.insert(
            "h2d.exposed_us".into(),
            json!(us(uncovered(&copies, &others))),
        );
        facts.insert("h2d.sized_copies".into(), json!(sized.len()));
        facts.insert(
            "h2d.bytes".into(),
            json!(sized.iter().map(|(bytes, _)| bytes).sum::<usize>()),
        );
        facts.insert("h2d.copies_over_64k".into(), json!(large().count()));
        facts.insert(
            "h2d.pageable_copies_over_64k".into(),
            json!(large().filter(|(_, pageable)| *pageable).count()),
        );
        for (chip, pairs) in &kernels {
            facts.insert(format!("kernel.{chip}.us"), json!(us(covered(pairs))));
        }
        for (chip, pairs) in &per_chip(Kind::Fill) {
            facts.insert(format!("fill.{chip}.us"), json!(us(covered(pairs))));
        }
        facts.insert(
            "kernel.global_poseidon2_local_memory.us".into(),
            json!(us(covered(&overlappable))),
        );
        facts.insert("device.async_engines".into(), json!(async_engines(device)));
        facts.insert("events_unread".into(), json!(unread));
        let named: Vec<Named<'_>> = read
            .iter()
            .map(|(interval, pair)| interval.named(*pair))
            .collect();
        (facts, brackets(&named, span, unread))
    }
}

/// A read interval as the brackets see it: its kind, chip, name, and start and end.
type Named<'a> = (Kind, Option<&'a str>, Option<&'static str>, (f64, f64));

impl Interval {
    fn named(&self, pair: (f64, f64)) -> Named<'_> {
        (self.kind, self.chip.as_deref(), self.what, pair)
    }
}

/// The trace generator's brackets from a chunk's read intervals, as the module header lists them.
/// Each figure is a union, so work on two streams at once counts once within a figure; `sum_ms`
/// adds the chip, copy, bridge and unowned figures, the steps being inside their chips', and so
/// counts overlap across figures, which `union_ms`, the union of every bracket, does not.
fn brackets(read: &[Named<'_>], span: f64, unread: usize) -> Map<String, Value> {
    type Pairs = Vec<(f64, f64)>;
    let mut chips: BTreeMap<&str, Pairs> = BTreeMap::new();
    let mut launchers: BTreeMap<&str, Pairs> = BTreeMap::new();
    let mut per_step: BTreeMap<(&str, &str), Pairs> = BTreeMap::new();
    let mut copies: BTreeMap<&str, Pairs> = BTreeMap::new();
    let (mut transposes, mut uploads, mut other) = (Pairs::new(), Pairs::new(), Pairs::new());
    let mut all = Pairs::new();
    for &(kind, chip, what, pair) in read {
        if kind != Kind::Step {
            all.push(pair);
        }
        match (kind, chip) {
            (Kind::Copy, _) => copies.entry(what.unwrap_or("-")).or_default().push(pair),
            (Kind::Transpose, _) => transposes.push(pair),
            (Kind::FallbackUpload, _) => uploads.push(pair),
            (_, None) => other.push(pair),
            (_, Some(chip)) => {
                chips.entry(chip).or_default().push(pair);
                if let Some(step) = what {
                    per_step.entry((chip, step)).or_default().push(pair);
                }
                if kind == Kind::Step {
                    launchers.entry(chip).or_default().push(pair);
                }
            }
        }
    }
    // An empty union sums to -0.0, which would print as such.
    let ms = |us: f64| json!(if us > 0.0 { us.round() / 1e3 } else { 0.0 });
    let mut facts = Map::new();
    let mut sum = 0.0;
    for (chip, pairs) in &chips {
        let us = covered(pairs);
        sum += us;
        facts.insert(format!("chip.{chip}_ms"), ms(us));
    }
    for ((chip, step), pairs) in &per_step {
        facts.insert(format!("step.{chip}.{step}_ms"), ms(covered(pairs)));
    }
    // A launcher's time outside its steps: its allocations, its host round trips and the gaps
    // between its launches.
    for (chip, pairs) in &launchers {
        let whole = chips.get(chip).map_or(0.0, |all| covered(all));
        facts.insert(
            format!("step.{chip}.between_ms"),
            ms((whole - covered(pairs)).max(0.0)),
        );
    }
    for (what, pairs) in &copies {
        let us = covered(pairs);
        sum += us;
        facts.insert(format!("copy.{what}_ms"), ms(us));
    }
    for (name, pairs) in [
        ("bridge.transpose_ms", &transposes),
        ("bridge.upload_ms", &uploads),
        ("other_ms", &other),
    ] {
        let us = covered(pairs);
        sum += us;
        facts.insert(name.into(), ms(us));
    }
    facts.insert("sum_ms".into(), ms(sum));
    facts.insert("union_ms".into(), ms(covered(&all)));
    facts.insert("span_ms".into(), ms(span));
    facts.insert("events_unread".into(), json!(unread));
    facts
}

/// Synchronise `stream`. When the chunk records, the wait is timed, counted, and logged with its
/// call site.
#[track_caller]
pub fn wait(stream: &CudaStream) -> CudaResult<()> {
    wait_with(|| stream.synchronize())
}

/// [`wait`] for a blocking call that is not a `CudaStream`'s synchronisation, such as the
/// per-thread stream's or a copy into pageable memory. Times the call; adds no synchronisation.
///
/// No stream query tells a busy wait from an idle one: its not-ready status could reach the
/// `cudaGetLastError` check after the next kernel launch. An idle wait reads as a few microseconds.
#[track_caller]
pub fn wait_with<T>(sync: impl FnOnce() -> T) -> T {
    if !recording() {
        return sync();
    }
    let (out, us) = timed(sync);
    if let Some((chunk, cpu)) = with_readings(|r| {
        r.waits += 1;
        r.wait_us += us;
        (r.chunk, r.cpu)
    }) {
        log_wait(chunk, cpu, Location::caller(), us, "");
    }
    out
}

/// The bridge's last wait, which every later reading depends on: timed and reported on its own,
/// outside the wait count and sum, since removing the other waits leaves it in place.
#[track_caller]
pub fn final_wait_with<T>(sync: impl FnOnce() -> T) -> T {
    if !recording() {
        return sync();
    }
    let (out, us) = timed(sync);
    if let Some((chunk, cpu)) = with_readings(|r| {
        r.final_wait_us = Some(us);
        (r.chunk, r.cpu)
    }) {
        log_wait(chunk, cpu, Location::caller(), us, " final=true");
    }
    out
}

fn timed<T>(sync: impl FnOnce() -> T) -> (T, u64) {
    let t0 = Instant::now();
    let out = sync();
    (out, t0.elapsed().as_micros() as u64)
}

fn log_wait(chunk: u64, cpu: bool, site: &Location<'_>, us: u64, tag: &str) {
    tracing::debug!(
        target: TARGET,
        "[host-wait] chunk={chunk} cpu={cpu} site={}:{} us={us}{tag}",
        site.file(),
        site.line()
    );
}

/// The start of a copy or of device work on one stream: an event recorded there when the chunk
/// records.
#[must_use = "a bracket times nothing until it is closed"]
pub struct Bracket(Option<CudaEvent>);

impl Bracket {
    /// Whether the bracket times its work: the chunk records and its start was recorded.
    pub fn times(&self) -> bool {
        self.0.is_some()
    }
}

pub fn start(stream: &CudaStream) -> Bracket {
    open(stream_handle(stream))
}

/// [`start`] for a site that already holds a bracket of the chunk's and has read [`Bracket::times`]
/// from it: nothing is looked up when `timed` is false.
pub fn start_if(timed: bool, stream: &CudaStream) -> Bracket {
    if timed {
        start(stream)
    } else {
        Bracket(None)
    }
}

/// [`start`] on the prover thread's own stream.
pub fn start_on_thread() -> Bracket {
    open(PER_THREAD_STREAM)
}

fn open(handle: usize) -> Bracket {
    Bracket(
        with_readings(|r| {
            if r.origin.is_none() {
                r.origin = recorded(handle);
            }
            recorded(handle)
        })
        .flatten(),
    )
}

/// Close `bracket` after a host-to-device copy on `stream` of `what`, the name the brackets give
/// the kind of copy. `source` is the copy's source pointer and byte count, when the site has them.
pub fn copied(
    bracket: Bracket,
    stream: &CudaStream,
    what: &'static str,
    source: Option<(*const c_void, usize)>,
) {
    // The pageable flag costs a driver query, so a copy the bracket does not time, which is every
    // copy while the readings are off, never asks it.
    if !bracket.times() {
        return;
    }
    let source = source.map(|(ptr, bytes)| (bytes, pageable(ptr)));
    let handle = stream_handle(stream);
    close(bracket, handle, Kind::Copy, Some(what), source);
}

/// Close `bracket` after kernels launched on `stream`, charged to the chip being run.
pub fn launched(bracket: Bracket, stream: &CudaStream) {
    close(bracket, stream_handle(stream), Kind::Kernel, None, None);
}

/// [`launched`] for kernels that are one named step of the chip being run, which the brackets
/// report on its own as well.
pub fn launched_step(bracket: Bracket, stream: &CudaStream, step: &'static str) {
    let handle = stream_handle(stream);
    close(bracket, handle, Kind::Kernel, Some(step), None);
}

/// Close `bracket` after a wrapper's zero-fill of its trace on `stream`, charged to the chip being
/// run apart from its kernels.
pub fn filled(bracket: Bracket, stream: &CudaStream) {
    close(bracket, stream_handle(stream), Kind::Fill, None, None);
}

/// Close `bracket` after one trace's transpose on the prover thread's own stream.
pub fn transposed_on_thread(bracket: Bracket) {
    close(bracket, PER_THREAD_STREAM, Kind::Transpose, None, None);
}

/// Close `bracket` after a host-generated trace's upload on the prover thread's own stream.
pub fn uploaded_on_thread(bracket: Bracket) {
    close(bracket, PER_THREAD_STREAM, Kind::FallbackUpload, None, None);
}

fn close(
    bracket: Bracket,
    handle: usize,
    kind: Kind,
    what: Option<&'static str>,
    source: Option<(usize, bool)>,
) {
    let Bracket(Some(start)) = bracket else {
        return;
    };
    let Some(end) = recorded(handle) else {
        return;
    };
    with_readings(|r| {
        let stream = r.stream_role(handle);
        r.intervals.push(Interval {
            kind,
            chip: r.chip.clone(),
            stream,
            what,
            source,
            start,
            end,
        })
    });
}

/// The events a launcher records around its own steps, handed to it as its step-events argument;
/// none, and handed over as null, when the launch is not timed.
pub struct Steps(Option<StepRecording>);

struct StepRecording {
    names: &'static [&'static str],
    /// Two per step, its start and then its end.
    events: Vec<CudaEvent>,
    /// The events' handles, which `ffi.events` points at once the launcher is handed them.
    handles: Vec<cudaEvent_t>,
    ffi: StepEvents,
}

/// Events for a launcher whose steps are `names`, in the order of its step events, inside
/// `bracket`, the launch's own: created only when that bracket times the launch, two per step.
pub fn steps(bracket: &Bracket, names: &'static [&'static str]) -> Steps {
    if !bracket.times() {
        return Steps(None);
    }
    let wanted = 2 * names.len();
    let events: Vec<CudaEvent> = (0..wanted)
        .map_while(|_| CudaEvent::create().ok())
        .collect();
    if events.len() < wanted {
        return Steps(None);
    }
    let handles = events.iter().map(Into::into).collect();
    Steps(Some(StepRecording {
        names,
        events,
        handles,
        ffi: StepEvents {
            events: std::ptr::null(),
            steps: names.len(),
            started: 0,
            recorded: 0,
        },
    }))
}

impl Steps {
    /// The launcher's step-events argument, null when the launch is not timed.
    pub fn ffi(&mut self) -> *mut StepEvents {
        match &mut self.0 {
            Some(recording) => {
                recording.ffi.events = recording.handles.as_ptr();
                &mut recording.ffi
            }
            None => std::ptr::null_mut(),
        }
    }
}

/// Take the steps the launcher recorded on `stream`, charged to the chip being run. A step it did
/// not record, skipped or failed, is left out rather than read as unread.
pub fn stepped(steps: Steps, stream: &CudaStream) {
    let Steps(Some(StepRecording {
        names, events, ffi, ..
    })) = steps
    else {
        return;
    };
    let handle = stream_handle(stream);
    let mut events = events.into_iter();
    with_readings(|r| {
        let role = r.stream_role(handle);
        for (step, &name) in names.iter().enumerate() {
            let (Some(start), Some(end)) = (events.next(), events.next()) else {
                break;
            };
            if ffi.recorded & (1 << step) != 0 {
                r.intervals.push(Interval {
                    kind: Kind::Step,
                    chip: r.chip.clone(),
                    stream: role,
                    what: Some(name),
                    source: None,
                    start,
                    end,
                });
            }
        }
    });
}

/// Charge the brackets from here to the chip `name` gives, named only when the chunk records.
pub fn set_chip(name: impl FnOnce() -> String) {
    with_readings(|r| {
        r.chip = Some(name());
        r.chip_streams.clear();
    });
}

pub fn clear_chip() {
    with_readings(|r| {
        r.chip = None;
        r.chip_streams.clear();
    });
}

/// Name `stream` as the orchestrator's own, so its brackets carry that role.
pub fn orchestrator_stream(stream: &CudaStream) {
    with_readings(|r| r.orchestrator = Some(stream_handle(stream)));
}

fn stream_handle(stream: &CudaStream) -> usize {
    cudaStream_t::from(stream) as usize
}

fn recorded(handle: usize) -> Option<CudaEvent> {
    let event = CudaEvent::create().ok()?;
    // SAFETY: the event is live, and the handle is a live stream's or `cudaStreamPerThread`.
    let status = unsafe { cudaEventRecord((&event).into(), handle as cudaStream_t) };
    (status == CudaError::Success).then_some(event)
}

fn pageable(ptr: *const c_void) -> bool {
    let mut attributes = MaybeUninit::<CudaPointerAttributes>::uninit();
    // SAFETY: the call only writes `attributes`, which is read only when it reports success.
    unsafe {
        cudaPointerGetAttributes(attributes.as_mut_ptr(), ptr as *mut c_void) == CudaError::Success
            && attributes.assume_init().type_ == CudaMemoryType::Unregistered
    }
}

/// Copy engines the card has, read once per process for every visible card.
fn async_engines(device: usize) -> Option<i32> {
    static ENGINES: OnceLock<Vec<Option<i32>>> = OnceLock::new();
    ENGINES
        .get_or_init(|| {
            (0..get_device_count().unwrap_or(0))
                .map(|id| device_get_attribute(CudaDeviceAttr::AsyncEngineCount, id).ok())
                .collect()
        })
        .get(device)
        .copied()
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Each figure is the union of its own intervals; a launcher's steps are inside its chip's
    /// figure and out of the sum, and only a chip with launcher steps has time between them.
    #[test]
    fn the_brackets_name_each_chip_step_and_copy() {
        let read: [Named<'_>; 10] = [
            (Kind::Kernel, Some("Global"), None, (0.0, 1000.0)),
            (Kind::Step, Some("Global"), Some("memset"), (0.0, 100.0)),
            (Kind::Step, Some("Global"), Some("convert"), (200.0, 600.0)),
            (Kind::Kernel, Some("Cpu"), None, (500.0, 2500.0)),
            (Kind::Kernel, Some("Cpu"), None, (1500.0, 3000.0)),
            (Kind::Copy, None, Some("cpu_slices"), (0.0, 800.0)),
            (Kind::Copy, None, Some("cpu_slices"), (400.0, 1200.0)),
            (Kind::Kernel, Some("Byte"), Some("init"), (3000.0, 3100.0)),
            (Kind::Fill, None, None, (0.0, 4.0)),
            (Kind::Transpose, None, None, (3100.0, 3600.0)),
        ];
        let facts = brackets(&read, 3600.0, 0);
        assert_eq!(facts["chip.Global_ms"], json!(1.0));
        assert_eq!(facts["step.Global.memset_ms"], json!(0.1));
        assert_eq!(facts["step.Global.convert_ms"], json!(0.4));
        assert_eq!(facts["step.Global.between_ms"], json!(0.5));
        assert_eq!(facts["chip.Cpu_ms"], json!(2.5));
        assert_eq!(facts["copy.cpu_slices_ms"], json!(1.2));
        assert_eq!(facts["chip.Byte_ms"], json!(0.1));
        assert_eq!(facts["step.Byte.init_ms"], json!(0.1));
        assert!(!facts.contains_key("step.Byte.between_ms"));
        assert_eq!(facts["other_ms"], json!(0.004));
        assert_eq!(facts["bridge.transpose_ms"], json!(0.5));
        assert_eq!(facts["bridge.upload_ms"], json!(0.0));
        assert!(facts["bridge.upload_ms"]
            .as_f64()
            .is_some_and(f64::is_sign_positive));
        assert_eq!(facts["sum_ms"], json!(5.304));
        assert_eq!(facts["union_ms"], json!(3.6));
        assert_eq!(facts["span_ms"], json!(3.6));
        assert_eq!(facts["events_unread"], json!(0));
    }
}
