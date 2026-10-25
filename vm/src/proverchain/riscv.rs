//! Snapshot-based RISC-V emulation pipeline: a sequencer takes emulator snapshots, worker threads
//! replay them into `EmulationRecord`s, and the caller consumes the records through a callback.
//! The FRI `RiscvProver` that used to drive proving from here was removed with the FRI path (tag
//! `legacy-fri-last`); the MLE prover (`mle::machine::riscv`) consumes this pipeline instead, and
//! `mle::machine::riscv::emulate_with_pipeline` maps a run of it onto the `EmulationOutput` that
//! `emulate_with_opts` returns, so the host prover can take its records.

#[cfg(feature = "aot-emulator")]
use crate::emulator::emulator::AotMetaEmulator;
use crate::emulator::{opts::SnapshotMainMode, riscv::record_merge::merge_segments};
use crate::{
    compiler::riscv::program::Program,
    configs::config::{StarkGenericConfig, Val},
    emulator::{
        emulator::MetaEmulator,
        riscv::{
            cpu_event_pool::{init_cpu_event_buffer_pool, is_pool_initialized},
            emulator::{EmulationDeferredState, EmulationError, SharedDeferredState},
            memory::{
                init_memory_pool, memory_pool_capacity, memory_recycler_threads,
                raise_pool_size_floor, ContiguousRiscvMemory, GLOBAL_MEMORY_RECYCLER,
            },
            public_values::RecordFinalPvsState,
            record::EmulationRecord,
            riscv_emulator::{ParOptions, RiscvEmulator, RiscvEmulatorMode},
            state::RiscvEmulationState,
        },
    },
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::{
        chip::ChipBehavior, field::FieldSpecificPoseidon2Config, report::EmulationReport,
        witness::ProvingWitness,
    },
    // Lane recording for the MLE figures. Inert unless a driver called `spans::set_origin`, which only
    // the MLE driver does: with no origin every `open` returns a guard that records nothing.
    mle::spans::{self, LaneId, Role, WorkKind},
};
use alloc::sync::Arc;
use core_affinity;
use crossbeam::channel::{bounded, unbounded, Receiver, Sender};
use cudart::memory::CudaHostAllocFlags;
use p3_field::PrimeField32;
use parking_lot::Mutex as ParkingMutex;
use std::{
    any::Any,
    collections::{BTreeMap, HashMap},
    num::NonZeroUsize,
    panic::{self, AssertUnwindSafe},
    sync::{
        atomic::{AtomicBool, Ordering},
        Mutex, PoisonError,
    },
    thread,
    time::Instant,
};
use tracing::{debug, info};

/// Failures only a test can arrange. Process-wide, so only the child process a test spawns sets
/// them.
#[cfg(test)]
mod hooks {
    use std::sync::atomic::AtomicBool;

    /// The next replay panics.
    pub(super) static PANIC_IN_FIRST_REPLAY: AtomicBool = AtomicBool::new(false);

    /// The next replay returns an error.
    pub(super) static ERROR_IN_FIRST_REPLAY: AtomicBool = AtomicBool::new(false);

    /// The snapshot thread takes one pool block per batch and drops it. The AOT snapshot thread
    /// hands each batch's block to the worker, so a dead worker drains the pool; the interpreter
    /// returns its own, and without this it cannot show that hang.
    pub(super) static DRAW_POOL_BLOCK_PER_BATCH: AtomicBool = AtomicBool::new(false);
}

pub type RiscvChips<SC> = RiscvChipType<Val<SC>>;

pub enum Msg {
    Record {
        chunk: u32,
        rec: Arc<EmulationRecord>,
        done: bool,
    },
    SnapShotDone {
        chunk: u32,
    },
}

pub struct Bucket {
    pub(crate) recs: Vec<(Arc<EmulationRecord>, bool)>,
    pub(crate) finished: bool,
}

/// Which segment of which chunk a message carries.
///
/// Three bare `usize` in a row transpose in silence, and all three decide what the receiver does
/// with the record: which chunk it belongs to, whether it may close that chunk, and how many
/// siblings the fold is waiting for.
#[derive(Clone, Copy, Debug)]
struct SegmentId {
    batch: usize,
    index: usize,
    count: usize,
}

impl SegmentId {
    /// Whether this segment reaches the chunk's own boundary. Only that one may close the chunk.
    fn is_final(self) -> bool {
        self.index + 1 == self.count
    }

    /// Whether the chunk's replay was split at all.
    fn is_split(self) -> bool {
        self.count > 1
    }
}

/// Send one record on, logging its digests first when the equivalence gate is armed.
fn emit_record(
    tx: &crossbeam::channel::Sender<Msg>,
    batch_idx: usize,
    record: EmulationRecord,
    done: bool,
) {
    if *RECORD_DIGEST {
        for (field, len, hash) in crate::emulator::riscv::record_digest::field_digests(&record) {
            // Say which rows are allowed to differ, or whoever diffs two runs chases one that is.
            let compared = crate::emulator::riscv::record_digest::is_compared(field);
            let note = if compared { "" } else { " reported-only" };
            info!(
                target: "bench",
                "[recdigest] chunk={batch_idx} {field} len={len} hash={hash:#018x}{note}"
            );
        }
    }
    tx.send(Msg::Record {
        chunk: batch_idx as u32,
        rec: Arc::new(record),
        done,
    })
    .unwrap();
}

/// Holds a chunk's segment records until every segment is in, then folds them into one.
///
/// Only the chunk's own record is held: the deferred and precompile records a segment splits out
/// stand on their own and go straight through.
#[derive(Default)]
struct SegmentCollector {
    pending: ParkingMutex<HashMap<usize, PendingChunk>>,
}

#[derive(Default)]
struct PendingChunk {
    records: Vec<Option<EmulationRecord>>,
    seen: Vec<bool>,
    arrived: usize,
}

impl SegmentCollector {
    /// Drops every segment still waiting for its siblings.
    fn clear(&self) {
        self.pending.lock().clear();
    }

    /// Hand in one segment. `Some` once the whole chunk is in — the folded record, or `None`
    /// inside it if no segment produced a chunk record at all.
    fn submit(
        &self,
        segment: SegmentId,
        record: Option<EmulationRecord>,
    ) -> Option<Option<EmulationRecord>> {
        let complete = {
            // `parking_lot`, so a panic below does not poison the lock and bury its own message
            // under every peer's "poisoned".
            let mut pending = self.pending.lock();
            let chunk = pending
                .entry(segment.batch)
                .or_insert_with(|| PendingChunk {
                    records: (0..segment.count).map(|_| None).collect(),
                    seen: vec![false; segment.count],
                    arrived: 0,
                });
            // Before the index below, or a chunk announced the second time with a bigger count
            // panics out of bounds instead of saying what went wrong.
            assert_eq!(
                chunk.records.len(),
                segment.count,
                "chunk {} was announced with {} segments and then with {}",
                segment.batch,
                chunk.records.len(),
                segment.count
            );
            // Counting hand-ins rather than records, so a segment that produced none cannot hang
            // the chunk — which makes a repeat hand-in close the chunk one short, silently.
            assert!(
                !chunk.seen[segment.index],
                "segment {} of chunk {} was handed in twice",
                segment.index, segment.batch
            );
            chunk.seen[segment.index] = true;
            chunk.records[segment.index] = record;
            chunk.arrived += 1;
            if chunk.arrived < segment.count {
                return None;
            }
            pending
                .remove(&segment.batch)
                .expect("just counted it complete")
        };
        // The fold concatenates a whole chunk's event vectors, so it runs outside the lock: a
        // peer handing in a segment of another chunk has no reason to wait behind it.
        let ordered: Vec<EmulationRecord> = complete.records.into_iter().flatten().collect();
        Some((!ordered.is_empty()).then(|| merge_segments(ordered)))
    }
}

/// `MLE_RECORD_DIGEST=1` logs a per-field digest of every replayed record, so two runs can be
/// diffed. Read once: a schedule that changed mid-run would make the diff meaningless.
static RECORD_DIGEST: std::sync::LazyLock<bool> =
    std::sync::LazyLock::new(|| std::env::var("MLE_RECORD_DIGEST").is_ok_and(|v| v == "1"));

#[derive(Clone, Copy, Debug)]
pub enum TraceKind {
    Full,
    Light,
}

/// One replay snapshot as the snapshot thread queues it: which segment, the state to start from,
/// the run's `done` flag and the global clock to stop at.
type Snapshot = (SegmentId, RiscvEmulationState, bool, u64);

/// Gives a snapshot's memory back to where it came from. On the AOT path every snapshot memory is
/// a block of the bounded pool, and only this returns it, so a block dropped instead is one the
/// pool never sees again. The interpreter's snapshot memories are its own allocations, which a
/// full pool has no room for: sent there, each one would wait in the recycler queue for good.
fn release(memory: ContiguousRiscvMemory, pooled: bool) {
    if pooled {
        let _ = GLOBAL_MEMORY_RECYCLER.send((memory, true));
    }
}

/// What the pipeline's threads share about how the run is going. The first failure in any of them
/// stops the rest: the snapshot thread takes no further batch, the workers hand queued snapshots
/// straight back, and the sequencer passes no more records on.
#[derive(Default)]
struct RunControl {
    aborted: AtomicBool,
    /// The first panic caught. No thread panics because another stopped, so this one is the cause.
    panic: Mutex<Option<Box<dyn Any + Send>>>,
    /// The first error a replay returned.
    replay_error: Mutex<Option<EmulationError>>,
}

impl RunControl {
    fn abort(&self) {
        self.aborted.store(true, Ordering::Release);
    }

    fn is_aborted(&self) -> bool {
        self.aborted.load(Ordering::Acquire)
    }

    /// Runs `f`, and stops the run if it panics. Caught rather than left to the scope, which
    /// reports every thread's panic with a payload of its own and so loses the message.
    fn guard(&self, f: impl FnOnce()) {
        if let Err(payload) = panic::catch_unwind(AssertUnwindSafe(f)) {
            self.abort();
            self.panic
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get_or_insert(payload);
        }
    }

    fn replay_failed(&self, error: EmulationError) {
        self.abort();
        self.replay_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get_or_insert(error);
    }
}

type WorkerEmulator<SC, C> = MetaEmulator<SC, C, Program, Vec<u8>, RiscvEmulator>;

/// A worker's emulator for the length of one replay, whose memory is released if the replay does
/// not hand it back. If a replay unwound with a pool block, a snapshot thread waiting on the pool
/// for it would never wake.
struct Replay<'a, SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>,
{
    emu: Option<WorkerEmulator<SC, C>>,
    run: &'a RunControl,
    pooled: bool,
}

impl<SC, C> Replay<'_, SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>,
{
    fn emu(&mut self) -> &mut WorkerEmulator<SC, C> {
        self.emu.as_mut().expect("held until the replay ends")
    }

    /// The emulator back for the worker's next batch.
    fn finish(mut self) -> Option<WorkerEmulator<SC, C>> {
        self.emu.take()
    }
}

impl<SC, C> Drop for Replay<'_, SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>,
{
    fn drop(&mut self) {
        // Raised before the block goes back: the block wakes the snapshot thread, which has to
        // find the flag up when it next looks rather than take a block no worker will return.
        if thread::panicking() {
            self.run.abort();
        }
        if let Some(emulator) = self.emu.take().and_then(|mut emu| emu.emulator.take()) {
            release(emulator.state.memory, self.pooled);
        }
    }
}

/// Releases whatever is still queued once the snapshot thread stops. The workers drain the queue
/// themselves, so something is left only if one of them never started.
struct DrainOnDrop<'a> {
    queue: &'a Receiver<Snapshot>,
    pooled: bool,
}

impl Drop for DrainOnDrop<'_> {
    fn drop(&mut self) {
        while let Ok((_, snapshot, _, _)) = self.queue.recv() {
            release(snapshot.memory, self.pooled);
        }
    }
}

// allow: domain-complex signature; each arg is an independent handle/config
#[allow(clippy::too_many_arguments)]
fn run_snapshot_main_loop<E, NextBatch, Cycles, PvStream>(
    emu: &mut E,
    mut next_batch: NextBatch,
    cycles: Cycles,
    mut pv_stream: PvStream,
    snap_tx: &Sender<Snapshot>,
    emu_result: &mut Result<(), EmulationError>,
    total_cycles: &mut u64,
    output_pv_stream: &mut Vec<u8>,
    run: &RunControl,
) where
    NextBatch:
        FnMut(&mut E) -> Result<(Vec<(RiscvEmulationState, u64)>, EmulationReport), EmulationError>,
    Cycles: Fn(&E) -> u64,
    PvStream: FnMut(&mut E) -> Vec<u8>,
{
    let mut batch_idx = 0;
    loop {
        // A failed run returns no more memory, so every further batch is a step towards a pool
        // that stays empty. What the run produced is discarded; the failure is the result.
        if run.is_aborted() {
            break;
        }
        let t_batch_start = Instant::now();
        let (segments, report) = {
            let _b = spans::busy(WorkKind::Snapshot, Some(batch_idx as u32));
            match next_batch(emu) {
                Ok(res) => res,
                Err(err) => {
                    *emu_result = Err(err);
                    break;
                }
            }
        };
        let done = report.done;
        let batch_dur = t_batch_start.elapsed();

        let t_send_start = Instant::now();
        let emu_cycles = cycles(emu);
        {
            // Blocked here means the replay workers have not drained the queue: capacity someone else
            // holds, so `Wait`, not idleness. Normally zero — a non-zero figure means the queue filled,
            // which is a memory-pressure signal.
            let _w = spans::wait(WorkKind::Snapshot, Some(batch_idx as u32));
            let count = segments.len();
            for (index, (snapshot, target)) in segments.into_iter().enumerate() {
                let segment = SegmentId {
                    batch: batch_idx,
                    index,
                    count,
                };
                snap_tx.send((segment, snapshot, done, target)).expect(
                    "the pipeline holds the queue's receiver until the snapshot thread ends",
                );
            }
        }
        let send_dur = t_send_start.elapsed();
        #[cfg(test)]
        if hooks::DRAW_POOL_BLOCK_PER_BATCH.load(Ordering::Relaxed) {
            drop(
                crate::emulator::riscv::memory::GLOBAL_MEMORY_POOL
                    .1
                    .recv()
                    .expect("memory pool"),
            );
        }

        info!(
            %batch_idx,
            cycles = emu_cycles,
            emulate_ms = batch_dur.as_secs_f64() * 1e3,
            send_ms    = send_dur.as_secs_f64() * 1e3,
            "snapshot batch finished"
        );
        info!(
            target: "bench",
            "[bench][emulator-0](chunk-{batch_idx}) simple_emulator: running={:.3} ms",
            batch_dur.as_secs_f64() * 1e3,
        );

        if done {
            *total_cycles = emu_cycles;
            *output_pv_stream = pv_stream(emu);
            break;
        }
        batch_idx += 1;
    }
}

/// A record's public values the sequencer still has to fold in after emitting it out of order:
/// `is_cpu_chunk`, `start_pc`, `next_pc`, `exit_code`, `committed_value_digest`,
/// `deferred_proofs_digest`.
type OooPvs = (bool, [u32; 3], [u32; 3], u32, [u32; 8], [u32; 8]);

/// Batch from which the deferred pool starts being split out under [`DeferredSplit::FromChunk16`].
#[cfg(feature = "two-round-chunks")]
const DYNAMIC_CHUNK_START: u32 = 32;
#[cfg(not(feature = "two-round-chunks"))]
const DYNAMIC_CHUNK_START: u32 = 16;

/// Where the sequencer starts splitting the deferred pool into records of their own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeferredSplit {
    /// From chunk 16 on (32 under `two-round-chunks`), and at the end, with the chunks before it
    /// handed out as they finish: the prover pipeline's schedule, which
    /// [`emulate_snapshot_pipeline`] keeps.
    FromChunk16,
    /// After every chunk and in chunk order, as `emulate_with_opts` splits, so a block that fills
    /// early comes out at the same place and the run's records can stand in for the interpreter's
    /// in a proof.
    AfterEveryChunk,
}

impl DeferredSplit {
    fn splits_after(self, chunk: u32) -> bool {
        match self {
            Self::FromChunk16 => chunk >= DYNAMIC_CHUNK_START,
            Self::AfterEveryChunk => true,
        }
    }
}

/// The most replay workers [`emulate_snapshot_pipeline_with`] accepts: one per core. They are
/// threads of their own, so the rayon pool's size does not bound them; past the core count they
/// would only take turns.
pub fn max_pipeline_workers() -> usize {
    core_affinity::get_core_ids().map_or(1, |cores| cores.len())
}

/// Refuses a run the snapshot pipeline could not finish, as [`emulate_snapshot_pipeline_with`]
/// does before any thread starts: more workers than [`max_pipeline_workers`], or a memory pool, as
/// the `MEMORY_POOL_*` and `MEMORY_RECYCLER_THREADS` variables and the AOT split size it, that the
/// snapshot thread would wait on forever. Public so that a caller can refuse before work of its own.
///
/// A pooled run with `MEMORY_POOL_SIZE` unset raises the pool to what the run needs instead, as
/// long as the pool is not yet built: each worker keeps a pool memory between its batches, so the
/// default cannot serve a run with a worker per core.
pub fn check_pipeline(
    workers: NonZeroUsize,
    snapshot_main: SnapshotMainMode,
) -> Result<(), EmulationError> {
    let cores = max_pipeline_workers();
    if workers.get() > cores {
        return Err(EmulationError::TooManyWorkers {
            workers: workers.get(),
            cores,
        });
    }
    let segments = pooled_segments(snapshot_main);
    let pooled = segments.map(|segments| (workers.get(), segments));
    if let Some((workers, segments)) = pooled {
        raise_pool_size_floor(workers + segments);
    }
    match memory_pool_refusal(memory_pool_capacity(), memory_recycler_threads(), pooled) {
        Some(reason) => Err(EmulationError::PipelineMemoryPool(reason)),
        None => Ok(()),
    }
}

/// How many pool memories each batch of a run takes, if its snapshot memories come from the pool:
/// only the AOT snapshot thread hands them out, one per segment it cuts.
fn pooled_segments(snapshot_main: SnapshotMainMode) -> Option<usize> {
    #[cfg(feature = "aot-emulator")]
    let segments = (snapshot_main == SnapshotMainMode::Aot).then(|| {
        if crate::emulator::aot::split_chunks() > 0 {
            crate::emulator::aot::split_segments() as usize
        } else {
            1
        }
    });
    #[cfg(not(feature = "aot-emulator"))]
    let segments = {
        let _ = snapshot_main;
        None
    };
    #[cfg(test)]
    let segments = segments.or(hooks::DRAW_POOL_BLOCK_PER_BATCH
        .load(Ordering::Relaxed)
        .then_some(1));
    segments
}

/// Why a pool that ever holds `capacity` memories, with `recyclers` threads returning them, can
/// never serve a run, if it cannot. `pooled` is the replay workers and the segments per batch of
/// a run whose snapshot memories come from the pool.
fn memory_pool_refusal(
    capacity: usize,
    recyclers: usize,
    pooled: Option<(usize, usize)>,
) -> Option<String> {
    // Either snapshot thread takes a pool memory per batch, and only a recycler puts one back.
    if capacity == 0 {
        return Some(
            "it never holds a memory: MEMORY_POOL_SIZE is 0, or MEMORY_POOL_EAGER is with \
             MEMORY_POOL_LOW_WATER=0"
                .into(),
        );
    }
    if recyclers == 0 {
        return Some("MEMORY_RECYCLER_THREADS=0 never puts a memory back".into());
    }
    // A worker keeps its last batch's memory until it is handed the next one, so once every
    // worker holds one, the batch being cut needs a memory for each of its segments on top.
    match pooled {
        Some((workers, segments)) if workers + segments > capacity => Some(format!(
            "each of the {workers} replay workers keeps a memory until its next batch and the \
             AOT snapshot thread holds {segments} for the batch it cuts, and the pool never \
             holds more than {capacity}"
        )),
        _ => None,
    }
}

/// [`emulate_snapshot_pipeline_with`], with the worker count read from `NUM_THREADS` (unset or
/// `0`: one) and the prover pipeline's deferred split.
pub fn emulate_snapshot_pipeline<SC, C, F>(
    witness: &ProvingWitness<SC, C, Vec<u8>>,
    handle_record: F,
) -> Result<(Vec<EmulationReport>, u64, Vec<u8>), EmulationError>
where
    SC: 'static + StarkGenericConfig + Send + Sync,
    SC::Val: PrimeField32 + FieldSpecificPoseidon2Config,
    C: 'static + ChipBehavior<Val<SC>, Program = Program, Record = EmulationRecord>,
    F: Fn(EmulationRecord, bool) + Send + Sync,
{
    let workers = crate::mle::env_u32("NUM_THREADS")
        .and_then(|n| NonZeroUsize::new(n as usize))
        .unwrap_or(NonZeroUsize::MIN);
    emulate_snapshot_pipeline_with(witness, workers, DeferredSplit::FromChunk16, handle_record)
}

/// Emulate `witness` with one snapshot thread, the interpreter or AOT code as
/// `witness.opts.snapshot_main` says, and `workers` interpreters replaying its snapshots into
/// records. `handle_record` gets them with the run's `done` flag; the result is the reports in the
/// order the workers finished, the snapshot thread's cycle count and the committed bytes.
///
/// `deferred_split` says where the deferred pool starts being split into records of their own.
/// A run [`check_pipeline`] refuses is refused with its error before any thread starts.
///
/// The first failure in any thread ends the run and is what the caller gets: the snapshot
/// thread's error, else a replay's, as an error; a panic in any thread, `handle_record` included,
/// resumed with its own payload.
///
/// # Panics
///
/// If `witness.opts.chunk_batch_size` is not 1.
pub fn emulate_snapshot_pipeline_with<SC, C, F>(
    witness: &ProvingWitness<SC, C, Vec<u8>>,
    workers: NonZeroUsize,
    deferred_split: DeferredSplit,
    handle_record: F,
) -> Result<(Vec<EmulationReport>, u64, Vec<u8>), EmulationError>
where
    SC: 'static + StarkGenericConfig + Send + Sync,
    SC::Val: PrimeField32 + FieldSpecificPoseidon2Config,
    C: 'static + ChipBehavior<Val<SC>, Program = Program, Record = EmulationRecord>,
    F: Fn(EmulationRecord, bool) + Send + Sync,
{
    emulate_snapshot_pipeline_with_selector(witness, workers, deferred_split, handle_record, |_| {
        TraceKind::Full
    })
}

/// [`emulate_snapshot_pipeline_with`], with `trace_selector` choosing each batch's trace mode.
pub fn emulate_snapshot_pipeline_with_selector<SC, C, F, S>(
    witness: &ProvingWitness<SC, C, Vec<u8>>,
    workers: NonZeroUsize,
    deferred_split: DeferredSplit,
    handle_record: F,
    trace_selector: S,
) -> Result<(Vec<EmulationReport>, u64, Vec<u8>), EmulationError>
where
    SC: 'static + StarkGenericConfig + Send + Sync,
    SC::Val: PrimeField32 + FieldSpecificPoseidon2Config,
    C: 'static + ChipBehavior<Val<SC>, Program = Program, Record = EmulationRecord>,
    F: Fn(EmulationRecord, bool) + Send + Sync,
    S: Fn(usize) -> TraceKind + Send + Sync,
{
    let opts = witness.opts.as_ref().expect("witness.opts not set");
    let split_opts = opts.split_opts;
    // A batch of more than one chunk drops most of its own precompile events without a word
    // (see `chunk_batch_size`), and the code reads the same either way -- so refuse to start.
    assert_eq!(
        opts.chunk_batch_size, 1,
        "the deferred split needs one chunk per batch; set CHUNK_BATCH_SIZE=1"
    );
    check_pipeline(workers, opts.snapshot_main)?;

    init_memory_pool();
    if !is_pool_initialized() {
        init_cpu_event_buffer_pool(50, CudaHostAllocFlags::DEFAULT);
    }

    let num_threads = workers.get();
    info!("Emulator snapshot worker threads: {}", num_threads);

    let pooled = pooled_segments(opts.snapshot_main).is_some();

    let (snap_tx, snap_rx) = bounded::<Snapshot>(256);
    let (snapshot_msg_tx, snapshot_msg_rx) = unbounded::<Msg>();

    let final_pvs_state = Arc::new(RecordFinalPvsState::default());
    let program = witness.program.as_ref().unwrap();
    let shared_ds: SharedDeferredState = Arc::new(ParkingMutex::new(EmulationDeferredState::new(
        program.clone(),
        final_pvs_state.clone(),
    )));

    // Shared so that whichever worker finishes a split chunk last can fold its segments.
    let collector = SegmentCollector::default();

    let mut emu_result = Ok(());
    let mut total_cycles = 0u64;
    let mut pv_stream: Vec<u8> = Vec::new();
    let reports = Mutex::new(Vec::new());
    let run = RunControl::default();

    // One batch on worker `tid`. The emulator in `slot` is reused across batches; the replay owns
    // it meanwhile and only hands it back if the batch completes.
    let replay_one = |tid: usize,
                      slot: &mut Option<WorkerEmulator<SC, C>>,
                      (segment, snapshot, done, global_clk): Snapshot,
                      snapshot_msg_tx: &Sender<Msg>,
                      shared_ds: &SharedDeferredState| {
        let batch_idx = segment.batch;
        let t_recover_and_emu = Instant::now();
        // The whole batch, not just the replay: the mode switch, the report push and the
        // completion send are this worker's work too, and the outer span is an idle one, so
        // anything left outside here would read as waiting for input.
        let _batch = spans::busy(WorkKind::Emulate, Some(batch_idx as u32));
        let mut replay = Replay {
            emu: slot.take(),
            run: &run,
            pooled,
        };
        {
            // Per-batch setup, kept apart from the replay it precedes: the pipeline's head
            // bubble is where that difference is worth having.
            let _b = spans::busy(WorkKind::EmulateRecover, Some(batch_idx as u32));
            match replay.emu.as_mut() {
                Some(emu) => {
                    let previous = emu.recover_riscv_in_place(
                        snapshot,
                        shared_ds.clone(),
                        global_clk,
                        segment.is_final(),
                    );
                    release(previous, pooled);
                }
                None => {
                    replay.emu = Some(MetaEmulator::recover_riscv(
                        witness,
                        snapshot,
                        Some(ParOptions {
                            thread_id: tid as u32,
                            num_threads: num_threads as u32,
                        }),
                        shared_ds.clone(),
                        global_clk,
                        segment.is_final(),
                    ));
                }
            }
        }
        #[cfg(test)]
        if hooks::PANIC_IN_FIRST_REPLAY.swap(false, Ordering::Relaxed) {
            panic!("injected replay panic");
        }
        if let Some(emulator) = replay.emu().emulator.as_mut() {
            emulator.mode = match trace_selector(batch_idx) {
                TraceKind::Full => RiscvEmulatorMode::Trace,
                TraceKind::Light => RiscvEmulatorMode::LightTrace,
            };
            emulator.update_mode_deps();
        }
        let t_record_batch = Instant::now();
        let mut chunk_record = None;
        let replayed = replay.emu().try_next_record_batch(&mut |rec| {
            // A split chunk's own record waits for its siblings; the deferred and precompile
            // records a segment splits out stand alone and go now.
            if segment.is_split() && rec.is_cpu_chunk {
                assert!(
                    chunk_record.replace(rec).is_none(),
                    "a replay segment produced two chunk records"
                );
                return;
            }
            emit_record(snapshot_msg_tx, batch_idx, rec, done);
        });
        #[cfg(test)]
        let replayed = if hooks::ERROR_IN_FIRST_REPLAY.swap(false, Ordering::Relaxed) {
            Err(EmulationError::Unimplemented())
        } else {
            replayed
        };
        let report = match replayed {
            Ok(report) => report,
            Err(error) => {
                run.replay_failed(error);
                return;
            }
        };
        *slot = replay.finish();
        let record_batch_ms = t_record_batch.elapsed().as_secs_f64() * 1000.0;
        info!(
            target: "bench",
            "[bench][emulator-{tid}](chunk-{batch_idx}) emulator: running={record_batch_ms:.3} ms"
        );
        // One report per chunk, as before the replay could be split: a middle segment's report
        // describes a piece of a chunk, and the consumers count on there being exactly one per
        // chunk.
        if segment.is_final() {
            reports
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(report);
        }
        // The batch is finished once every segment is in — which is not necessarily the last one
        // to start, so the segment that completes the fold announces it.
        let batch_finished = if segment.is_split() {
            match collector.submit(segment, chunk_record) {
                Some(folded) => {
                    if let Some(record) = folded {
                        emit_record(snapshot_msg_tx, batch_idx, record, done);
                    }
                    true
                }
                None => false,
            }
        } else {
            true
        };
        if batch_finished {
            snapshot_msg_tx
                .send(Msg::SnapShotDone {
                    chunk: batch_idx as u32,
                })
                .expect("the sequencer receives until every worker is gone");
        }
        debug!(
            "[Thread {}] Done, Batch: {}, Recover & Emulate One Batch: {}ms.",
            tid,
            batch_idx,
            t_recover_and_emu.elapsed().as_secs_f64() * 1000.0
        );
    };

    // Workers are threads of their own, not rayon jobs: a worker waits on the snapshot queue, and
    // the sequencer's deferred split and the snapshot thread's memory restore are rayon jobs, so
    // workers holding every rayon thread would leave those nowhere to run. A worker outlives a
    // failed replay and keeps draining the queue: the snapshots on it hold pool memories that the
    // snapshot thread may be waiting on.
    let replay_snapshots = |tid: usize,
                            snap_rx: Receiver<Snapshot>,
                            snapshot_msg_tx: Sender<Msg>,
                            shared_ds: SharedDeferredState| {
        spans::bind_lane(LaneId::new(Role::Emulate, tid));
        // Held for the thread's life, so a worker that waited through the run without being fed
        // still produces a row — that idleness is the finding — and the span's start says when
        // it started.
        let _lane = spans::idle(WorkKind::Unattributed);
        let mut slot = None;
        while let Ok(snapshot) = snap_rx.recv() {
            if run.is_aborted() {
                release(snapshot.1.memory, pooled);
                continue;
            }
            run.guard(|| replay_one(tid, &mut slot, snapshot, &snapshot_msg_tx, &shared_ds));
        }
        if let Some(emulator) = slot.and_then(|mut emu| emu.emulator.take()) {
            release(emulator.state.memory, pooled);
        }
    };

    let t_emu = std::time::Instant::now();
    thread::scope(|s| {
        // sequencer
        //
        // Named because the snapshot pass and the replay pool run concurrently: with every lane
        // anonymous a `perf --per-thread` profile cannot tell one from the other.
        spawn_named(s, "mle-sequencer", {
            let shared_ds = Arc::clone(&shared_ds);
            let run = &run;
            let handle_record = &handle_record;
            let collector = &collector;
            move || {
                let mut stash: BTreeMap<u32, Bucket> = BTreeMap::new();
                let mut next = 0u32;

                // OOO state: saved PV fields for deferred accumulation
                let mut ooo_saved: BTreeMap<u32, Vec<OooPvs>> = BTreeMap::new();

                // Received to the end even after a failure, so a live worker's send never fails,
                // but nothing more reaches the caller: the run's result is the failure.
                while let Ok(msg) = snapshot_msg_rx.recv() {
                    if run.is_aborted() {
                        // Held records keep fixed-pool pinned buffers that a worker still
                        // replaying may be blocked on, so let them go rather than wait to exit.
                        stash.clear();
                        ooo_saved.clear();
                        collector.clear();
                        continue;
                    }
                    run.guard(|| {
                        let is_snapshot_done = matches!(&msg, Msg::SnapShotDone { .. });
                        match msg {
                            Msg::Record { chunk, rec, done } => {
                                stash
                                    .entry(chunk)
                                    .or_insert_with(|| Bucket {
                                        recs: Vec::new(),
                                        finished: false,
                                    })
                                    .recs
                                    .push((rec, done));
                            }

                            Msg::SnapShotDone { chunk } => {
                                stash
                                    .entry(chunk)
                                    .or_insert_with(|| Bucket {
                                        recs: Vec::new(),
                                        finished: false,
                                    })
                                    .finished = true;
                            }
                        }

                        // === OOO emission for first DYNAMIC_CHUNK_START batches ===
                        // Only scan on SnapShotDone — Record messages alone can't trigger emission
                        // since a batch must be fully finished before it can be emitted OOO.
                        // `AfterEveryChunk` emits in chunk order, so it never takes this path.
                        if is_snapshot_done && deferred_split == DeferredSplit::FromChunk16 {
                            let mut to_emit_ooo: Vec<u32> = Vec::new();
                            for (&batch, bkt) in stash.iter() {
                                if batch < DYNAMIC_CHUNK_START
                                    && bkt.finished
                                    && !ooo_saved.contains_key(&batch)
                                {
                                    // Check if any record has done_flag (total chunks < threshold)
                                    let has_done = bkt.recs.iter().any(|(_, done)| *done);
                                    if !has_done {
                                        to_emit_ooo.push(batch);
                                    }
                                }
                            }

                            for batch in to_emit_ooo {
                                let Bucket { mut recs, .. } = stash.remove(&batch).unwrap();
                                let mut saved_fields = Vec::new();

                                for (mut rec, _done_flag) in recs.drain(..) {
                                    let rec_mut = Arc::make_mut(&mut rec);
                                    let orig_pvs = rec_mut.public_values;

                                    // Save fields for deferred PV accumulation
                                    saved_fields.push((
                                        rec_mut.is_cpu_chunk,
                                        orig_pvs.start_pc,
                                        orig_pvs.next_pc,
                                        orig_pvs.exit_code,
                                        orig_pvs.committed_value_digest,
                                        orig_pvs.deferred_proofs_digest,
                                    ));

                                    // Compute standalone PVs from default (matching sequential)
                                    // Key: flag_active starts TRUE in EmulationDeferredState::new,
                                    // so update_public_values increments exec_chunk from the start.
                                    use crate::emulator::riscv::{
                                        public_values::PublicValues,
                                        public_values_compat::encode_public_value_chunk_counter,
                                    };
                                    let counter = encode_public_value_chunk_counter(batch + 1);
                                    let pvs = PublicValues::<u32, u32> {
                                        chunk: counter,
                                        execution_chunk: counter,
                                        start_pc: orig_pvs.start_pc,
                                        next_pc: orig_pvs.next_pc,
                                        exit_code: orig_pvs.exit_code,
                                        committed_value_digest: orig_pvs.committed_value_digest,
                                        deferred_proofs_digest: orig_pvs.deferred_proofs_digest,
                                        ..Default::default()
                                    };
                                    // addr_limbs + empty stay at default (zero) — matching
                                    // sequential

                                    rec_mut.public_values = pvs;

                                    // Emit immediately (no splits for first DYNAMIC_CHUNK_START,
                                    // not done_flag)
                                    handle_record(Arc::try_unwrap(rec).unwrap(), false);
                                }

                                ooo_saved.insert(batch, saved_fields);
                            }
                        } // end if SnapShotDone (OOO scan guard)

                        // === Sequential drain (PV accumulation + batch >= DYNAMIC_CHUNK_START
                        // emission) ===
                        loop {
                            // First check: was this batch already emitted OOO?
                            if let Some(saved) = ooo_saved.remove(&next) {
                                // Already emitted OOO — just accumulate PVs for deferred state
                                let mut ds = shared_ds.lock();
                                for (is_cpu, spc, npc, ec, cvd, dpd) in saved {
                                    ds.accumulate_pvs_only(is_cpu, spc, npc, ec, cvd, dpd);
                                }
                                next += 1;
                                continue;
                            }

                            // Second check: is there a finished batch in the stash?
                            match stash.get(&next) {
                                Some(bkt) if bkt.finished => {} // proceed below
                                _ => break,                     // not ready yet
                            }

                            // Standard sequential processing (batch >= DYNAMIC_CHUNK_START or
                            // done_flag batches)
                            let Bucket { mut recs, .. } = stash.remove(&next).unwrap();

                            for (mut rec, done_flag) in recs.drain(..) {
                                let rec_mut = Arc::make_mut(&mut rec);
                                let mut ds = shared_ds.lock();
                                ds.update_public_values(done_flag, rec_mut);

                                handle_record(Arc::try_unwrap(rec).unwrap(), done_flag);

                                let mut splits = if deferred_split.splits_after(next) || done_flag {
                                    ds.take_split_records(done_flag, split_opts, next)
                                } else {
                                    Vec::new()
                                };

                                if !splits.is_empty() {
                                    let count = splits.len();
                                    let eid = 99usize;

                                    info!(
                                        target: "bench",
                                        "[bench][split-burst][emulator-{eid}] count={count} ms=0",
                                    );
                                }

                                for mut split_rec in splits.drain(..) {
                                    ds.update_public_values(done_flag, &mut split_rec);
                                    handle_record(split_rec, done_flag);
                                }
                            }
                            next += 1;
                        }
                    });
                }
            }
        });

        // snapshot main thread
        spawn_named(s, "mle-snapshot", {
            let run = &run;
            let emu_result = &mut emu_result;
            let total_cycles = &mut total_cycles;
            let pv_stream = &mut pv_stream;
            move || {
                run.guard(|| {
                    let t_snapshot_main = Instant::now();
                    // One lane for the whole thread, so bind it outright.
                    spans::bind_lane(LaneId::new(Role::Snapshot, 0));
                    // Busy, not idle, for its whole life: this thread produces snapshots and never
                    // waits for input, and the one thing that does block it — a full queue — is
                    // `Wait` in the loop.
                    let _lane = spans::busy(WorkKind::Snapshot, None);
                    let run_interp =
                        |emu_result: &mut _, total_cycles: &mut _, pv_stream: &mut _| {
                            info!("[Snapshot Main] mode=Interpreter");
                            let mut emu =
                                MetaEmulator::setup_riscv(witness, final_pvs_state.clone(), None);
                            emu.disable_cost_estimator_for_snapshot();
                            run_snapshot_main_loop(
                                &mut emu,
                                |emu| emu.next_state_batch_segments(true, &mut |_| {}),
                                |emu| emu.cycles(),
                                |emu| emu.get_pv_stream(),
                                &snap_tx,
                                emu_result,
                                total_cycles,
                                pv_stream,
                                run,
                            );
                        };
                    #[cfg(feature = "aot-emulator")]
                    match witness.opts.expect("witness.opts not set").snapshot_main {
                        SnapshotMainMode::Aot => {
                            info!("[AOT] snapshot-main = AotMetaEmulator (running AOT-compiled chunks)");
                            // Both knobs default to the shape of the run rather than a constant,
                            // so say what they came out as. On the `bench` target because that is
                            // the one a run at the shipped log level keeps, and here because this
                            // is the only path that reads them.
                            info!(
                                target: "bench",
                                "[split-replay] {} segment(s) on each of the first {} chunk(s)",
                                crate::emulator::aot::split_segments(),
                                crate::emulator::aot::split_chunks(),
                            );
                            let t_aot_setup = Instant::now();
                            let mut emu =
                                AotMetaEmulator::setup_riscv(witness, final_pvs_state, None);
                            emu.disable_cost_estimator_for_snapshot();
                            info!(
                                "[Snapshot Main] AOT setup done in {:.3}s",
                                t_aot_setup.elapsed().as_secs_f64()
                            );
                            run_snapshot_main_loop(
                                &mut emu,
                                |emu| emu.next_state_batch_segments(),
                                |emu| emu.cycles(),
                                |emu| emu.get_pv_stream(),
                                &snap_tx,
                                emu_result,
                                total_cycles,
                                pv_stream,
                                run,
                            );
                        }
                        SnapshotMainMode::Interpreter => {
                            run_interp(emu_result, total_cycles, pv_stream);
                        }
                    }
                    #[cfg(not(feature = "aot-emulator"))]
                    {
                        // Without the feature this arm is the only one compiled, so an `Aot`
                        // request would run the interpreter and report success.
                        assert_eq!(
                            witness.opts.expect("witness.opts not set").snapshot_main,
                            SnapshotMainMode::Interpreter,
                            "snapshot_main = Aot needs the `aot-emulator` feature"
                        );
                        run_interp(emu_result, total_cycles, pv_stream);
                    }
                    info!(
                        "[Thread Snapshot] Done in {:.3}s",
                        t_snapshot_main.elapsed().as_secs_f64()
                    );
                });
                // However the thread ends, or the workers wait on the queue forever.
                drop(snap_tx);
            }
        });

        let _drain = DrainOnDrop {
            queue: &snap_rx,
            pooled,
        };
        let replay_snapshots = &replay_snapshots;
        let replay_workers: Vec<_> = (0..num_threads)
            .map(|tid| {
                let snap_rx = snap_rx.clone();
                let snapshot_msg_tx = snapshot_msg_tx.clone();
                let shared_ds = shared_ds.clone();
                spawn_named(s, &format!("mle-replay-{tid}"), move || {
                    replay_snapshots(tid, snap_rx, snapshot_msg_tx, shared_ds)
                })
            })
            .collect();
        drop(snapshot_msg_tx);
        // Before `_drain` goes, which would otherwise take snapshots from under live workers.
        for worker in replay_workers {
            if let Err(payload) = worker.join() {
                run.guard(|| panic::resume_unwind(payload));
            }
        }
    });

    let emu_ms = t_emu.elapsed().as_secs_f64() * 1000.0;
    info!(target: "bench", "EMULATION_TOTAL = {emu_ms:.3} ms");

    let RunControl {
        panic: first_panic,
        replay_error,
        ..
    } = run;
    if let Some(payload) = first_panic
        .into_inner()
        .unwrap_or_else(PoisonError::into_inner)
    {
        panic::resume_unwind(payload);
    }
    emu_result?;
    if let Some(error) = replay_error
        .into_inner()
        .unwrap_or_else(PoisonError::into_inner)
    {
        return Err(error);
    }
    Ok((
        reports.into_inner().unwrap_or_else(PoisonError::into_inner),
        total_cycles,
        pv_stream,
    ))
}

/// `Scope::spawn` with a thread name, so `perf --per-thread`, `top -H` and panic messages can tell
/// the pipeline's lanes apart. Panics only if the OS refuses the thread, same as `Scope::spawn`.
fn spawn_named<'scope, 'env, F, T>(
    scope: &'scope thread::Scope<'scope, 'env>,
    name: &str,
    f: F,
) -> thread::ScopedJoinHandle<'scope, T>
where
    F: FnOnce() -> T + Send + 'scope,
    T: Send + 'scope,
{
    thread::Builder::new()
        .name(name.to_string())
        .spawn_scoped(scope, f)
        .expect("failed to spawn pipeline thread")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configs::stark_config::KoalaBearPoseidon2;
    use std::time::Duration;

    /// fib(10) in five chunks of 2048, each its own batch.
    fn fib_witness() -> ProvingWitness<KoalaBearPoseidon2, RiscvChips<KoalaBearPoseidon2>, Vec<u8>>
    {
        let fib: &[u8] = include_bytes!("../compiler/test_elf/fib-elf");
        let program = crate::compiler::riscv::compiler::Compiler::new(
            crate::compiler::riscv::compiler::SourceType::RISCV,
            fib,
        )
        .expect("parse fib")
        .compile();
        let mut stdin = crate::emulator::stdin::EmulatorStdin::<Program, Vec<u8>>::new_builder::<
            KoalaBearPoseidon2,
        >();
        stdin.write(&10u32);
        ProvingWitness {
            program: Some(program),
            vk_root: None,
            stdin: Some(stdin.finalize()),
            flag_empty_stdin: false,
            config: None,
            opts: Some(crate::emulator::opts::EmulatorOpts {
                chunk_size: 2048,
                chunk_batch_size: 1,
                split_opts: crate::emulator::opts::SplitOpts::new(512),
                max_cycles: Some(1 << 32),
                cycle_tracker: false,
                cost_estimator: false,
                snapshot_main: SnapshotMainMode::Interpreter,
            }),
            records: Vec::new(),
        }
    }

    /// Re-runs `test` alone in a child process under `env` plus `child_var`, kills it once
    /// `deadline` passes, and fails with `hung` if it did, or if it failed or never printed
    /// `marker`. A run that can hang has to be killable, and the environment the pipeline reads
    /// (the memory pool's size, the rayon pool's) is read once per process.
    fn in_child(
        test: &str,
        child_var: &str,
        env: &[(&str, &str)],
        deadline: Duration,
        hung: &str,
        marker: &str,
    ) {
        let mut child = std::process::Command::new(std::env::current_exe().expect("test binary"))
            .args(["--exact", test, "--nocapture"])
            .env(child_var, "1")
            .envs(env.iter().copied())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("re-run this test binary");
        // Read as it comes: a child blocked on a full pipe would pass for a hung pipeline.
        let pipe = |mut from: Box<dyn std::io::Read + Send>| {
            thread::spawn(move || {
                let mut text = String::new();
                let _ = from.read_to_string(&mut text);
                text
            })
        };
        let stdout = pipe(Box::new(child.stdout.take().expect("stdout")));
        let stderr = pipe(Box::new(child.stderr.take().expect("stderr")));
        let started = Instant::now();
        let status = loop {
            if let Some(status) = child.try_wait().expect("wait on the child") {
                break Some(status);
            }
            if started.elapsed() > deadline {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            thread::sleep(Duration::from_millis(100));
        };
        let stdout = stdout.join().expect("stdout reader");
        let stderr = stderr.join().expect("stderr reader");
        let tail = |text: &str| text.lines().rev().take(20).collect::<Vec<_>>().join("\n");
        let Some(status) = status else {
            panic!(
                "{hung}: killed after {deadline:?}\n{}\n{}",
                tail(&stdout),
                tail(&stderr)
            );
        };
        assert!(
            status.success(),
            "child failed:\n{}\n{}",
            tail(&stdout),
            tail(&stderr)
        );
        // `--exact` against a stale name matches nothing and still exits 0.
        assert!(
            stdout.contains(marker),
            "child ran no assertion; is the test name still its path?\n{}",
            tail(&stdout)
        );
    }

    /// Every way a run can fail reaches the caller as what it was, and none of them hangs: a
    /// replay's panic and the record handler's with their own payloads, a replay's error as that
    /// error. Before them, interpreter runs leave the pool's recycler idle: their snapshot memories
    /// are their own allocations, and a full pool would keep each one waiting for good.
    ///
    /// The pool is two memories, the least `check_pipeline` lets a pooled run with one worker
    /// start on: the worker keeps one until its next batch. In the failing runs the snapshot
    /// thread draws a memory per batch the way the AOT thread does, so the run moves in lockstep
    /// with its one worker and a memory a failed replay kept stops it for good.
    #[test]
    fn every_failure_reaches_the_caller_without_a_hang() {
        const CHILD_VAR: &str = "PICO_PIPELINE_FAILURE_PROBE";
        const MARKER: &str = "[pipeline-failure] every failure reached the caller";

        if std::env::var(CHILD_VAR).is_ok() {
            let witness = fib_witness();
            let run = |handle_record: &(dyn Fn(EmulationRecord, bool) + Sync)| {
                emulate_snapshot_pipeline_with(
                    &witness,
                    NonZeroUsize::MIN,
                    DeferredSplit::FromChunk16,
                    handle_record,
                )
            };
            let panic_of = |handle_record: &(dyn Fn(EmulationRecord, bool) + Sync)| {
                let payload =
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| run(handle_record)))
                        .expect_err("the panic must reach the caller");
                payload.downcast_ref::<&str>().copied()
            };

            for _ in 0..2 {
                run(&|_, _| {}).expect("an interpreter run completes");
            }
            let started = Instant::now();
            while !GLOBAL_MEMORY_RECYCLER.is_empty() {
                assert!(
                    started.elapsed() < Duration::from_secs(10),
                    "{} memories wait in the recycler queue after two interpreter runs",
                    GLOBAL_MEMORY_RECYCLER.len()
                );
                thread::sleep(Duration::from_millis(10));
            }

            hooks::DRAW_POOL_BLOCK_PER_BATCH.store(true, Ordering::Relaxed);
            // The same setting without a failure finishes, so a hang below is the failure's.
            let (reports, cycles, _) = run(&|_, _| {}).expect("the lockstep run completes");
            assert!(
                reports.len() > 1 && cycles > 0,
                "{} report(s)",
                reports.len()
            );

            hooks::PANIC_IN_FIRST_REPLAY.store(true, Ordering::Relaxed);
            assert_eq!(panic_of(&|_, _| {}), Some("injected replay panic"));

            assert_eq!(
                panic_of(&|_, _| panic!("injected handler panic")),
                Some("injected handler panic"),
                "the workers' failed sends must not stand in for the handler's panic"
            );

            hooks::ERROR_IN_FIRST_REPLAY.store(true, Ordering::Relaxed);
            assert!(
                matches!(run(&|_, _| {}), Err(EmulationError::Unimplemented())),
                "the replay's error must be the run's"
            );
            println!("{MARKER}");
            return;
        }

        in_child(
            "proverchain::riscv::tests::every_failure_reaches_the_caller_without_a_hang",
            CHILD_VAR,
            &[("MEMORY_POOL_SIZE", "2")],
            Duration::from_secs(180),
            "the pipeline hung on a failure",
            MARKER,
        );
    }

    #[test]
    fn a_pool_that_can_never_serve_the_run_is_named() {
        assert_eq!(memory_pool_refusal(16, 4, None), None);
        assert_eq!(
            memory_pool_refusal(16, 4, Some((8, 8))),
            None,
            "exactly full is served"
        );
        assert!(memory_pool_refusal(0, 4, None).is_some_and(|r| r.contains("never holds")));
        assert!(memory_pool_refusal(16, 0, None)
            .is_some_and(|r| r.contains("MEMORY_RECYCLER_THREADS=0")));
        // Either side alone can tip it.
        assert!(memory_pool_refusal(16, 4, Some((8, 9))).is_some_and(|r| r.contains("9 for")));
        assert!(memory_pool_refusal(16, 4, Some((16, 1))).is_some());
        // A pool sized the way the launch scripts size it has room for the whole clamp range.
        assert_eq!(memory_pool_refusal(140, 4, Some((12, 16))), None);
    }

    /// As many workers as the rayon pool has threads must still finish. The snapshot thread's
    /// memory restore is a rayon job, and workers that waited for snapshots on the pool's own
    /// threads would leave it none to run on.
    #[cfg(feature = "rayon")]
    #[test]
    fn as_many_workers_as_rayon_threads_finish() {
        const CHILD_VAR: &str = "PICO_PIPELINE_RAYON_POOL_PROBE";
        const MARKER: &str = "[rayon-pool] the pipeline finished with every rayon thread a worker";
        const THREADS: usize = 2;

        if std::env::var(CHILD_VAR).is_ok() {
            assert_eq!(
                rayon::current_num_threads(),
                THREADS,
                "RAYON_NUM_THREADS not applied"
            );
            let workers = NonZeroUsize::new(THREADS).expect("nonzero");
            let (reports, cycles, _) = emulate_snapshot_pipeline_with(
                &fib_witness(),
                workers,
                DeferredSplit::FromChunk16,
                |_, _| {},
            )
            .expect("the pipeline completes");
            assert!(
                reports.len() > 1 && cycles > 0,
                "{} report(s)",
                reports.len()
            );
            println!("{MARKER}");
            return;
        }

        in_child(
            "proverchain::riscv::tests::as_many_workers_as_rayon_threads_finish",
            CHILD_VAR,
            &[("RAYON_NUM_THREADS", &THREADS.to_string())],
            Duration::from_secs(120),
            "the pipeline hung with every rayon thread a worker",
            MARKER,
        );
    }

    /// A record the assertions can tell apart. `start_pc` is carried by the fold from the first
    /// segment, so it doubles as a marker of which segment ended up at the head.
    fn marked(start_pc: u32) -> EmulationRecord {
        let mut record = EmulationRecord::default();
        record.public_values.start_pc = [start_pc, 0, 0];
        record
    }

    fn seg(batch: usize, index: usize, count: usize) -> SegmentId {
        SegmentId {
            batch,
            index,
            count,
        }
    }

    /// The workers run in parallel, so the last segment can be handed in first. What comes out
    /// has to be in clock order regardless — merging them as they arrive would splice a chunk's
    /// events out of order, and nothing downstream would say so.
    #[test]
    fn segments_fold_in_index_order_however_they_arrive() {
        let collector = SegmentCollector::default();

        assert!(
            collector
                .submit(seg(0, 1, 2), Some(marked(0x2000)))
                .is_none(),
            "one segment of two is not a chunk"
        );
        let folded = collector
            .submit(seg(0, 0, 2), Some(marked(0x1000)))
            .expect("the chunk is complete")
            .expect("it has records");

        assert_eq!(
            folded.public_values.start_pc,
            [0x1000, 0, 0],
            "the head is segment 0, not whichever arrived first"
        );
    }

    #[test]
    fn a_chunk_waits_for_every_segment() {
        let collector = SegmentCollector::default();
        assert!(collector.submit(seg(7, 0, 3), Some(marked(1))).is_none());
        assert!(collector.submit(seg(7, 2, 3), Some(marked(3))).is_none());
        assert!(
            collector.submit(seg(7, 1, 3), Some(marked(2))).is_some(),
            "the third hand-in completes it"
        );
    }

    /// Counting hand-ins, not records: a segment whose replay produced no chunk record must not
    /// leave the chunk one short for ever.
    #[test]
    fn a_segment_with_no_record_still_counts() {
        let collector = SegmentCollector::default();
        assert!(collector.submit(seg(1, 0, 2), None).is_none());
        let folded = collector
            .submit(seg(1, 1, 2), Some(marked(0x30)))
            .expect("the chunk is complete");
        assert_eq!(
            folded
                .expect("one segment had a record")
                .public_values
                .start_pc,
            [0x30, 0, 0]
        );
    }

    #[test]
    fn chunks_are_kept_apart() {
        let collector = SegmentCollector::default();
        assert!(collector.submit(seg(4, 0, 2), Some(marked(0x40))).is_none());
        assert!(
            collector.submit(seg(5, 0, 2), Some(marked(0x50))).is_none(),
            "a segment of another chunk does not complete this one"
        );
        assert!(collector.submit(seg(4, 1, 2), Some(marked(0x41))).is_some());
    }

    /// A panicking hand-in must not take the collector down with it. The assertions run before
    /// the first write, so the map is still consistent, and the workers behind it have to keep
    /// going — otherwise one bad segment turns into one panic per worker and the pipeline's
    /// producer waits for a consumer that no longer exists.
    #[test]
    fn a_panicking_hand_in_does_not_stop_the_collector() {
        let collector = SegmentCollector::default();
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(|_| {}));
        let doubled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            collector.submit(seg(3, 0, 2), Some(marked(1)));
            collector.submit(seg(3, 0, 2), Some(marked(1)));
        }));
        std::panic::set_hook(previous);
        assert!(doubled.is_err(), "a repeat hand-in panics");

        assert!(
            collector.submit(seg(3, 1, 2), Some(marked(2))).is_some(),
            "the chunk still completes on its remaining segment"
        );
    }

    #[test]
    #[should_panic(expected = "was handed in twice")]
    fn a_repeat_hand_in_is_loud() {
        let collector = SegmentCollector::default();
        collector.submit(seg(2, 0, 2), Some(marked(1)));
        collector.submit(seg(2, 0, 2), Some(marked(1)));
    }
}
