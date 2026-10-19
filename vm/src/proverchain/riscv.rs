//! Snapshot-based RISC-V emulation pipeline: a sequencer takes emulator snapshots, worker threads
//! replay them into `EmulationRecord`s, and the caller consumes the records through a callback. A
//! chunk's replay can arrive as several segments, folded back here into the one record the unsplit
//! replay would have produced, so the chunk still proves once.
//!
//! The FRI `RiscvProver` that used to drive proving from here was removed with the FRI path (tag
//! `legacy-fri-last`). `mle::machine::riscv::emulate_with_pipeline` maps a run of it onto the
//! `EmulationOutput` that `emulate_with_opts` returns, so a prover can take its records; the AOT
//! validation harness under `perf/aot/` calls it directly.

#[cfg(feature = "aot-emulator")]
use crate::emulator::emulator::AotMetaEmulator;
use crate::{
    compiler::riscv::program::Program,
    configs::config::{StarkGenericConfig, Val},
    emulator::{
        emulator::MetaEmulator,
        opts::SnapshotMainMode,
        riscv::{
            emulator::{
                EmulationDeferredState, EmulationError, RiscvEmulator, SharedDeferredState,
            },
            memory::{
                memory_pool_capacity, memory_recycler_threads, ContiguousRiscvMemory,
                GLOBAL_MEMORY_RECYCLER,
            },
            record::EmulationRecord,
            record_digest::{field_digests, is_compared},
            record_merge::merge_segments,
            state::RiscvEmulationState,
        },
        snapshot::SnapshotEmulator,
    },
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::{
        chip::ChipBehavior, field::FieldSpecificPoseidon2Config, report::EmulationReport,
        witness::ProvingWitness,
    },
};
use alloc::sync::Arc;
use core_affinity;
use crossbeam::channel::{bounded, unbounded, Receiver, Sender};
use p3_field::PrimeField32;
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

pub type RiscvChips<SC> = RiscvChipType<Val<SC>>;

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

/// Which segment of which chunk's replay a message is about.
///
/// Three bare `usize` in a row transpose in silence and all three decide what the receiver does.
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

/// `MLE_RECORD_DIGEST=1` logs a per-field digest of every replayed record, so two runs can be
/// diffed. Read once: a schedule that changed mid-run would make the diff meaningless.
static RECORD_DIGEST: std::sync::LazyLock<bool> =
    std::sync::LazyLock::new(|| std::env::var("MLE_RECORD_DIGEST").is_ok_and(|v| v == "1"));

/// Send one record on, logging its digests first when the equivalence gate is armed.
fn emit_record(
    tx: &crossbeam::channel::Sender<Msg>,
    batch_idx: usize,
    record: EmulationRecord,
    done: bool,
) {
    if *RECORD_DIGEST {
        for (field, len, hash) in field_digests(&record) {
            // Say which rows are allowed to differ, or whoever diffs two runs chases one that is.
            let note = if is_compared(field) {
                ""
            } else {
                " reported-only"
            };
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
    .expect("the sequencer receives until every worker is gone");
}

/// Holds a chunk's segment records until every segment is in, then folds them into one.
#[derive(Default)]
struct SegmentCollector {
    pending: Mutex<HashMap<usize, PendingChunk>>,
}

#[derive(Default)]
struct PendingChunk {
    records: Vec<Option<EmulationRecord>>,
    seen: Vec<bool>,
    arrived: usize,
}

impl SegmentCollector {
    /// Hand in one segment. `Some` once the whole chunk is in — the folded record, or `None`
    /// inside it if no segment produced a chunk record at all.
    fn submit(
        &self,
        segment: SegmentId,
        record: Option<EmulationRecord>,
    ) -> Option<Option<EmulationRecord>> {
        let complete = {
            // Recovered rather than propagated. Every point below that can panic leaves the map
            // completable — the assertions precede the writes, and a fresh entry trips neither —
            // so `expect` here would only bury the first panic's message under one per worker.
            let mut pending = self.pending.lock().unwrap_or_else(PoisonError::into_inner);
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

/// A replay's emulator, whose snapshot memory is released however the replay ends. If a replay
/// unwound with a pool block, a snapshot thread waiting on the pool for it would never wake.
struct Replay<'a, SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>,
{
    emu: MetaEmulator<SC, C, Program, Vec<u8>, RiscvEmulator>,
    run: &'a RunControl,
    pooled: bool,
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
        if let Some(emulator) = self.emu.emulator.take() {
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

fn run_snapshot_main_loop<E: SnapshotEmulator>(
    emu: &mut E,
    snap_tx: &crossbeam::channel::Sender<Snapshot>,
    emu_result: &mut Result<(), EmulationError>,
    total_cycles: &mut u64,
    output_pv_stream: &mut Vec<u8>,
    run: &RunControl,
) {
    let mut batch_idx = 0;
    loop {
        // A failed run returns no more memory, so every further batch is a step towards a pool
        // that stays empty. What the run produced is discarded; the failure is the result.
        if run.is_aborted() {
            break;
        }
        let t_batch_start = Instant::now();
        let (segments, report) = match emu.next_state_batch_segments() {
            Ok(res) => res,
            Err(err) => {
                *emu_result = Err(err);
                break;
            }
        };
        let done = report.done;
        let batch_dur = t_batch_start.elapsed();

        let t_send_start = Instant::now();
        let emu_cycles = emu.cycles();
        let count = segments.len();
        for (index, (snapshot, target)) in segments.into_iter().enumerate() {
            let segment = SegmentId {
                batch: batch_idx,
                index,
                count,
            };
            snap_tx
                .send((segment, snapshot, done, target))
                .expect("the pipeline holds the queue's receiver until the snapshot thread ends");
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
            "batch finished"
        );

        if done {
            *total_cycles = emu_cycles;
            *output_pv_stream = emu.get_pv_stream();
            break;
        }
        batch_idx += 1;
    }
}

/// Batch from which the deferred pool starts being split out. gpu-base doubles this under its
/// `two-round-chunks` feature, which this branch does not declare.
const DYNAMIC_CHUNK_START: u32 = 16;

/// Where the sequencer starts splitting the deferred pool into records of their own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeferredSplit {
    /// From chunk 16 on, and at the end: the chunk sequence gpu-base's pipeline produces, which
    /// [`emulate_snapshot_pipeline`] keeps.
    FromChunk16,
    /// After every chunk, as `emulate_with_opts` splits, so a block that fills early comes out at
    /// the same place and the run's records can stand in for the interpreter's in a proof.
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
    // Only the AOT snapshot thread cuts a chunk into segments.
    #[cfg(feature = "aot-emulator")]
    let segments = (snapshot_main == SnapshotMainMode::Aot
        && crate::emulator::aot::split_chunks() > 0)
        .then(|| crate::emulator::aot::split_segments() as usize);
    #[cfg(not(feature = "aot-emulator"))]
    let segments = {
        let _ = snapshot_main;
        None
    };
    match memory_pool_refusal(memory_pool_capacity(), memory_recycler_threads(), segments) {
        Some(reason) => Err(EmulationError::PipelineMemoryPool(reason)),
        None => Ok(()),
    }
}

/// Why a pool that ever holds `capacity` memories, with `recyclers` threads returning them, can
/// never serve a run whose AOT batches are cut into `segments`, if it cannot.
fn memory_pool_refusal(
    capacity: usize,
    recyclers: usize,
    segments: Option<usize>,
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
    // A batch cut into segments holds one memory for each until it has cut them all.
    match segments {
        Some(segments) if segments > capacity => Some(format!(
            "the AOT snapshot thread cuts a chunk into {segments} segments and holds a memory for \
             each, and the pool never holds more than {capacity}"
        )),
        _ => None,
    }
}

/// [`emulate_snapshot_pipeline_with`], with the worker count read from `NUM_THREADS` (unset or
/// `0`: one).
pub fn emulate_snapshot_pipeline<SC, C, F>(
    witness: &ProvingWitness<SC, C, Vec<u8>>,
    handle_record: F,
) -> Result<(Vec<EmulationReport>, u64, Vec<u8>), EmulationError>
where
    SC: 'static + StarkGenericConfig + Send + Sync,
    SC::Val: PrimeField32 + FieldSpecificPoseidon2Config,
    C: 'static + ChipBehavior<Val<SC>, Program = Program, Record = EmulationRecord>,
    F: Fn(EmulationRecord, bool) + Send + Sync + 'static,
{
    let workers = std::env::var("NUM_THREADS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .and_then(NonZeroUsize::new)
        .unwrap_or(NonZeroUsize::MIN);
    emulate_snapshot_pipeline_with(witness, workers, DeferredSplit::FromChunk16, handle_record)
}

/// Emulate `witness` with one snapshot thread, the interpreter or AOT code as
/// `witness.opts.snapshot_main` says, and `workers` interpreters replaying its snapshots into
/// records. `handle_record` gets them in chunk order, each with the run's `done` flag; the result
/// is the reports in the order the workers finished, the snapshot thread's cycle count and the
/// committed bytes.
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
    let opts = witness.opts.as_ref().expect("witness.opts not set");
    let split_opts = opts.split_opts;
    // A batch of more than one chunk drops most of its own precompile events without a word
    // (see `chunk_batch_size`), and the code reads the same either way -- so refuse to start.
    assert_eq!(
        opts.chunk_batch_size, 1,
        "the deferred split needs one chunk per batch; set CHUNK_BATCH_SIZE=1"
    );
    check_pipeline(workers, opts.snapshot_main)?;

    let num_threads = workers.get();
    info!("Emulator snapshot worker threads: {}", num_threads);

    // Only the AOT snapshot thread hands out pool memories for the workers to return.
    #[cfg(not(test))]
    let pooled = opts.snapshot_main == SnapshotMainMode::Aot;
    #[cfg(test)]
    let pooled = opts.snapshot_main == SnapshotMainMode::Aot
        || hooks::DRAW_POOL_BLOCK_PER_BATCH.load(Ordering::Relaxed);

    let (snap_tx, snap_rx) = bounded::<Snapshot>(256);
    let (snapshot_msg_tx, snapshot_msg_rx) = unbounded::<Msg>();

    let program = witness.program.as_ref().unwrap();
    let shared_ds: SharedDeferredState =
        Arc::new(Mutex::new(EmulationDeferredState::new(program.clone())));

    // Holds a split chunk's segment records until the last one lands.
    let collector = SegmentCollector::default();

    let mut emu_result = Ok(());
    let mut total_cycles = 0u64;
    let mut pv_stream: Vec<u8> = Vec::new();
    let reports = Mutex::new(Vec::new());
    let run = RunControl::default();

    let replay_one = |tid: usize,
                      (segment, snapshot, done, target_clk): Snapshot,
                      snapshot_msg_tx: &Sender<Msg>,
                      shared_ds: &SharedDeferredState| {
        let batch_idx = segment.batch;
        let t_recover_and_emu = Instant::now();
        let mut replay = Replay {
            emu: MetaEmulator::recover_riscv(
                witness,
                snapshot,
                None,
                shared_ds.clone(),
                target_clk,
                segment.is_final(),
            ),
            run: &run,
            pooled,
        };
        #[cfg(test)]
        if hooks::PANIC_IN_FIRST_REPLAY.swap(false, Ordering::Relaxed) {
            panic!("injected replay panic");
        }
        let t_record_batch = Instant::now();
        let mut chunk_record = None;
        let replayed = replay.emu.try_next_record_batch(&mut |rec| {
            // Every record a replay hands back here is the chunk's own: the deferred and
            // precompile ones are split out downstream, in the sequencer. So a split
            // chunk holds all of them, and a segment can produce at most one — a segment
            // that produced none is normal, and the collector counts hand-ins for it. The
            // `is_cpu_chunk` test therefore always holds here; it says what the fold is
            // about, and keeps a deferred record out of it should one ever arrive.
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
        let record_batch_ms = t_record_batch.elapsed().as_secs_f64() * 1000.0;
        info!(
            target = "bench",
            "[bench][emulator-{tid}](chunk-{batch_idx}) emulator: running={record_batch_ms:.3} ms"
        );
        // One report per chunk, as before the replay could be split: a middle segment's
        // report describes a piece of a chunk, and the consumers count on there being
        // exactly one per chunk.
        if segment.is_final() {
            reports
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(report);
        }
        // The chunk is finished once every segment is in — which is not necessarily the
        // last one to start, so whichever completes the fold announces it.
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
    // the snapshot thread's memory restore is a rayon job, so workers holding every rayon thread
    // would leave that job nowhere to run. A worker outlives a failed replay and keeps draining
    // the queue: the snapshots on it hold pool memories that the snapshot thread may be waiting on.
    let replay_snapshots = |tid: usize,
                            snap_rx: Receiver<Snapshot>,
                            snapshot_msg_tx: Sender<Msg>,
                            shared_ds: SharedDeferredState| {
        while let Ok(snapshot) = snap_rx.recv() {
            if run.is_aborted() {
                release(snapshot.1.memory, pooled);
                continue;
            }
            run.guard(|| replay_one(tid, snapshot, &snapshot_msg_tx, &shared_ds));
        }
    };

    thread::scope(|s| {
        // sequencer
        s.spawn({
            let shared_ds = Arc::clone(&shared_ds);
            let run = &run;
            let handle_record = &handle_record;
            move || {
                let mut stash: BTreeMap<u32, Bucket> = BTreeMap::new();
                let mut next = 0u32;

                // Received to the end even after a failure, so a live worker's send never fails,
                // but nothing more reaches the caller: the run's result is the failure.
                while let Ok(msg) = snapshot_msg_rx.recv() {
                    if run.is_aborted() {
                        continue;
                    }
                    run.guard(|| {
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

                        // TODO: handle disorder records (get pvs by snapshot main)
                        while let Some(bkt) = stash.get(&next) {
                            if !bkt.finished {
                                break;
                            }
                            let Bucket { mut recs, .. } = stash.remove(&next).unwrap();

                            for (mut rec, done_flag) in recs.drain(..) {
                                let rec_mut = Arc::make_mut(&mut rec);
                                let mut ds = shared_ds.lock().unwrap();
                                ds.update_public_values(done_flag, rec_mut);

                                handle_record(Arc::try_unwrap(rec).unwrap(), done_flag);

                                // Before that batch the events stay in the pool: an early batch
                                // would otherwise emit a tail record of its own, and the chunk
                                // sequence would stop matching the one gpu-base produces.
                                let splits = if deferred_split.splits_after(next) || done_flag {
                                    ds.take_split_records(done_flag, split_opts, next)
                                } else {
                                    Vec::new()
                                };

                                for mut split_rec in splits {
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
        s.spawn({
            let run = &run;
            let emu_result = &mut emu_result;
            let total_cycles = &mut total_cycles;
            let pv_stream = &mut pv_stream;
            move || {
                run.guard(|| {
                    let t_snapshot_main = Instant::now();

                    let run_interp =
                        |emu_result: &mut _, total_cycles: &mut _, pv_stream: &mut _| {
                            let mut emu = MetaEmulator::setup_riscv(witness, None);
                            emu.set_cost_estimator(false);
                            run_snapshot_main_loop(
                                &mut emu,
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
                            info!(
                                "[AOT] snapshot-main = AotMetaEmulator (running AOT-compiled \
                                 chunks)"
                            );
                            let mut emu = AotMetaEmulator::<SC, C>::setup_riscv(witness);
                            run_snapshot_main_loop(
                                &mut emu,
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
                thread::Builder::new()
                    .name(format!("snapshot-replay-{tid}"))
                    .spawn_scoped(s, move || {
                        replay_snapshots(tid, snap_rx, snapshot_msg_tx, shared_ds)
                    })
                    .expect("spawn a replay worker")
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
    /// The pool is one memory. In the failing runs the snapshot thread draws it the way the AOT
    /// thread does, so the run moves in lockstep with its one worker and a memory a failed replay
    /// kept stops it for good.
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
            &[("MEMORY_POOL_SIZE", "1")],
            Duration::from_secs(180),
            "the pipeline hung on a failure",
            MARKER,
        );
    }

    #[test]
    fn a_pool_that_can_never_serve_the_run_is_named() {
        assert_eq!(memory_pool_refusal(16, 4, None), None);
        assert_eq!(
            memory_pool_refusal(16, 4, Some(16)),
            None,
            "exactly full is served"
        );
        assert!(memory_pool_refusal(0, 4, None).is_some_and(|r| r.contains("never holds")));
        assert!(memory_pool_refusal(16, 0, None)
            .is_some_and(|r| r.contains("MEMORY_RECYCLER_THREADS=0")));
        assert!(memory_pool_refusal(8, 4, Some(9)).is_some_and(|r| r.contains("9 segments")));
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
