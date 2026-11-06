//! Snapshot-based RISC-V emulation pipeline: a sequencer takes emulator snapshots, worker threads
//! replay them into `EmulationRecord`s, and the caller consumes the records through a callback.
//! The FRI `RiscvProver` that used to drive proving from here was removed with the FRI path (tag
//! `legacy-fri-last`); the MLE prover (`mle::machine::riscv`) consumes this pipeline instead, and
//! `mle::machine::riscv::emulate_with_pipeline` maps a run of it onto the `EmulationOutput` that
//! `emulate_with_opts` returns, so the host prover can take its records.

#[cfg(feature = "aot-emulator")]
use crate::emulator::emulator::{AotMetaEmulator, AotReplayMetaEmulator};
use crate::emulator::{
    opts::{EmulatorOpts, ReplayWorkers, SnapshotMainMode},
    riscv::record_merge::merge_segments,
};
use crate::{
    compiler::riscv::program::Program,
    configs::config::{StarkGenericConfig, Val},
    emulator::{
        emulator::MetaEmulator,
        record::RecordBehavior,
        riscv::{
            emulator::{
                DeferredChunkPc, EmulationDeferredState, EmulationError, SharedDeferredState,
            },
            history::ExecutionHistory,
            history_arena::{GrantOrder, GrantTicket, Table},
            memory::{
                init_memory_pool, memory_pool_capacity, memory_recycler_threads,
                raise_pool_size_floor, ContiguousRiscvMemory, GLOBAL_MEMORY_RECYCLER,
            },
            public_values::RecordFinalPvsState,
            record::EmulationRecord,
            record_digest::{
                field_digests, is_compared, record_bytes, record_streams, restamp_public_values,
                FieldDigest,
            },
            record_slots::{bound_in_force, SLOTS_VAR},
            riscv_emulator::RiscvEmulator,
            state::RiscvEmulationState,
        },
        snapshot::{SnapshotCounters, SnapshotEmulator},
    },
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::{
        chip::ChipBehavior, field::FieldSpecificPoseidon2Config, report::EmulationReport,
        witness::ProvingWitness,
    },
    // Both instruments are inert unless a driver opened a window (`ledger::open_window`, which
    // only `emulate_with_pipeline` does) or called `spans::set_origin` (the distributed driver):
    // with neither, a span guard and a ledger hook record nothing.
    mle::{
        ledger::{self, At},
        spans::{self, LaneId, Role, WorkKind},
    },
};
use alloc::sync::Arc;
use core_affinity;
use crossbeam::channel::{bounded, unbounded, Receiver, Sender};
use p3_field::PrimeField32;
use parking_lot::Mutex as ParkingMutex;
use serde_json::json;
use std::{
    any::Any,
    collections::{BTreeMap, HashMap},
    num::NonZeroUsize,
    panic::{self, AssertUnwindSafe},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Mutex, PoisonError,
    },
    thread,
    time::{Duration, Instant},
};
use tracing::{debug, info, warn};

/// Failures and delays only a test can arrange. Process-wide, so only the child process a test
/// spawns sets them.
#[cfg(test)]
mod hooks {
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

    /// The next replay panics.
    pub(super) static PANIC_IN_FIRST_REPLAY: AtomicBool = AtomicBool::new(false);

    /// The next replay returns an error.
    pub(super) static ERROR_IN_FIRST_REPLAY: AtomicBool = AtomicBool::new(false);

    /// The next replay on an emulator recovered in place returns an error.
    pub(super) static ERROR_IN_FIRST_IN_PLACE_REPLAY: AtomicBool = AtomicBool::new(false);

    /// The snapshot thread takes one pool block per batch and drops it. The AOT snapshot thread
    /// hands each batch's block to the worker, so a dead worker drains the pool; the interpreter
    /// returns its own, and without this it cannot show that hang.
    pub(super) static DRAW_POOL_BLOCK_PER_BATCH: AtomicBool = AtomicBool::new(false);

    /// The replay of this batch waits, once, until the two batches after it have replayed, as a
    /// slow recovery or a descheduled worker would hold it; `usize::MAX` names none.
    pub(super) static LATE_BATCH: AtomicUsize = AtomicUsize::new(usize::MAX);

    /// The batches below 64 whose replay has returned, a bit each.
    static REPLAYED: AtomicU64 = AtomicU64::new(0);

    pub(super) fn replayed(batch: usize) {
        if batch < 64 {
            REPLAYED.fetch_or(1 << batch, Ordering::Relaxed);
        }
    }

    /// Whether the two batches after `batch`, below 62, have replayed.
    pub(super) fn next_two_replayed(batch: usize) -> bool {
        let both = 0b11 << (batch + 1);
        REPLAYED.load(Ordering::Relaxed) & both == both
    }
}

pub type RiscvChips<SC> = RiscvChipType<Val<SC>>;

pub enum Msg {
    Record {
        chunk: u32,
        rec: Arc<EmulationRecord>,
        done: bool,
        /// The record's digests under `MLE_RECORD_DIGEST`, taken by the worker before the
        /// sequencer stamps the public values.
        digests: Option<Vec<FieldDigest>>,
    },
    SnapShotDone {
        chunk: u32,
    },
}

pub struct Bucket {
    pub(crate) recs: Vec<(Arc<EmulationRecord>, bool, Option<Vec<FieldDigest>>)>,
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

/// `MLE_RECORD_DIGEST=1` logs a per-field digest of every record the pipeline hands on, so two runs
/// can be diffed. Logged by the sequencer after it stamps the public values, and keyed by the
/// stamped chunk index, so the records split out of the deferred pool and the public values are in
/// it too. A chunk record's digests are taken by its worker, in parallel and off every lock, and
/// only the public-values row is redone once stamped; a worker hands its records on after the
/// replay rather than as they come, inside `worker.fold`. Read once: a schedule that changed mid-run
/// would make the diff meaningless.
static RECORD_DIGEST: std::sync::LazyLock<bool> =
    std::sync::LazyLock::new(|| std::env::var("MLE_RECORD_DIGEST").is_ok_and(|v| v == "1"));

fn log_record_digests(record: &EmulationRecord, digests: &[FieldDigest]) {
    let chunk = record.chunk_index();
    for &(field, len, hash) in digests {
        // Say which rows are allowed to differ, or whoever diffs two runs chases one that is.
        let note = if is_compared(field) {
            ""
        } else {
            " reported-only"
        };
        info!(
            target: "bench",
            "[recdigest] chunk={chunk} {field} len={len} hash={hash:#018x}{note}"
        );
    }
}

/// Send one record on to the sequencer.
fn emit_record(
    tx: &crossbeam::channel::Sender<Msg>,
    batch_idx: usize,
    record: EmulationRecord,
    done: bool,
) {
    let digests = RECORD_DIGEST.then(|| field_digests(&record));
    tx.send(Msg::Record {
        chunk: batch_idx as u32,
        rec: Arc::new(record),
        done,
        digests,
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

/// One replay snapshot as the snapshot thread queues it: which segment, the state to start from,
/// the run's `done` flag, the global clock to stop at, and its place in the order the run's
/// histories take their slots in.
type Snapshot = (SegmentId, RiscvEmulationState, bool, u64, GrantTicket);

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
    /// The order the run's histories take their slots in, closed by the first failure: a failed run
    /// hands nothing more on, and no take should wait for its turn behind it.
    grants: Arc<GrantOrder>,
}

impl RunControl {
    fn abort(&self) {
        self.aborted.store(true, Ordering::Release);
        self.grants.close();
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

/// A replay worker's emulator, kept in its slot across batches: the interpreter, or the AOT core
/// when `replay_workers` asks for it.
enum WorkerEmulator<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>,
{
    Interpreter(Box<MetaEmulator<SC, C, Program, Vec<u8>, RiscvEmulator>>),
    #[cfg(feature = "aot-emulator")]
    Aot(AotReplayMetaEmulator<SC, C>),
}

impl<SC, C> WorkerEmulator<SC, C>
where
    SC: StarkGenericConfig,
    SC::Val: PrimeField32 + FieldSpecificPoseidon2Config,
    C: ChipBehavior<Val<SC>, Program = Program, Record = EmulationRecord>,
{
    /// A worker's first batch: an emulator of `engine`'s kind, recovered from `snapshot`.
    fn recover(
        engine: ReplayWorkers,
        witness: &ProvingWitness<SC, C, Vec<u8>>,
        snapshot: RiscvEmulationState,
        shared_ds: SharedDeferredState,
        target_clk: u64,
        final_segment: bool,
    ) -> Self {
        match engine {
            ReplayWorkers::Interpreter => Self::Interpreter(Box::new(MetaEmulator::recover_riscv(
                witness,
                snapshot,
                shared_ds,
                target_clk,
                final_segment,
            ))),
            #[cfg(feature = "aot-emulator")]
            ReplayWorkers::Aot => Self::Aot(AotReplayMetaEmulator::recover_riscv(
                witness,
                snapshot,
                shared_ds,
                target_clk,
                final_segment,
            )),
            #[cfg(not(feature = "aot-emulator"))]
            ReplayWorkers::Aot => {
                unreachable!("check_pipeline refuses AOT replay workers without aot-emulator")
            }
        }
    }

    /// Recovers from `snapshot` in place. Returns the previous state's memory.
    fn recover_in_place(
        &mut self,
        snapshot: RiscvEmulationState,
        shared_ds: SharedDeferredState,
        target_clk: u64,
        final_segment: bool,
    ) -> ContiguousRiscvMemory {
        match self {
            Self::Interpreter(emu) => {
                emu.recover_riscv_in_place(snapshot, shared_ds, target_clk, final_segment)
            }
            #[cfg(feature = "aot-emulator")]
            Self::Aot(emu) => {
                emu.recover_riscv_in_place(snapshot, shared_ds, target_clk, final_segment)
            }
        }
    }

    fn try_next_record_batch<F>(
        &mut self,
        record_callback: &mut F,
    ) -> Result<EmulationReport, EmulationError>
    where
        F: FnMut(EmulationRecord),
    {
        match self {
            Self::Interpreter(emu) => emu.try_next_record_batch(record_callback),
            #[cfg(feature = "aot-emulator")]
            Self::Aot(emu) => emu.try_next_record_batch(record_callback),
        }
    }

    /// The ledger's `worker_kind`.
    fn kind(&self) -> &'static str {
        match self {
            Self::Interpreter(_) => "interpreter",
            #[cfg(feature = "aot-emulator")]
            Self::Aot(_) => "aot",
        }
    }

    /// The AOT core's counters so far; none for an interpreter.
    fn aot_counters(&self) -> Option<AotCounters> {
        match self {
            Self::Interpreter(_) => None,
            #[cfg(feature = "aot-emulator")]
            Self::Aot(emu) => Some(AotCounters {
                dispatches: emu.compiled_block_dispatches(),
                fallback_insns: emu.fallback_insns(),
                recorder_dispatches: emu.recorder_body_dispatches(),
                recorder_insns: emu.recorder_body_insns(),
                recorder_direct_insns: emu.recorder_direct_insns(),
            }),
        }
    }
}

/// An AOT replay worker's counters, cumulative over its replays.
#[derive(Clone, Copy)]
#[cfg_attr(not(feature = "aot-emulator"), allow(dead_code))]
struct AotCounters {
    dispatches: u64,
    fallback_insns: u64,
    recorder_dispatches: u64,
    recorder_insns: u64,
    recorder_direct_insns: u64,
}

impl AotCounters {
    fn since(self, before: Self) -> Self {
        Self {
            dispatches: self.dispatches - before.dispatches,
            fallback_insns: self.fallback_insns - before.fallback_insns,
            recorder_dispatches: self.recorder_dispatches - before.recorder_dispatches,
            recorder_insns: self.recorder_insns - before.recorder_insns,
            recorder_direct_insns: self.recorder_direct_insns - before.recorder_direct_insns,
        }
    }
}

impl<SC, C> WorkerEmulator<SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>,
{
    /// Puts `memory` in place of the one the emulator runs on, and returns that one.
    fn replace_memory(&mut self, memory: ContiguousRiscvMemory) -> ContiguousRiscvMemory {
        match self {
            Self::Interpreter(emu) => {
                let state = &mut emu.emulator.as_mut().expect("a worker's emulator").state;
                std::mem::replace(&mut state.memory, memory)
            }
            #[cfg(feature = "aot-emulator")]
            Self::Aot(emu) => emu.replace_memory(memory),
        }
    }

    /// The memory the emulator runs on, the emulator given up for it.
    fn into_memory(self) -> Option<ContiguousRiscvMemory> {
        match self {
            Self::Interpreter(mut emu) => emu.emulator.take().map(|emulator| emulator.state.memory),
            #[cfg(feature = "aot-emulator")]
            Self::Aot(emu) => Some(emu.into_memory()),
        }
    }
}

/// A worker's emulator for the length of one replay, whose snapshot memory is released however the
/// replay ends. If a replay unwound with a pool block, a snapshot thread waiting on the pool for it
/// would never wake.
struct Replay<'a, SC, C>
where
    SC: StarkGenericConfig,
    C: ChipBehavior<Val<SC>>,
{
    emu: Option<WorkerEmulator<SC, C>>,
    /// The memory the emulator's state holds while it waits in the worker's slot. The worker's own
    /// allocation, so it is never released to the pool.
    spare: Option<ContiguousRiscvMemory>,
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

    /// The emulator back for the worker's next batch, its batch's memory released.
    fn finish(mut self) -> Option<WorkerEmulator<SC, C>> {
        // Allocated while the replay still owns the emulator: a panic here unwinds through the
        // drop, which releases the block rather than freeing it.
        let spare = self.spare.take().unwrap_or_default();
        let mut emu = self.emu.take()?;
        // An idle worker must not hold a pool block: the snapshot thread blocks on an empty pool,
        // and the block would come back only with this worker's next batch.
        release(emu.replace_memory(spare), self.pooled);
        Some(emu)
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
        if let Some(memory) = self.emu.take().and_then(WorkerEmulator::into_memory) {
            release(memory, self.pooled);
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
        while let Ok((_, snapshot, ..)) = self.queue.recv() {
            release(snapshot.memory, self.pooled);
        }
    }
}

// allow: domain-complex signature; each arg is an independent handle/config
#[allow(clippy::too_many_arguments)]
fn run_snapshot_main_loop<E, NextBatch, Cycles, Counters, PvStream>(
    emu: &mut E,
    engine: SnapshotMainMode,
    mut next_batch: NextBatch,
    cycles: Cycles,
    counters: Counters,
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
    Counters: Fn(&E) -> SnapshotCounters,
    PvStream: FnMut(&mut E) -> Vec<u8>,
{
    let lane = LaneId::new(Role::Snapshot, 0);
    let mut batch_idx = 0;
    loop {
        // A failed run returns no more memory, so every further batch is a step towards a pool
        // that stays empty. What the run produced is discarded; the failure is the result.
        if run.is_aborted() {
            break;
        }
        let cycles_before = cycles(emu);
        // The AOT emulator's counters are a call into it, made for the ledger alone.
        let counters_before = ledger::active().then(|| counters(emu));
        let t_batch_start = Instant::now();
        let (segments, report) = {
            let _b = spans::busy(WorkKind::Snapshot, Some(batch_idx as u32));
            let context = ledger::Context {
                lane: lane.into(),
                at: At::batch(batch_idx, None),
            };
            match ledger::with_context(context, || next_batch(emu)) {
                Ok(res) => res,
                Err(err) => {
                    *emu_result = Err(err);
                    break;
                }
            }
        };
        let done = report.done;
        let batch_dur = t_batch_start.elapsed();
        let timers = ledger::take_timers();

        let t_send_start = Instant::now();
        let emu_cycles = cycles(emu);
        let count = segments.len();
        if let Some(counters_before) = &counters_before {
            let counters = counters(emu).since(counters_before);
            ledger::stage(
                "snapshot.emulate",
                At::batch(batch_idx, None),
                lane,
                t_batch_start,
                t_batch_start + batch_dur,
                || {
                    let mut facts = json!({
                        "cycles_delta": emu_cycles - cycles_before,
                        "segments": count,
                        "snapshot_main": snapshot_main_name(engine),
                        "dispatches_delta": counters.dispatches,
                        "cycles_per_dispatch": counters
                            .dispatches
                            .filter(|&d| d > 0)
                            .map(|d| (emu_cycles - cycles_before) as f64 / d as f64),
                        "memory_source": "pooled",
                        "pool_returns": pool_returns(engine),
                        "prestate_entries": counters.prestate_entries,
                        "prestate_bytes": counters.prestate_bytes,
                        "first_touch_loads": counters.first_touch_loads,
                        "first_touch_partial_stores": counters.first_touch_partial_stores,
                        "first_touch_full_stores": counters.first_touch_full_stores,
                        "first_touch_registers": counters.first_touch_registers,
                    });
                    timers.add_to(&mut facts);
                    facts
                },
            );
        }
        // Read before the sends consume `segments`, and only when the ledger will write them.
        let send_facts = ledger::active().then(|| {
            let input_stream_bytes: usize = segments
                .iter()
                .map(|(snapshot, _)| snapshot.input_stream.iter().map(Vec::len).sum::<usize>())
                .sum();
            (snap_tx.len(), input_stream_bytes)
        });
        {
            // Blocked here means the replay workers have not drained the queue: capacity someone
            // else holds, so `Wait`, not idleness. Normally zero — a non-zero figure means the
            // queue filled, which is a memory-pressure signal.
            let _w = spans::wait(WorkKind::Snapshot, Some(batch_idx as u32));
            for (index, (snapshot, target)) in segments.into_iter().enumerate() {
                let segment = SegmentId {
                    batch: batch_idx,
                    index,
                    count,
                };
                snap_tx
                    .send((segment, snapshot, done, target, run.grants.ticket()))
                    .expect(
                        "the pipeline holds the queue's receiver until the snapshot thread ends",
                    );
            }
        }
        let send_dur = t_send_start.elapsed();
        if let Some((queue_len, input_stream_bytes)) = send_facts {
            ledger::stage(
                "snapshot.send",
                At::batch(batch_idx, None),
                lane,
                t_send_start,
                t_send_start + send_dur,
                || {
                    json!({
                        "queue_len": queue_len,
                        "segments": count,
                        "input_stream_bytes": input_stream_bytes,
                    })
                },
            );
        }
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

/// The snapshot thread's emulator setup: one-time, so it is setup time in the envelope and the
/// phase walls start where it ends, and a stage on the lane, so the lane's head is not an
/// unbracketed gap.
fn snapshot_setup<E>(setup: impl FnOnce() -> E) -> E {
    let t0 = Instant::now();
    let emu = setup();
    let t1 = Instant::now();
    ledger::add_setup(ledger::Setup::EmulatorSetup, t1 - t0);
    ledger::emulation_starts(t1);
    let lane = LaneId::new(Role::Snapshot, 0);
    ledger::stage("snapshot.setup", At::default(), lane, t0, t1, || json!({}));
    emu
}

/// The snapshot thread's end: its emulator, and the memory that still holds, freed.
fn snapshot_finish<E>(emu: E) {
    let t0 = Instant::now();
    drop(emu);
    let lane = LaneId::new(Role::Snapshot, 0);
    ledger::stage(
        "snapshot.finish",
        At::default(),
        lane,
        t0,
        Instant::now(),
        || json!({}),
    );
}

fn snapshot_main_name(engine: SnapshotMainMode) -> &'static str {
    match engine {
        SnapshotMainMode::Aot => "aot",
        SnapshotMainMode::Interpreter => "interpreter",
    }
}

/// Who gives a batch's snapshot memory back to the pool. Both snapshot threads take one from it
/// per batch (`build_snapshot_state`, `clone_without_memory`); the AOT one hands it to the replay
/// worker, which returns it, and the interpreter puts its own back.
fn pool_returns(engine: SnapshotMainMode) -> &'static str {
    match engine {
        SnapshotMainMode::Aot => "worker",
        SnapshotMainMode::Interpreter => "snapshot",
    }
}

/// A record's public values the sequencer still has to fold in after emitting it out of order:
/// `is_cpu_chunk`, `start_pc`, `next_pc`, `committed_value_digest`, `deferred_proofs_digest`.
type OooPvs = (bool, [u32; 3], [u32; 3], [u32; 8], [u32; 8]);

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
    /// The first chunk the pool is split out after, `None` when it is split after every chunk.
    pub fn start(self) -> Option<u32> {
        match self {
            Self::FromChunk16 => Some(DYNAMIC_CHUNK_START),
            Self::AfterEveryChunk => None,
        }
    }

    fn splits_after(self, chunk: u32) -> bool {
        self.start().is_none_or(|start| chunk >= start)
    }
}

/// The most replay workers [`emulate_snapshot_pipeline_with`] accepts: one per core. They are
/// threads of their own, so the rayon pool's size does not bound them; past the core count they
/// would only take turns.
pub fn max_pipeline_workers() -> usize {
    core_affinity::get_core_ids().map_or(1, |cores| cores.len())
}

/// Replay workers for a caller that states none: 8, the GPU benchmark script's `NUM_THREADS`, or
/// one per core on a smaller machine. Past it the snapshot thread, not the replay, bounds the run.
pub fn default_pipeline_workers() -> NonZeroUsize {
    NonZeroUsize::new(max_pipeline_workers().min(8)).unwrap_or(NonZeroUsize::MIN)
}

/// Refuses a run the snapshot pipeline could not finish, or could not run as `opts` asks, as
/// [`emulate_snapshot_pipeline_with`] does before any thread starts: more workers than
/// [`max_pipeline_workers`], AOT replay workers it cannot run (see [`replay_workers_refusal`]), a
/// memory pool, as the `MEMORY_POOL_*` and `MEMORY_RECYCLER_THREADS` variables and the AOT split
/// size it, that the snapshot thread would wait on forever, or a bound on records held at once
/// below the AOT split's segments (see [`history_slot_refusal`]). Public so that a caller can
/// refuse before work of its own.
///
/// A pooled run with `MEMORY_POOL_SIZE` unset raises the pool, while it is not yet built, to one
/// memory per worker plus the segments of the batch being cut, so every worker can replay at once:
/// each holds a pool memory while it replays. A smaller pool is not refused; it caps how many
/// workers replay at once, and the first run of the process that meets one says so.
pub fn check_pipeline(workers: NonZeroUsize, opts: &EmulatorOpts) -> Result<(), EmulationError> {
    let cores = max_pipeline_workers();
    if workers.get() > cores {
        return Err(EmulationError::TooManyWorkers {
            workers: workers.get(),
            cores,
        });
    }
    #[cfg(feature = "aot-emulator")]
    let registered = Registered {
        program: crate::emulator::aot::is_aot_factory_registered(),
        replay: crate::emulator::aot::is_aot_replay_factory_registered(),
    };
    #[cfg(not(feature = "aot-emulator"))]
    let registered = Registered {
        program: false,
        replay: false,
    };
    if let Some(reason) = replay_workers_refusal(opts, registered) {
        return Err(EmulationError::UnsupportedReplayWorkers(reason.into()));
    }
    let segments = raise_pool_floor_for(workers, opts.snapshot_main);
    if let Some(reason) = history_slot_refusal(bound_in_force(), segments.unwrap_or(1)) {
        return Err(EmulationError::PipelineHistorySlots(reason));
    }
    let capacity = memory_pool_capacity();
    if let Some(reason) = memory_pool_refusal(capacity, memory_recycler_threads(), segments) {
        return Err(EmulationError::PipelineMemoryPool(reason));
    }
    if let Some(shortfall) = memory_pool_shortfall(capacity, workers, segments) {
        static WARNED: std::sync::Once = std::sync::Once::new();
        WARNED.call_once(|| warn!("{shortfall}"));
    }
    Ok(())
}

/// The replay workers [`emulate_snapshot_pipeline`] runs: `NUM_THREADS`, one when it is unset or
/// `0`. A caller that prepares for that run sizes it with this, so the two cannot differ.
pub fn pipeline_workers_from_env() -> NonZeroUsize {
    crate::mle::env_u32("NUM_THREADS")
        .and_then(|n| NonZeroUsize::new(n as usize))
        .unwrap_or(NonZeroUsize::MIN)
}

/// Raises the size an unset `MEMORY_POOL_SIZE` stands for to one memory per worker plus the
/// segments of the batch being cut, for a run whose snapshot memories come from the pool, and
/// returns those segments.
fn raise_pool_floor_for(workers: NonZeroUsize, snapshot_main: SnapshotMainMode) -> Option<usize> {
    let segments = pooled_segments(snapshot_main);
    if let Some(segments) = segments {
        raise_pool_size_floor(workers.get() + segments);
    }
    segments
}

/// Builds the memory pool ahead of a run of `workers` workers whose snapshot thread is
/// `snapshot_main`, at the size [`check_pipeline`] gives it. A pool keeps the size it was built
/// at, so one built before the first run's check, as a prewarm builds it, is sized here or stays
/// at the unraised size.
pub fn init_memory_pool_for(workers: NonZeroUsize, snapshot_main: SnapshotMainMode) {
    raise_pool_floor_for(workers, snapshot_main);
    init_memory_pool();
}

/// Why a pool that ever holds `capacity` memories keeps some of `workers` workers from replaying
/// while a batch is cut into `segments`, if it does: each worker holds a memory while it replays,
/// and the batch holds one per segment.
fn memory_pool_shortfall(
    capacity: usize,
    workers: NonZeroUsize,
    segments: Option<usize>,
) -> Option<String> {
    let segments = segments?;
    let needed = workers.get() + segments;
    (capacity < needed).then(|| {
        format!(
            "the memory pool holds at most {capacity} memories, fewer than the {needed} this run \
             replays with ({} workers and a batch cut into {segments} segments), so fewer workers \
             replay at once; MEMORY_POOL_SIZE sets the cap",
            workers.get()
        )
    })
}

/// Replay segments per chunk of a run whose snapshot thread is `snapshot_main`: more than one only
/// where the AOT split replay cuts the leading chunks.
pub fn chunk_segments(snapshot_main: SnapshotMainMode) -> usize {
    pooled_segments(snapshot_main).unwrap_or(1)
}

/// How many pool memories each batch of a run takes, if its snapshot memories come from the pool:
/// only the AOT snapshot thread hands them out, one per segment it cuts.
fn pooled_segments(snapshot_main: SnapshotMainMode) -> Option<usize> {
    #[cfg(feature = "aot-emulator")]
    let segments = (snapshot_main == SnapshotMainMode::Aot).then(|| {
        if crate::emulator::aot::splits_any_batch() {
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

/// The AOT factories this process holds.
#[derive(Clone, Copy)]
struct Registered {
    /// The snapshot thread's, which any registered program installs.
    program: bool,
    /// The replay workers', which only a program with a recording entry point installs.
    replay: bool,
}

/// Why the pipeline cannot run the replay workers `opts` asks for, if it cannot. An AOT worker
/// keeps neither a cycle tracker nor a cost estimate, so a run asking for either would come back
/// without it.
fn replay_workers_refusal(opts: &EmulatorOpts, registered: Registered) -> Option<&'static str> {
    if opts.replay_workers == ReplayWorkers::Interpreter {
        None
    } else if opts.snapshot_main != SnapshotMainMode::Aot {
        Some("they replay the AOT snapshot thread's snapshots: set snapshot_main = Aot")
    } else if !registered.program {
        Some("no AOT program is registered in this process")
    } else if !registered.replay {
        Some(
            "the registered AOT program has no recording entry point, which the AOT replay \
             workers run: regenerate it from the guest's ELF with `cargo pico aot`",
        )
    } else if opts.cycle_tracker {
        Some("an AOT worker keeps no cycle tracker: turn cycle_tracker off")
    } else if opts.cost_estimator {
        Some("an AOT worker makes no cost estimate: turn cost_estimator off")
    } else {
        None
    }
}

/// Why a process holding at most `bound` records at once can never finish a run whose chunks are
/// cut into `segments` segments, if it cannot. Each segment's history holds a slot until the last
/// of its chunk's segments is in and they fold, so a chunk needs that many slots at once; the
/// chunks before it free theirs, since slots are granted in chunk order.
pub fn history_slot_refusal(
    bound: Result<Option<NonZeroUsize>, String>,
    segments: usize,
) -> Option<String> {
    match bound {
        Err(reason) => Some(reason),
        Ok(Some(slots)) if slots.get() < segments => Some(format!(
            "the AOT snapshot thread cuts a chunk into {segments} segments, each holding a history \
             slot until the chunk is whole, and the process holds at most {slots} ({SLOTS_VAR})"
        )),
        Ok(_) => None,
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
    emulate_snapshot_pipeline_with(
        witness,
        pipeline_workers_from_env(),
        DeferredSplit::FromChunk16,
        handle_record,
    )
}

/// Emulate `witness` with one snapshot thread, the interpreter or AOT code as
/// `witness.opts.snapshot_main` says, and `workers` workers replaying its snapshots into records,
/// interpreters or the AOT core as `witness.opts.replay_workers` says. `handle_record` gets them
/// with the run's `done` flag; the result is the reports in the order the workers finished, the
/// snapshot thread's cycle count and the committed bytes.
///
/// `deferred_split` says where the deferred pool starts being split into records of their own.
/// A run [`check_pipeline`] refuses is refused with its error before any thread starts. A run that
/// completes logs one `bench` line saying what replayed its chunks and, for AOT workers, how many
/// compiled blocks they entered.
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
    // A batch of more than one chunk drops most of its own precompile events without a word
    // (see `chunk_batch_size`), and the code reads the same either way -- so refuse to start.
    assert_eq!(
        opts.chunk_batch_size, 1,
        "the deferred split needs one chunk per batch; set CHUNK_BATCH_SIZE=1"
    );
    check_pipeline(workers, opts)?;
    crate::mle::heights::begin_pipeline(
        witness.program.as_deref(),
        witness.stdin.as_ref(),
        opts,
        deferred_split,
    );

    init_memory_pool();

    let num_threads = workers.get();
    info!("Emulator snapshot worker threads: {}", num_threads);
    match opts.replay_workers {
        ReplayWorkers::Aot => info!(
            "[AOT] replay workers = AotReplayMetaEmulator (replaying on AOT-compiled recording \
             blocks)"
        ),
        ReplayWorkers::Interpreter => {}
    }

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
    // Totals over every replay of the run, for the `bench` line.
    let replay_dispatches = AtomicU64::new(0);
    let recorder_insns_run = AtomicU64::new(0);

    // One batch on worker `tid`. The emulator in `slot` is reused across batches; the replay owns
    // it meanwhile and only hands it back if the batch completes.
    let replay_one = |tid: usize,
                      slot: &mut Option<WorkerEmulator<SC, C>>,
                      (segment, snapshot, done, global_clk, ticket): Snapshot,
                      snapshot_msg_tx: &Sender<Msg>,
                      shared_ds: &SharedDeferredState| {
        let batch_idx = segment.batch;
        let lane = LaneId::new(Role::Emulate, tid);
        let at = At::batch(batch_idx, Some((segment.index, segment.count)));
        let start_clk = snapshot.global_clk;
        let t_recover_and_emu = Instant::now();
        // The whole batch, not just the replay: the mode switch, the report push, the fold and the
        // completion send are this worker's work too, and the lane's outer span is an idle one, so
        // anything left outside here would read as waiting for input.
        let _batch = spans::busy(WorkKind::Emulate, Some(batch_idx as u32));
        let mut replay = Replay {
            emu: slot.take(),
            spare: None,
            run: &run,
            pooled,
        };
        let recover_kind = {
            // Per-batch setup, kept apart from the replay it precedes: the pipeline's head
            // bubble is where that difference is worth having.
            let _b = spans::busy(WorkKind::EmulateRecover, Some(batch_idx as u32));
            match replay.emu.as_mut() {
                Some(emu) => {
                    // What comes back is the worker's spare, never a pool block: kept, not
                    // released.
                    replay.spare = Some(emu.recover_in_place(
                        snapshot,
                        shared_ds.clone(),
                        global_clk,
                        segment.is_final(),
                    ));
                    "in_place"
                }
                None => {
                    replay.emu = Some(WorkerEmulator::recover(
                        opts.replay_workers,
                        witness,
                        snapshot,
                        shared_ds.clone(),
                        global_clk,
                        segment.is_final(),
                    ));
                    "fresh"
                }
            }
        };
        #[cfg(test)]
        if hooks::PANIC_IN_FIRST_REPLAY.swap(false, Ordering::Relaxed) {
            panic!("injected replay panic");
        }
        let t_record_batch = Instant::now();
        ledger::stage(
            "worker.recover",
            at,
            lane,
            t_recover_and_emu,
            t_record_batch,
            // What a recovery allocates is not observable without an allocator hook, so it is
            // reported as unknown rather than as zero.
            || json!({ "recover_kind": recover_kind, "allocated_bytes": null }),
        );
        let ledger_on = ledger::active();
        // The history's digest reads every row, so it waits for the ledger's digests, and its
        // records are held back like the ones `MLE_RECORD_DIGEST` digests.
        let digest_history = ledger_on && ledger::digests_enabled();
        let mut events: BTreeMap<&'static str, usize> = BTreeMap::new();
        let mut produced_bytes = 0usize;
        let mut history_bytes = None;
        // Per table, the histories that outgrew their arena region; and the histories in a slot.
        let mut spills: BTreeMap<&'static str, usize> = BTreeMap::new();
        let mut in_slot = 0usize;
        let mut produced = 0usize;
        let mut chunk_record = None;
        // Records whose digests are owed: this callback runs under the deferred-state lock the
        // other workers and the sequencer take, so they are digested once the replay returns.
        let mut undigested = Vec::new();
        // The core outlives the batch, so its counters are read around the replay.
        let counted_before = replay.emu().aot_counters();
        let faults_before = ledger_on.then(ledger::thread_page_faults).flatten();
        #[cfg(test)]
        if hooks::LATE_BATCH
            .compare_exchange(batch_idx, usize::MAX, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            // Granted in chunk order, the batches after it cannot replay first: the hold ends once
            // one of them waits for this batch's turn.
            while !hooks::next_two_replayed(batch_idx) && !run.grants.is_awaited() {
                thread::sleep(Duration::from_millis(1));
            }
            let why = if hooks::next_two_replayed(batch_idx) {
                "the next two batches replayed first"
            } else {
                "a later batch waits for its turn"
            };
            eprintln!("[slot-order] batch {batch_idx} replays now: {why}");
        }
        // Counted from here, so a wait before the replay is not its.
        ledger::take_record_slot_waits();
        // The replay's history takes its slot in this turn; the turn ends with the replay, and a
        // replay that took none gives it up there.
        let in_turn = ticket.enter();
        let replayed = replay.emu().try_next_record_batch(&mut |rec| {
            if ledger_on {
                for (stream, len, bytes) in record_streams(&rec) {
                    *events.entry(stream).or_default() += len;
                    produced_bytes += bytes;
                }
                if let Some(history) = &rec.history {
                    *history_bytes.get_or_insert(0) += history.bytes();
                    in_slot += usize::from(history.holds_slot());
                    for table in history.spilled() {
                        *spills.entry(table.name()).or_default() += 1;
                    }
                }
                produced += 1;
            }
            // A split chunk's own record waits for its siblings; the deferred and precompile
            // records a segment splits out stand alone and go now.
            if segment.is_split() && rec.is_cpu_chunk {
                assert!(
                    chunk_record.replace(rec).is_none(),
                    "a replay segment produced two chunk records"
                );
                return;
            }
            if *RECORD_DIGEST || (digest_history && rec.history.is_some()) {
                undigested.push(rec);
            } else {
                emit_record(snapshot_msg_tx, batch_idx, rec, done);
            }
        });
        #[cfg(test)]
        hooks::replayed(batch_idx);
        drop(in_turn);
        let timers = ledger::take_timers();
        let (pool_blocked_gets, pool_blocked) = ledger::take_record_slot_waits();
        #[cfg(test)]
        let replayed = if hooks::ERROR_IN_FIRST_REPLAY.swap(false, Ordering::Relaxed)
            || (recover_kind == "in_place"
                && hooks::ERROR_IN_FIRST_IN_PLACE_REPLAY.swap(false, Ordering::Relaxed))
        {
            Err(EmulationError::illegal_instruction(0))
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
        let record_batch_dur = t_record_batch.elapsed();
        let faults = faults_before.zip(ledger_on.then(ledger::thread_page_faults).flatten());
        let record_batch_ms = record_batch_dur.as_secs_f64() * 1000.0;
        // Excludes the recover step above (`worker.recover`), so it is the replay alone.
        info!(
            target: "bench",
            "[bench][emulator-{tid}](chunk-{batch_idx}) emulator: running={record_batch_ms:.3} ms"
        );
        let worker_kind = replay.emu().kind();
        let counted = replay
            .emu()
            .aot_counters()
            .zip(counted_before)
            .map(|(after, before)| after.since(before));
        let dispatches = counted.map(|counted| counted.dispatches);
        let fallback_insns = counted.map(|counted| counted.fallback_insns);
        let recorder_dispatches = counted.map(|counted| counted.recorder_dispatches);
        let recorder_insns = counted.map(|counted| counted.recorder_insns);
        let recorder_direct_insns = counted.map(|counted| counted.recorder_direct_insns);
        if let Some(dispatches) = dispatches {
            replay_dispatches.fetch_add(dispatches, Ordering::Relaxed);
        }
        if let Some(insns) = recorder_insns {
            recorder_insns_run.fetch_add(insns, Ordering::Relaxed);
        }
        ledger::stage(
            "worker.replay",
            at,
            lane,
            t_record_batch,
            t_record_batch + record_batch_dur,
            || {
                let cycles = global_clk.saturating_sub(start_clk);
                let mut facts = json!({
                    "tid": tid,
                    "cycles": cycles,
                    "records": produced,
                    "events": events,
                    "record_bytes": produced_bytes,
                    "worker_kind": worker_kind,
                    "sink": "history",
                    "dispatches": dispatches,
                    "fallback_insns": fallback_insns,
                    // AOT workers only; with `fallback_insns`, every cycle replayed.
                    "recorder_dispatches": recorder_dispatches,
                    "recorder_insns": recorder_insns,
                    // Of those, the ones whose rows the recording blocks wrote directly.
                    "recorder_direct_insns": recorder_direct_insns,
                    "cycles_per_dispatch": dispatches
                        .filter(|&dispatches| dispatches > 0)
                        .map(|dispatches| cycles as f64 / dispatches as f64),
                });
                if let Some(bytes) = history_bytes {
                    facts["history_bytes"] = json!(bytes);
                    facts["history.in_slot"] = json!(in_slot);
                    facts["history.spills"] = json!(spills);
                }
                if let Some(((minor, major), (minor_after, major_after))) = faults {
                    facts["faults.minor"] = json!(minor_after.saturating_sub(minor));
                    facts["faults.major"] = json!(major_after.saturating_sub(major));
                }
                facts["pool.blocked_gets"] = json!(pool_blocked_gets);
                facts["pool.blocked_us"] = json!(pool_blocked.as_secs_f64() * 1e6);
                timers.add_to(&mut facts);
                if digest_history {
                    let histories: Vec<&ExecutionHistory> = undigested
                        .iter()
                        .chain(&chunk_record)
                        .filter_map(|record| record.history.as_ref())
                        .collect();
                    if !histories.is_empty() {
                        facts["history_digest"] =
                            json!(format!("{:#018x}", ExecutionHistory::digest_all(histories)));
                    }
                }
                facts
            },
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
        let t_fold = Instant::now();
        for rec in undigested {
            emit_record(snapshot_msg_tx, batch_idx, rec, done);
        }
        let mut folded_bytes = None;
        // The folded history's tables that outgrew the first segment's arena region.
        let mut folded_spills: Option<Vec<&'static str>> = None;
        let batch_finished = if segment.is_split() {
            match collector.submit(segment, chunk_record) {
                Some(folded) => {
                    if let Some(record) = folded {
                        if ledger_on {
                            folded_bytes = Some(record_bytes(&record));
                            folded_spills = record
                                .history
                                .as_ref()
                                .map(|history| history.spilled().map(Table::name).collect());
                        }
                        emit_record(snapshot_msg_tx, batch_idx, record, done);
                    }
                    true
                }
                None => false,
            }
        } else {
            true
        };
        let segments_folded = if segment.is_split() && batch_finished {
            segment.count
        } else {
            0
        };
        ledger::stage("worker.fold", at, lane, t_fold, Instant::now(), || {
            json!({
                "segments_folded": segments_folded,
                "record_bytes": folded_bytes,
                "history.spills": folded_spills,
            })
        });
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
        // The snapshot memory goes back here and the emulator to the slot, inside the batch's busy
        // span; named, so a slow release reads as this stage and not as an unbracketed gap.
        let t_drop = Instant::now();
        *slot = replay.finish();
        ledger::stage(
            "worker.drop",
            at,
            lane,
            t_drop,
            Instant::now(),
            || json!({ "pooled": pooled }),
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
        // The spare is the worker's own allocation, not a pool block: freed with the slot, never
        // released.
        drop(slot);
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
                let lane = LaneId::new(Role::Sequencer, 0);
                spans::bind_lane(lane);
                let _lane = spans::idle(WorkKind::Unattributed);
                let mut stash: BTreeMap<u32, Bucket> = BTreeMap::new();
                let mut next = 0u32;
                // When each chunk's completion arrived, so its finalize can say how long it then
                // waited behind the chunks before it.
                let mut done_at: HashMap<u32, Instant> = HashMap::new();
                // Records handed on so far: the index the next one has in the caller's sequence,
                // and so in every proof of the run.
                let mut handed = 0u64;

                // OOO state: saved PV fields for deferred accumulation
                let mut ooo_saved: BTreeMap<u32, Vec<OooPvs>> = BTreeMap::new();

                // Received to the end even after a failure, so a live worker's send never fails,
                // but nothing more reaches the caller: the run's result is the failure.
                loop {
                    let t_wait = Instant::now();
                    let Ok(msg) = snapshot_msg_rx.recv() else {
                        break;
                    };
                    let t_msg = Instant::now();
                    if run.is_aborted() {
                        // Held records keep record slots that a worker still replaying may be
                        // blocked on, so let them go rather than wait to exit.
                        stash.clear();
                        ooo_saved.clear();
                        collector.clear();
                        continue;
                    }
                    let (chunk, message) = match &msg {
                        Msg::Record { chunk, .. } => (*chunk, "record"),
                        Msg::SnapShotDone { chunk } => (*chunk, "done"),
                    };
                    ledger::stage(
                        "sequencer.wait",
                        At::batch(chunk as usize, None),
                        lane,
                        t_wait,
                        t_msg,
                        || json!({ "message": message }),
                    );
                    run.guard(|| {
                        let is_snapshot_done = matches!(&msg, Msg::SnapShotDone { .. });
                        match msg {
                            Msg::Record {
                                chunk,
                                rec,
                                done,
                                digests,
                            } => {
                                stash
                                    .entry(chunk)
                                    .or_insert_with(|| Bucket {
                                        recs: Vec::new(),
                                        finished: false,
                                    })
                                    .recs
                                    .push((rec, done, digests));
                            }

                            Msg::SnapShotDone { chunk } => {
                                done_at.insert(chunk, t_msg);
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
                                    let has_done = bkt.recs.iter().any(|(_, done, _)| *done);
                                    if !has_done {
                                        to_emit_ooo.push(batch);
                                    }
                                }
                            }

                            for batch in to_emit_ooo {
                                let Bucket { mut recs, .. } = stash.remove(&batch).unwrap();
                                let mut saved_fields = Vec::new();

                                for (mut rec, _done_flag, digests) in recs.drain(..) {
                                    let rec_mut = Arc::make_mut(&mut rec);
                                    let orig_pvs = rec_mut.public_values;

                                    // Save fields for deferred PV accumulation
                                    saved_fields.push((
                                        rec_mut.is_cpu_chunk,
                                        orig_pvs.start_pc,
                                        orig_pvs.next_pc,
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
                                        committed_value_digest: orig_pvs.committed_value_digest,
                                        deferred_proofs_digest: orig_pvs.deferred_proofs_digest,
                                        ..Default::default()
                                    };
                                    // exit_code, addr_limbs + empty stay at default (zero) —
                                    // matching sequential

                                    rec_mut.public_values = pvs;
                                    if let Some(mut digests) = digests {
                                        restamp_public_values(&mut digests, rec_mut);
                                        log_record_digests(rec_mut, &digests);
                                    }

                                    // Emit immediately (no splits for first DYNAMIC_CHUNK_START,
                                    // not done_flag)
                                    handle_record(Arc::try_unwrap(rec).unwrap(), false);
                                    handed += 1;
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
                                for (is_cpu, spc, npc, cvd, dpd) in saved {
                                    ds.accumulate_pvs_only(is_cpu, spc, npc, cvd, dpd);
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

                            let t_finalize = Instant::now();
                            let _b = spans::busy(WorkKind::Sequence, Some(next));
                            let first_index = handed;
                            let mut lock_wait = Duration::ZERO;
                            let mut lock_hold = Duration::ZERO;
                            let mut handling = Duration::ZERO;
                            let mut splits_emitted = 0usize;
                            for (mut rec, done_flag, digests) in recs.drain(..) {
                                let rec_mut = Arc::make_mut(&mut rec);
                                let t_lock = Instant::now();
                                let mut ds = shared_ds.lock();
                                let mut t_locked = Instant::now();
                                lock_wait += t_locked - t_lock;
                                ds.update_public_values(
                                    done_flag,
                                    rec_mut,
                                    DeferredChunkPc::LastCpuChunk,
                                );
                                if let Some(mut digests) = digests {
                                    restamp_public_values(&mut digests, rec_mut);
                                    log_record_digests(rec_mut, &digests);
                                }

                                let t_handle = Instant::now();
                                handle_record(Arc::try_unwrap(rec).unwrap(), done_flag);
                                handling += t_handle.elapsed();
                                handed += 1;

                                let mut splits = if deferred_split.splits_after(next) || done_flag {
                                    ds.take_split_records(done_flag, next)
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

                                splits_emitted += splits.len();
                                for mut split_rec in splits.drain(..) {
                                    ds.update_public_values(
                                        done_flag,
                                        &mut split_rec,
                                        DeferredChunkPc::LastCpuChunk,
                                    );
                                    if *RECORD_DIGEST {
                                        // Off the lock the workers take: they only add to the
                                        // deferred pool, which a split already taken no longer
                                        // reads, and the public values are this thread's alone.
                                        drop(ds);
                                        lock_hold += t_locked.elapsed();
                                        log_record_digests(&split_rec, &field_digests(&split_rec));
                                        let t_relock = Instant::now();
                                        ds = shared_ds.lock();
                                        t_locked = Instant::now();
                                        lock_wait += t_locked - t_relock;
                                    }
                                    let t_handle = Instant::now();
                                    handle_record(split_rec, done_flag);
                                    handling += t_handle.elapsed();
                                    handed += 1;
                                }
                                drop(ds);
                                lock_hold += t_locked.elapsed();
                            }
                            drop(_b);
                            let timers = ledger::take_timers();
                            let order_wait = done_at
                                .remove(&next)
                                .map(|t| t_finalize.saturating_duration_since(t));
                            ledger::stage(
                                "sequencer.finalize",
                                At::batch(next as usize, None),
                                lane,
                                t_finalize,
                                Instant::now(),
                                || {
                                    let mut facts = json!({
                                        "order_wait_us": order_wait.map(|d| d.as_micros() as u64),
                                        "lock_wait_us": lock_wait.as_micros() as u64,
                                        "lock_hold_us": lock_hold.as_micros() as u64,
                                        "handle_record_us": handling.as_micros() as u64,
                                        "splits_emitted": splits_emitted,
                                        "record_index_first": first_index,
                                        "records_out": handed - first_index,
                                    });
                                    timers.add_to(&mut facts);
                                    facts
                                },
                            );
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
                            let mut emu = snapshot_setup(|| {
                                let mut emu = MetaEmulator::setup_riscv(
                                    witness,
                                    final_pvs_state.clone(),
                                );
                                emu.disable_cost_estimator_for_snapshot();
                                emu
                            });
                            run_snapshot_main_loop(
                                &mut emu,
                                SnapshotMainMode::Interpreter,
                                |emu| emu.next_state_batch_segments(true, &mut |_| {}),
                                |emu| emu.cycles(),
                                |emu| emu.counters(),
                                |emu| emu.get_pv_stream(),
                                &snap_tx,
                                emu_result,
                                total_cycles,
                                pv_stream,
                                run,
                            );
                            snapshot_finish(emu);
                        };
                    #[cfg(feature = "aot-emulator")]
                    match witness.opts.expect("witness.opts not set").snapshot_main {
                        SnapshotMainMode::Aot => {
                            info!("[AOT] snapshot-main = AotMetaEmulator (running AOT-compiled chunks)");
                            // Both knobs default to the shape of the run rather than a constant,
                            // so say what they came out as. On the `bench` target because that is
                            // the one a run at the shipped log level keeps, and here because this
                            // is the only path that reads them.
                            match crate::emulator::aot::split_from_chunk() {
                                Some(from) => info!(
                                    target: "bench",
                                    "[split-replay] {} segment(s) on each chunk from chunk {from} \
                                     on (MLE_SPLIT_FROM_CHUNK)",
                                    crate::emulator::aot::split_segments(),
                                ),
                                None => info!(
                                    target: "bench",
                                    "[split-replay] {} segment(s) on each of the first {} chunk(s)",
                                    crate::emulator::aot::split_segments(),
                                    crate::emulator::aot::split_chunks(),
                                ),
                            }
                            let t_aot_setup = Instant::now();
                            let mut emu = snapshot_setup(|| {
                                let mut emu =
                                    AotMetaEmulator::setup_riscv(witness, final_pvs_state);
                                emu.disable_cost_estimator_for_snapshot();
                                emu
                            });
                            info!(
                                "[Snapshot Main] AOT setup done in {:.3}s",
                                t_aot_setup.elapsed().as_secs_f64()
                            );
                            run_snapshot_main_loop(
                                &mut emu,
                                SnapshotMainMode::Aot,
                                |emu| emu.next_state_batch_segments(),
                                |emu| emu.cycles(),
                                |emu| emu.counters(),
                                |emu| emu.get_pv_stream(),
                                &snap_tx,
                                emu_result,
                                total_cycles,
                                pv_stream,
                                run,
                            );
                            snapshot_finish(emu);
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

                    // Includes the emulator's setup, which the ledger keeps apart as setup time.
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
    let reports = reports.into_inner().unwrap_or_else(PoisonError::into_inner);
    // On the `bench` target, which a run at the shipped log level keeps. It says what reached the
    // workers rather than what a caller asked for: an option that never got here reads as the
    // interpreter, and AOT workers that interpreted every instruction in their fallback read as
    // zero dispatches.
    match opts.replay_workers {
        ReplayWorkers::Aot => info!(
            target: "bench",
            "MLE replay workers: aot, {} compiled-block dispatches over {} chunks, {} \
             instructions run by recording blocks",
            replay_dispatches.into_inner(),
            reports.len(),
            recorder_insns_run.into_inner()
        ),
        ReplayWorkers::Interpreter => info!(
            target: "bench",
            "MLE replay workers: interpreter, {} chunks",
            reports.len()
        ),
    }
    Ok((reports, total_cycles, pv_stream))
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
                max_cycles: Some(1 << 32),
                cycle_tracker: false,
                cost_estimator: false,
                snapshot_main: SnapshotMainMode::Interpreter,
                replay_workers: crate::emulator::opts::ReplayWorkers::Interpreter,
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
                run(&|_, _| {}).is_err_and(|e| e.to_string().contains("illegal instruction")),
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

    #[test]
    fn a_pool_short_of_every_worker_is_named_and_one_that_fits_is_not() {
        let workers = NonZeroUsize::new(16).unwrap();
        assert_eq!(memory_pool_shortfall(18, workers, Some(2)), None);
        assert_eq!(
            memory_pool_shortfall(16, workers, None),
            None,
            "a run that draws no pool memory per batch"
        );
        assert!(memory_pool_shortfall(16, workers, Some(2))
            .is_some_and(|r| r.contains("at most 16") && r.contains("the 18 this run")));
    }

    /// A pool built ahead of the run, as a prewarm builds it, has the size the run's own check
    /// gives an unset `MEMORY_POOL_SIZE`, and keeps it. In a child process: a process builds its
    /// pool once. The hook stands in for the AOT snapshot thread's draw of one memory per batch, and
    /// no memory is made, so building the pool costs nothing.
    #[test]
    fn a_pool_built_ahead_of_the_run_is_sized_for_it() {
        const CHILD_VAR: &str = "PICO_POOL_AHEAD_PROBE";
        const MARKER: &str = "[pool-ahead] the pool was built at the run's size";

        if std::env::var(CHILD_VAR).is_ok() {
            assert!(
                std::env::var_os("MEMORY_POOL_SIZE").is_none(),
                "the probe sizes an unset MEMORY_POOL_SIZE; unset it"
            );
            hooks::DRAW_POOL_BLOCK_PER_BATCH.store(true, Ordering::Relaxed);
            init_memory_pool_for(
                NonZeroUsize::new(20).unwrap(),
                SnapshotMainMode::Interpreter,
            );
            let built = || {
                crate::emulator::riscv::memory::GLOBAL_MEMORY_POOL
                    .0
                    .capacity()
            };
            assert_eq!(built(), Some(21), "20 workers and one segment");
            raise_pool_size_floor(64);
            assert_eq!(built(), Some(21));
            assert_eq!(
                crate::emulator::riscv::memory::memory_pool_size(),
                21,
                "a later raise leaves the size a built pool reports"
            );
            println!("{MARKER}");
            return;
        }
        in_child(
            "proverchain::riscv::tests::a_pool_built_ahead_of_the_run_is_sized_for_it",
            CHILD_VAR,
            &[("MEMORY_POOL_EAGER", "0"), ("MEMORY_POOL_LOW_WATER", "0")],
            Duration::from_secs(60),
            "building the pool hung",
            MARKER,
        );
    }

    #[test]
    fn a_bound_below_a_chunks_segments_is_named() {
        let slots = |count| -> Result<_, String> { Ok(NonZeroUsize::new(count)) };
        assert_eq!(
            history_slot_refusal(Ok(None), 16),
            None,
            "an unbounded process"
        );
        assert_eq!(history_slot_refusal(slots(64), 1), None);
        assert_eq!(history_slot_refusal(slots(3), 3), None, "exactly enough");
        assert!(history_slot_refusal(slots(2), 3)
            .is_some_and(|r| r.contains("3 segments") && r.contains(SLOTS_VAR)));
        assert_eq!(
            history_slot_refusal(Err("unreadable".into()), 1).as_deref(),
            Some("unreadable"),
            "a count the first take could not read"
        );
    }

    /// Each refusal names what is missing; interpreter workers are never refused.
    #[test]
    fn aot_replay_workers_are_refused_where_they_cannot_run() {
        let opts = |snapshot_main, replay_workers| EmulatorOpts {
            snapshot_main,
            replay_workers,
            cycle_tracker: false,
            cost_estimator: false,
            ..EmulatorOpts::default()
        };
        let registered = |program, replay| Registered { program, replay };
        let (none, program, both) = (
            registered(false, false),
            registered(true, false),
            registered(true, true),
        );
        let aot = opts(SnapshotMainMode::Aot, ReplayWorkers::Aot);
        assert_eq!(replay_workers_refusal(&aot, both), None);
        for registered in [none, program, both] {
            let interpreter = opts(SnapshotMainMode::Interpreter, ReplayWorkers::Interpreter);
            assert_eq!(replay_workers_refusal(&interpreter, registered), None);
        }
        let refused = |opts: EmulatorOpts, registered, named: &str| {
            assert!(
                replay_workers_refusal(&opts, registered).is_some_and(|r| r.contains(named)),
                "{named}"
            );
        };
        refused(
            aot.with_snapshot_main(SnapshotMainMode::Interpreter),
            both,
            "snapshot_main = Aot",
        );
        refused(aot, none, "no AOT program is registered");
        refused(aot, program, "no recording entry point");
        refused(aot.with_cycle_tracker(), both, "cycle_tracker");
        refused(aot.with_cost_estimator(), both, "cost_estimator");
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

    /// fib through the pipeline on `workers`, against the serial interpreter: the same committed
    /// bytes and cycles, and record for record the same kind and digest rows. Fewer workers than
    /// chunks, so some worker replays a chunk on the emulator it kept from the one before.
    fn assert_replays_like_the_interpreter(workers: NonZeroUsize) {
        let witness = fib_witness();
        let program = witness.program.clone().expect("program");
        let stdin = witness.stdin.clone().expect("stdin");
        let opts = witness.opts.expect("opts");
        let rows = |records: &[EmulationRecord]| -> Vec<(bool, Vec<FieldDigest>)> {
            records
                .iter()
                .map(|record| (record.is_cpu_chunk, field_digests(record)))
                .collect()
        };
        let serial = crate::mle::machine::riscv::emulate_with_opts(program.clone(), &stdin, opts)
            .expect("the interpreter runs");
        let piped =
            crate::mle::machine::riscv::emulate_with_pipeline(program, &stdin, opts, workers)
                .expect("the pipeline runs");
        assert!(
            piped.chunks as usize > workers.get(),
            "{} chunks on {workers} workers: no worker replays twice",
            piped.chunks
        );
        assert_eq!(piped.committed_bytes, serial.committed_bytes);
        assert_eq!(piped.cycles, serial.cycles);
        assert_eq!(rows(&piped.records), rows(&serial.records));
    }

    #[test]
    fn fewer_workers_than_chunks_replay_as_the_interpreter_does() {
        const CHILD_VAR: &str = "PICO_PIPELINE_REUSE_PROBE";
        const MARKER: &str = "[pipeline-reuse] the reused workers replayed as the interpreter does";

        if std::env::var(CHILD_VAR).is_ok() {
            let workers = NonZeroUsize::new(max_pipeline_workers().min(2)).expect("a core");
            assert_replays_like_the_interpreter(workers);
            println!("{MARKER}");
            return;
        }

        in_child(
            "proverchain::riscv::tests::fewer_workers_than_chunks_replay_as_the_interpreter_does",
            CHILD_VAR,
            &[],
            Duration::from_secs(120),
            "the pipeline hung reusing its workers' emulators",
            MARKER,
        );
    }

    /// Several workers on a pool of one memory, which the snapshot thread draws a batch at a time
    /// the way the AOT thread does: the run goes on only once a worker gives its batch's memory
    /// back, so a worker that kept one while it waited for its next batch would stop it for good.
    /// A replay that fails, on a fresh emulator or on one recovered in place, leaves the pool
    /// whole: the run after it, which a lost memory would stop, replays as before.
    #[test]
    fn several_workers_share_a_one_memory_pool_and_survive_a_failed_run() {
        const CHILD_VAR: &str = "PICO_PIPELINE_SHARED_POOL_PROBE";
        const MARKER: &str = "[pipeline-pool] several workers finished on a one-memory pool";

        if std::env::var(CHILD_VAR).is_ok() {
            let workers = NonZeroUsize::new(max_pipeline_workers().min(3)).expect("a core");
            hooks::DRAW_POOL_BLOCK_PER_BATCH.store(true, Ordering::Relaxed);
            assert_replays_like_the_interpreter(workers);

            for hook in [
                &hooks::ERROR_IN_FIRST_REPLAY,
                &hooks::ERROR_IN_FIRST_IN_PLACE_REPLAY,
            ] {
                hook.store(true, Ordering::Relaxed);
                let failed = emulate_snapshot_pipeline_with(
                    &fib_witness(),
                    workers,
                    DeferredSplit::AfterEveryChunk,
                    |_, _| {},
                );
                assert!(
                    failed.is_err_and(|e| e.to_string().contains("illegal instruction")),
                    "the replay's error must be the run's"
                );
                assert!(
                    !hook.load(Ordering::Relaxed),
                    "no replay the hook names ran"
                );
                assert_replays_like_the_interpreter(workers);
            }
            println!("{MARKER}");
            return;
        }

        in_child(
            "proverchain::riscv::tests::several_workers_share_a_one_memory_pool_and_survive_a_failed_run",
            CHILD_VAR,
            &[("MEMORY_POOL_SIZE", "1")],
            Duration::from_secs(180),
            "the pipeline hung on a one-memory pool",
            MARKER,
        );
    }

    /// Two history slots, two workers, and the replay of chunk 16 held until the two chunks after
    /// it have replayed: chunk 16 is the first the sequencer passes on in chunk order, so their
    /// records wait in its stash, each holding its slot. Granted first come, first served, chunk 16
    /// then waits for a slot for good.
    #[test]
    fn a_late_chunk_takes_its_slot_before_the_chunks_after_it() {
        const CHILD_VAR: &str = "PICO_PIPELINE_SLOT_ORDER_PROBE";
        const MARKER: &str = "[slot-order] the late chunk took its slot before the chunks after it";
        const SLOTS: usize = 2;

        if std::env::var(CHILD_VAR).is_ok() {
            use crate::emulator::riscv::record_slots::{history_arena, init_record_slots};
            use std::sync::atomic::AtomicUsize;

            assert!(max_pipeline_workers() >= 2, "two workers need two cores");
            assert_eq!(init_record_slots(SLOTS), SLOTS);
            let late = DYNAMIC_CHUNK_START as usize;
            hooks::LATE_BATCH.store(late, Ordering::Relaxed);
            let mut witness = fib_witness();
            // Chunks small enough that those after the late one fill every slot, as checked below.
            witness.opts.as_mut().expect("opts").chunk_size = 128;
            let (cpu, in_slot) = (AtomicUsize::new(0), AtomicUsize::new(0));
            let (reports, _, _) = emulate_snapshot_pipeline_with(
                &witness,
                NonZeroUsize::new(2).expect("nonzero"),
                DeferredSplit::FromChunk16,
                |record, _| {
                    if record.is_cpu_chunk {
                        let held = record
                            .history
                            .as_ref()
                            .is_some_and(ExecutionHistory::holds_slot);
                        cpu.fetch_add(1, Ordering::Relaxed);
                        in_slot.fetch_add(usize::from(held), Ordering::Relaxed);
                    }
                },
            )
            .expect("the pipeline completes");
            assert_eq!(
                hooks::LATE_BATCH.load(Ordering::Relaxed),
                usize::MAX,
                "chunk {late} was never replayed"
            );
            assert!(
                reports.len() >= late + 2 * SLOTS,
                "{} chunks: too few after chunk {late} to fill the slots",
                reports.len()
            );
            let cpu = cpu.into_inner();
            assert_eq!(
                in_slot.into_inner(),
                cpu,
                "a chunk's history outside a slot"
            );
            let stats = history_arena().expect("a bounded process").stats();
            assert!(
                stats.blocked_takes > 0,
                "no take waited, so the late chunk held nothing back"
            );
            println!("{MARKER}");
            return;
        }

        in_child(
            "proverchain::riscv::tests::a_late_chunk_takes_its_slot_before_the_chunks_after_it",
            CHILD_VAR,
            &[],
            Duration::from_secs(120),
            "a late chunk waited for good on the history slots of the chunks after it",
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
