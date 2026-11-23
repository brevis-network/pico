//! MLE/WHIR single-node orchestration (KoalaBear).
//!
//! In-process pipeline:
//! - emulation runs `emulate_snapshot_pipeline` with `bench_riscv_ops` opts, its replay workers on
//!   the engine [`replay_workers`] resolves at startup (`MLE_REPLAY_WORKERS`); it self-initializes
//!   the shared snapshot memory-pool/recycler (sized via `MEMORY_POOL_SIZE`) and streams records
//!   to a preparer thread. (Distinct from the bound on records held at once, which this module
//!   sets from `MLE_HISTORY_SLOTS`.) `PICO_GPU_MEM=5090` selects the precompile-split thresholds;
//! - a [`GlobalScheduler`] hands chunk indices to a worker pool. Without `--step combine` it runs
//!   in no-combine mode and completes by count (chunk proofs are terminal); with it, the scheduler
//!   also runs its aggregation tree — convert proofs are reported into its proof tree, adjacent
//!   pairs become combine tasks, and the same worker pool proves those nodes;
//! - each worker proves its chunk via the shared [`RiscvMachine`];
//! - cross-chunk consistency is the global LogUp: each chunk's convert leaf takes its entry into
//!   the chain over the chunks' Global table commitments ([`GlobalChain`]), and once every chunk's
//!   table is committed the tree's prefix (the second phase and its nodes) is proved on the
//!   prover lanes and joined with the chunks at the root;
//! - `--step combine` then hands the tree's root to the CPU `CombineMachine` for the four-step
//!   host-side acceptance, so that check lives in exactly one place.

pub mod config;
pub mod embed;
pub mod ethproofs;
use pico_vm::mle::inject;
pub mod two_machine;
mod watch;

use std::{
    fmt,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    thread,
    time::{Duration, Instant},
};

use dashmap::DashMap;
use p3_koala_bear::KoalaBear;
use pico_vm::{
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{
        opts::{EmulatorOpts, ReplayWorkers},
        record::RecordBehavior,
        riscv::{
            memory::{memories_made, memory_pool_size},
            record::EmulationRecord,
            record_slots::{init_record_slots, record_slots_from_env, take_occupancy},
        },
        stdin::EmulatorStdin,
    },
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::{host_memory, witness::ProvingWitness},
    mle::{
        env_flag,
        machine::{
            convert::ProofWithVk,
            riscv::{corrupt_one_record, PreparedChunk, RiscvMachine},
        },
    },
    proverchain::riscv::{
        emulate_snapshot_pipeline, emulate_snapshot_pipeline_with, init_memory_pool_for,
        pipeline_workers_from_env, DeferredSplit,
    },
};
use tracing::{info, warn};
use watch::SpawnWatched;

// The streaming convert stage is GPU-only (no CPU path); its types exist only under `cuda`.
#[cfg(feature = "cuda")]
use pico_vm::mle::machine::{
    apex::MleApexVerifier,
    combine::CombineMachine,
    compress::{CompressMachine, GpuCompressMachine},
    convert::GpuConvertMachine,
    exe::RiscvVmVk,
    vk_map::{pinned_root_from_env, MleVkMap},
};
use pico_vm::mle::spans::{self, LaneId, Role, WorkKind};

use crate::common::{
    global_scheduler::GlobalScheduler,
    machine_role::{get_worker_label, set_mle_chunk_assignment_defaults},
    mle_scheduler_singleton::{
        get_mle_scheduler, is_mle_secondary, mle_abort_run, mle_acquire_task_unified_async,
        mle_finalize_emulation, mle_register_chunk, mle_register_chunk_with_cost,
        mle_report_chunk_terminal, reset_mle_scheduler, MleAcquireResult,
    },
};
// The combine-preparer feed names the task type; on CPU builds the dispatcher's combine arm is
// `unreachable!` and never names it.
#[cfg(feature = "cuda")]
use crate::common::global_scheduler::CombineTask;
// The global LogUp of a block on two machines: its chain and its group nodes cross between them.
#[cfg(feature = "cuda")]
use crate::common::{
    global_logup_exchange::{exchange, ChunkTableReport, Exchange},
    mle_scheduler_singleton::{
        mle_await_chunk_tables, mle_report_chunk_table, mle_report_group_node,
    },
    scheduler_service::ExchangeError,
};
// Reached only from the convert/combine reporting arms, which are GPU-only.
#[cfg(feature = "cuda")]
use crate::{
    common::mle_scheduler_singleton::mle_report_proof, gateway::handler::proof_tree::IndexedProof,
};
use config::{MleSingleNodeConfig, Step};

/// The RISCV chunk proof type. It flows to the convert stage over a channel; it never enters the
/// scheduler (see [`SchedulerProof`]).
type MleProof = pico_vm::mle::proof::Proof<pico_vm::mle::machine::riscv::Sc>;

/// The final combine node, handed from the worker that proved it to the main thread.
///
/// `proof` is the `Arc` the scheduler's `IndexedProof` already wraps, so stashing it costs a
/// refcount rather than a deep copy of the proof.
#[cfg(feature = "cuda")]
struct RootRecord {
    proof: Arc<SchedulerProof>,
    /// The root node's ORDERED child layouts — required to register its shape on the CPU
    /// `CombineMachine` before that machine will accept the root (see its `verify` CONTRACT).
    child_layouts: Vec<pico_vm::mle::compiler::recursion::RecursionVkLayout>,
}

/// The global LogUp's chain over a block's chunks, as the pipeline learns it.
///
/// A chunk's convert leaf enters the chain at the value after the chunks before it, a value
/// over their Global table commitments, which their riscv proofs carry. A riscv lane records a
/// chunk's commitment once its traces are built, ahead of its proof; a convert preparer waits
/// here for its chunk's entry; the stage that proves the tree's prefix waits for the whole
/// chain.
///
/// On two machines each traces only the chunks it proves, and the chain is over them all. The
/// primary's chain also takes the commitments the secondary reports, and its growth is
/// published for the secondary, whose chain follows it ([`follow_peer_chunks`]).
#[cfg(feature = "cuda")]
struct GlobalChain {
    state: std::sync::Mutex<GlobalChainState>,
    grew: std::sync::Condvar,
    /// A two-machine primary's exchange, where the secondary reads the chain's growth.
    followed: Option<&'static Exchange>,
}

#[cfg(feature = "cuda")]
struct GlobalChainState {
    /// The chain over the block's leading chunks whose commitments are in.
    chain: pico_vm::mle::machine::global_logup::Chain,
    /// The commitments the chain has stepped over, in chunk order.
    commits: Vec<ChainDigest>,
    /// Commitments that arrived ahead of an earlier chunk's, by 0-based chunk index.
    ahead: std::collections::BTreeMap<usize, ChainDigest>,
    /// The block's chunk count, once the emulation is finalized.
    total: Option<usize>,
    /// When the block's window opened ([`GlobalChain::start_clock`]).
    origin: Option<Instant>,
    /// How far into the block the chain had every chunk's commitment.
    whole_after: Option<Duration>,
    /// The convert leaves' waits for their entries: how many waited, in total, and the longest.
    waits: (usize, Duration, Duration),
}

#[cfg(feature = "cuda")]
type ChainDigest = [pico_vm::mle::machine::recursion::Kb; pico_vm::primitives::consts::DIGEST_SIZE];

#[cfg(feature = "cuda")]
impl GlobalChain {
    /// `chain` is the block's chain before any chunk (`Chain::new` of the riscv machine);
    /// `followed`, a two-machine primary's exchange.
    fn new(
        chain: pico_vm::mle::machine::global_logup::Chain,
        followed: Option<&'static Exchange>,
    ) -> Self {
        Self {
            state: std::sync::Mutex::new(GlobalChainState {
                chain,
                commits: Vec::new(),
                ahead: std::collections::BTreeMap::new(),
                total: None,
                origin: None,
                whole_after: None,
                waits: (0, Duration::ZERO, Duration::ZERO),
            }),
            grew: std::sync::Condvar::new(),
            followed,
        }
    }

    /// Record the commitment of chunk `chunk_idx`'s (0-based) Global table.
    ///
    /// On two machines a chunk's commitment may be recorded twice, by the lane that traced the
    /// chunk and as the other machine hands it back; both are the one value.
    fn record(&self, chunk_idx: usize, commit: ChainDigest) {
        let mut state = self.state.lock().expect("global LogUp chain poisoned");
        let known = match state.commits.get(chunk_idx) {
            Some(known) => Some(*known),
            None => state.ahead.insert(chunk_idx, commit),
        };
        assert!(
            known.is_none_or(|known| known == commit),
            "chunk {chunk_idx}'s Global table was recorded under two commitments"
        );
        loop {
            let next = state.commits.len();
            let Some(commit) = state.ahead.remove(&next) else {
                break;
            };
            state.chain.push(&commit);
            state.commits.push(commit);
            if let Some(exchange) = self.followed {
                exchange.publish_commit(encode_commit(&commit));
            }
        }
        self.grew.notify_all();
    }

    /// How many of the block's leading chunks the chain has stepped over.
    fn held(&self) -> usize {
        self.state
            .lock()
            .expect("global LogUp chain poisoned")
            .commits
            .len()
    }

    /// The block's chunk count, once this machine's emulation is finalized.
    fn total(&self) -> Option<usize> {
        self.state
            .lock()
            .expect("global LogUp chain poisoned")
            .total
    }

    /// The commitment a chunk's proof opens its Global table under.
    fn commit_of(&self, proof: &MleProof) -> Option<ChainDigest> {
        self.state
            .lock()
            .expect("global LogUp chain poisoned")
            .chain
            .commit_of(proof)
    }

    /// The chain value chunk `chunk_idx`'s convert leaf enters at: waits until the chunks
    /// before it have recorded their commitments.
    ///
    /// A run that is being drained (`mle_abort_run`) gets the chain's last value instead: its
    /// proofs are thrown away.
    fn before(&self, chunk_idx: usize) -> ChainDigest {
        let asked = Instant::now();
        let mut state = self.state.lock().expect("global LogUp chain poisoned");
        if state.chain.values().len() > chunk_idx {
            return state.chain.values()[chunk_idx];
        }
        while state.chain.values().len() <= chunk_idx {
            if get_mle_scheduler().is_aborted() {
                return *state
                    .chain
                    .values()
                    .last()
                    .expect("the chain has its start");
            }
            state = self
                .grew
                .wait_timeout(state, Self::ABORT_POLL)
                .expect("global LogUp chain poisoned")
                .0;
        }
        let waited = asked.elapsed();
        state.waits.0 += 1;
        state.waits.1 += waited;
        state.waits.2 = state.waits.2.max(waited);
        state.chain.values()[chunk_idx]
    }

    /// The block's window opens now: the times in [`Self::timing`] count from here.
    fn start_clock(&self) {
        self.state
            .lock()
            .expect("global LogUp chain poisoned")
            .origin = Some(Instant::now());
    }

    /// One line on what the chain cost the block: when it had every commitment, and how long
    /// convert leaves waited for their entries.
    fn timing(&self) -> String {
        let state = self.state.lock().expect("global LogUp chain poisoned");
        let (waited, total, longest) = state.waits;
        format!(
            "the chain had every chunk's commitment {} into the block; {waited} convert \
             leaf(s) waited for their entries, {:.3}s in total, {:.3}s at most",
            state
                .whole_after
                .map_or("at an unknown time".to_string(), |d| format!(
                    "{:.3}s",
                    d.as_secs_f64()
                )),
            total.as_secs_f64(),
            longest.as_secs_f64(),
        )
    }

    /// How often a wait looks whether the run was aborted meanwhile.
    const ABORT_POLL: Duration = Duration::from_millis(200);

    /// The emulation is finalized at `total` chunks.
    fn set_total(&self, total: usize) {
        self.state
            .lock()
            .expect("global LogUp chain poisoned")
            .total = Some(total);
        if let Some(exchange) = self.followed {
            exchange.publish_chunks(total);
        }
        self.grew.notify_all();
    }

    /// The chain over the whole block, `total + 1` values: waits for the finalize and for every
    /// chunk's commitment. `None` if the run is aborted first, and for a block of no chunks:
    /// its chain is whole from the start, over nothing, and it has no second phase to prove.
    fn whole(&self) -> Option<Vec<ChainDigest>> {
        let mut state = self.state.lock().expect("global LogUp chain poisoned");
        loop {
            if get_mle_scheduler().is_aborted() || state.total == Some(0) {
                return None;
            }
            if state.total == Some(state.chain.values().len() - 1) {
                state.whole_after = state.origin.map(|origin| origin.elapsed());
                return Some(state.chain.values().to_vec());
            }
            state = self
                .grew
                .wait_timeout(state, Self::ABORT_POLL)
                .expect("global LogUp chain poisoned")
                .0;
        }
    }
}

#[cfg(all(test, feature = "cuda"))]
mod global_chain_tests {
    use super::{decode_commit, ChainDigest, Exchange, GlobalChain};
    use p3_field::PrimeCharacteristicRing;
    use pico_vm::mle::machine::{global_logup::Chain, recursion::Kb};
    use std::time::Duration;

    /// A chain before any chunk. Any parameters do: the tests compare with a `Chain` of the same.
    fn start() -> Chain {
        Chain::new(&pico_vm::mle::recursion_params_with_128_bits_security())
    }

    fn commit(of: u32) -> ChainDigest {
        std::array::from_fn(|at| Kb::from_u32(of * 16 + at as u32))
    }

    /// The chain's values over the commitments of chunks `0..chunks`, stepped in order.
    fn values(chunks: u32) -> Vec<ChainDigest> {
        let mut chain = start();
        for chunk in 0..chunks {
            chain.push(&commit(chunk));
        }
        chain.values().to_vec()
    }

    #[test]
    fn commitments_step_the_chain_in_chunk_order_however_they_arrive() {
        let chain = GlobalChain::new(start(), None);
        chain.record(2, commit(2));
        chain.record(1, commit(1));
        assert_eq!(chain.held(), 0);
        chain.record(0, commit(0));
        assert_eq!(chain.held(), 3);
        assert_eq!(chain.total(), None);
        chain.set_total(3);
        assert_eq!(chain.total(), Some(3));
        let expected = values(3);
        assert_eq!(chain.before(0), expected[0]);
        assert_eq!(chain.before(2), expected[2]);
        assert_eq!(chain.whole(), Some(expected));
    }

    #[test]
    fn a_commitment_recorded_twice_is_one() {
        let chain = GlobalChain::new(start(), None);
        // Ahead of its turn, twice; then in the chain, and once more.
        chain.record(1, commit(1));
        chain.record(1, commit(1));
        chain.record(0, commit(0));
        chain.record(0, commit(0));
        chain.record(1, commit(1));
        chain.set_total(2);
        assert_eq!(chain.whole(), Some(values(2)));
    }

    #[test]
    #[should_panic(expected = "two commitments")]
    fn two_commitments_for_a_chunk_in_the_chain_are_refused() {
        let chain = GlobalChain::new(start(), None);
        chain.record(0, commit(0));
        chain.record(0, commit(1));
    }

    #[test]
    #[should_panic(expected = "two commitments")]
    fn two_commitments_for_a_chunk_ahead_of_its_turn_are_refused() {
        let chain = GlobalChain::new(start(), None);
        chain.record(1, commit(0));
        chain.record(1, commit(1));
    }

    #[test]
    fn a_primarys_chain_is_published_as_it_grows() {
        let exchange: &'static Exchange = Box::leak(Box::new(Exchange::new()));
        exchange.open(1);
        let chain = GlobalChain::new(start(), Some(exchange));
        let poll = |from| {
            tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .expect("a test runtime")
                .block_on(exchange.await_commits(1, from, Duration::from_millis(20)))
                .expect("the primary is on the block")
        };
        // Chunk 1 arrives first, as the other machine's may: nothing is in order yet.
        chain.record(1, commit(1));
        assert!(poll(0).commits.is_empty());
        chain.record(0, commit(0));
        let news = poll(0);
        let published: Vec<ChainDigest> = news
            .commits
            .iter()
            .enumerate()
            .map(|(chunk, bytes)| decode_commit(chunk, bytes))
            .collect();
        assert_eq!(published, vec![commit(0), commit(1)]);
        assert_eq!(news.chunks, None);
        chain.set_total(2);
        assert_eq!(poll(2).chunks, Some(2));
    }
}

/// A Global table commitment as the two machines of a block send it to each other.
#[cfg(feature = "cuda")]
fn encode_commit(commit: &ChainDigest) -> Vec<u8> {
    bincode::serialize(commit).expect("a commitment serialises")
}

/// The commitment of chunk `chunk_idx` as the other machine sent it.
#[cfg(feature = "cuda")]
fn decode_commit(chunk_idx: usize, bytes: &[u8]) -> ChainDigest {
    bincode::deserialize(bytes).unwrap_or_else(|e| {
        panic!(
            "the other machine's commitment of chunk {chunk_idx}'s Global table does not \
             decode: {e}"
        )
    })
}

/// Keeps a two-machine block's chain in step with the chunks the other machine traces, until
/// the chain is whole, the run is stopped, or `done` is set.
///
/// The primary takes the secondary's reports off the exchange: a chunk's share of the real-row
/// count goes into the block's count, and then its commitment into the chain, so that a whole
/// chain has a whole count. `over` is told of the share that takes the count past the limit.
/// The secondary follows the chain the primary publishes, which is over both machines' chunks.
#[cfg(feature = "cuda")]
fn follow_peer_chunks(
    chain: &GlobalChain,
    count: Option<&GlobalRowCount>,
    done: &AtomicBool,
    guest_failed: &AtomicBool,
    over: impl Fn(TooManyGlobalRows),
) {
    let stop = || {
        done.load(Ordering::SeqCst)
            || run_stopped(guest_failed)
            || get_mle_scheduler().is_aborted()
            || chain.total().is_some_and(|total| chain.held() == total)
    };
    if is_mle_secondary() {
        while !stop() {
            let from = chain.held();
            match mle_await_chunk_tables(from) {
                Ok(news) => {
                    if let (Some(theirs), Some(ours)) = (news.chunks, chain.total()) {
                        assert_eq!(
                            theirs, ours,
                            "the primary emulated the block to {theirs} chunks, this machine \
                             to {ours}"
                        );
                    }
                    for (at, commit) in news.commits.iter().enumerate() {
                        chain.record(from + at, decode_commit(from + at, commit));
                    }
                    // The primary's chain is whole and this machine's emulation is not
                    // finalized yet: its polls are answered at once.
                    if news.commits.is_empty() && news.chunks.is_some_and(|chunks| from >= chunks) {
                        thread::sleep(Duration::from_millis(20));
                    }
                }
                Err(ExchangeError::OtherBlock(why)) => {
                    tracing::error!(
                        "the primary refused to hand out the block's chain: {why}; this \
                         block's run is stopped"
                    );
                    mle_abort_run();
                    return;
                }
                Err(ExchangeError::Failed(why)) => {
                    warn!("secondary failed to follow the primary's chain: {why}");
                    thread::sleep(Duration::from_secs(1));
                }
            }
        }
    } else {
        while !stop() {
            for report in exchange().take_tables(GlobalChain::ABORT_POLL) {
                let commit = decode_commit(report.chunk_idx, &report.commit);
                if let Some(Err(too_many)) =
                    count.map(|count| count.add(report.chunk_idx, report.row_count))
                {
                    over(too_many);
                }
                chain.record(report.chunk_idx, commit);
            }
        }
    }
}

/// A chunk's share took the block past the global LogUp's real-row limit: the run ends as it
/// does on a refused shape. The CLI stops on it; an embedded caller gets the refusal back, in
/// `slot`, and the run drains.
#[cfg(feature = "cuda")]
fn stop_over_global_rows(
    over: TooManyGlobalRows,
    embedded_run: bool,
    slot: &std::sync::Mutex<Option<TooManyGlobalRows>>,
    guest_failed: &AtomicBool,
) {
    if !embedded_run {
        panic!("{over}");
    }
    slot.lock()
        .unwrap_or_else(|e| e.into_inner())
        .get_or_insert(over);
    guest_failed.store(true, Ordering::SeqCst);
    mle_abort_run();
}

/// A block's real-row count for the global LogUp, added up as its chunks leave the preparers.
/// A two-machine primary adds the chunks the secondary traces as the secondary reports them
/// ([`follow_peer_chunks`]); the secondary's own count is over its chunks alone.
///
/// The tree's root refuses a block over the limit, so the run stops at the chunk that takes
/// the count past it, instead of proving on to a root that cannot be proved.
#[cfg(any(feature = "cuda", test))]
struct GlobalRowCount {
    counted: AtomicU64,
    limit: u64,
    /// The chunks whose shares are in. A two-machine primary counts a chunk as it prepares it
    /// and as the secondary reports having traced it: a chunk that reaches it both ways, or
    /// in a report sent twice, is counted once.
    chunks: std::sync::Mutex<std::collections::HashSet<usize>>,
}

#[cfg(any(feature = "cuda", test))]
impl GlobalRowCount {
    /// The global LogUp's limit, or the lower one a negative test injects.
    fn new() -> Self {
        let limit = pico_vm::mle::machine::global_logup::MAX_COUNT;
        Self::within(inject::global_row_count_limit().map_or(limit, |injected| injected.min(limit)))
    }

    fn within(limit: u64) -> Self {
        Self {
            counted: AtomicU64::new(0),
            limit,
            chunks: Default::default(),
        }
    }

    /// Adds the share of chunk `chunk_idx` (`RiscvMachine::chunk_global_row_count`), once.
    fn add(&self, chunk_idx: usize, share: u64) -> Result<(), TooManyGlobalRows> {
        let first = self
            .chunks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(chunk_idx);
        if !first {
            return Ok(());
        }
        let count = self.counted.fetch_add(share, Ordering::SeqCst) + share;
        if count > self.limit {
            return Err(TooManyGlobalRows {
                count,
                max: self.limit,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod global_row_count_tests {
    use super::{GlobalRowCount, TooManyGlobalRows};

    #[test]
    fn a_block_may_reach_the_limit_and_not_pass_it() {
        let count = GlobalRowCount::within(10);
        assert_eq!(count.add(0, 4), Ok(()));
        assert_eq!(count.add(1, 6), Ok(()));
        assert_eq!(
            count.add(2, 1),
            Err(TooManyGlobalRows { count: 11, max: 10 })
        );
    }

    #[test]
    fn a_chunk_counted_twice_is_counted_once() {
        let count = GlobalRowCount::within(10);
        assert_eq!(count.add(3, 6), Ok(()));
        assert_eq!(count.add(3, 6), Ok(()));
        assert_eq!(count.add(4, 4), Ok(()));
        assert_eq!(count.counted.load(std::sync::atomic::Ordering::SeqCst), 10);
    }

    #[test]
    fn the_limit_is_the_global_logups_unless_a_test_lowers_it() {
        assert_eq!(
            GlobalRowCount::new().limit,
            pico_vm::mle::machine::global_logup::MAX_COUNT
        );
    }
}

/// A piece of the tree's prefix (a group proof, a node, a step of the nodes' reduction) for a
/// card's prover lane. The lane runs it between its other items and ahead of any chunk that is
/// waiting; its thread is bound to its card, and the piece is told which card that is.
type PrefixPiece = Box<dyn FnOnce(usize) + Send>;

/// Runs a piece of the tree's prefix on the calling lane, unless the run is being drained.
fn run_prefix_piece(piece: PrefixPiece, card: usize, guest_failed: &AtomicBool) {
    if run_stopped(guest_failed) {
        return;
    }
    let _b = spans::busy(WorkKind::ProveGlobalLogUp, None);
    piece(card);
    // A piece's trace generation sets the lane thread's `MLE_BREAKDOWN` reading; left there, it
    // would be taken for the next convert or combine proof of the lane.
    #[cfg(feature = "cuda")]
    let _ = pico_vm::mle::cuda_mle::breakdown::take();
}

/// How a piece of the tree's prefix fared: how long it waited for a lane, and how long it ran.
#[cfg(feature = "cuda")]
#[derive(Clone, Copy)]
struct PieceTime {
    waited: Duration,
    ran: Duration,
}

/// One step's pieces in a phrase: each piece's run time, and the longest wait for a lane.
#[cfg(feature = "cuda")]
fn piece_times(what: &str, times: &[PieceTime]) -> String {
    let ran: Vec<String> = times
        .iter()
        .map(|time| format!("{:.3}", time.ran.as_secs_f64()))
        .collect();
    let waited = times
        .iter()
        .map(|time| time.waited)
        .max()
        .unwrap_or_default();
    format!(
        "{what} ran [{}]s after waiting {:.3}s at most",
        ran.join(" "),
        waited.as_secs_f64()
    )
}

/// Chunks to a group of the second phase: as many as a group holds, or the smaller count
/// `MLE_GLOBAL_LOGUP_GROUP_LEN` asks for. Any grouping that covers the chunks in order verifies; the
/// setting is for measuring what a group's length costs.
///
/// A short length on few cards makes many more pieces of the prefix, which the tree's root waits
/// for: the scheduler's dispatcher gives a run up after 300 s without a task.
#[cfg(feature = "cuda")]
fn global_logup_group_len() -> usize {
    global_logup_group_len_setting().unwrap_or_else(|e| panic!("{e}"))
}

/// [`global_logup_group_len`], with a bad `MLE_GLOBAL_LOGUP_GROUP_LEN` as an error: an embedded caller checks it up
/// front, where a bad value poisons nothing.
#[cfg(feature = "cuda")]
pub(crate) fn global_logup_group_len_setting() -> Result<usize, String> {
    let most = pico_vm::mle::machine::global_logup::GROUP_LEN;
    match std::env::var("MLE_GLOBAL_LOGUP_GROUP_LEN") {
        Ok(raw) => match raw.trim().parse::<usize>() {
            Ok(len) if (1..=most).contains(&len) => Ok(len),
            _ => Err(format!(
                "MLE_GLOBAL_LOGUP_GROUP_LEN={raw:?} is not a group length from 1 to {most}"
            )),
        },
        Err(_) => Ok(most),
    }
}

/// Hands `pieces` to the cards' prover lanes and waits for their results, in the pieces' order,
/// each with its time. `None` if the run is drained before every piece has run.
#[cfg(feature = "cuda")]
fn prefix_on_lanes<T: Send + 'static>(
    lanes: &crossbeam::channel::Sender<PrefixPiece>,
    pieces: Vec<Box<dyn FnOnce(usize) -> T + Send>>,
) -> Option<(Vec<T>, Vec<PieceTime>)> {
    let (done_tx, done_rx) = crossbeam::channel::unbounded();
    let mut results: Vec<Option<(T, PieceTime)>> = pieces.iter().map(|_| None).collect();
    for (at, piece) in pieces.into_iter().enumerate() {
        let done_tx = done_tx.clone();
        let handed = Instant::now();
        lanes
            .send(Box::new(move |card| {
                let waited = handed.elapsed();
                let result = piece(card);
                let ran = handed.elapsed() - waited;
                // Nobody is listening only if the stage gave up on a drained run.
                let _ = done_tx.send((at, (result, PieceTime { waited, ran })));
            }))
            .ok()?;
    }
    drop(done_tx);
    for _ in 0..results.len() {
        let (at, result) = loop {
            match done_rx.recv_timeout(GlobalChain::ABORT_POLL) {
                Ok(done) => break done,
                Err(crossbeam::channel::RecvTimeoutError::Timeout)
                    if !get_mle_scheduler().is_aborted() => {}
                // Aborted, or a lane dropped a piece unrun, which it does only in a drained run.
                Err(_) => return None,
            }
        };
        results[at] = Some(result);
    }
    let results: Option<Vec<_>> = results.into_iter().collect();
    Some(results?.into_iter().unzip())
}

/// The groups a machine proves over the Global tables it holds: every run of consecutive
/// chunks, cut at `group_len` chunks. `stamps` are the tables' chunks, ascending; a group is a
/// range of positions in it.
///
/// A machine that proves the whole block holds one run, and its groups are the block in steps
/// of `group_len`. Of two machines each holds the chunks it proved, in the rounds of the chunk
/// assignment, and a round is a run: no group needs a table of the other machine, and the two
/// machines' groups together cover the block in order.
#[cfg(any(feature = "cuda", test))]
fn groups_of(stamps: &[u32], group_len: usize) -> Vec<std::ops::Range<usize>> {
    let mut groups = Vec::new();
    let mut start = 0;
    for at in 1..=stamps.len() {
        let run_ends = at == stamps.len() || stamps[at] != stamps[at - 1] + 1;
        if run_ends || at - start == group_len {
            groups.push(start..at);
            start = at;
        }
    }
    groups
}

/// Whether `groups` (a group's first chunk, 0-based, to its chunk count) cover a block of
/// `chunks` chunks in order: `false` while a group is still to come. Groups that overlap are
/// not a block's.
#[cfg(any(feature = "cuda", test))]
fn groups_cover<T>(groups: &std::collections::BTreeMap<usize, (usize, T)>, chunks: usize) -> bool {
    let mut next = 0;
    for (&first, &(len, _)) in groups {
        assert!(
            first >= next,
            "the group at chunk {first} overlaps the one before it, which ends at {next}"
        );
        if first != next {
            return false;
        }
        next += len;
    }
    assert!(
        next <= chunks,
        "the groups cover {next} chunks, the block has {chunks}"
    );
    next == chunks
}

#[cfg(test)]
mod group_tests {
    use super::{groups_cover, groups_of};
    use std::collections::BTreeMap;

    #[test]
    fn a_whole_block_is_cut_in_steps_of_the_group_length() {
        let stamps: Vec<u32> = (1..=7).collect();
        assert_eq!(groups_of(&stamps, 3), vec![0..3, 3..6, 6..7]);
        assert_eq!(groups_of(&stamps, 7), vec![0..7]);
        assert_eq!(groups_of(&stamps, 15), vec![0..7]);
        assert_eq!(groups_of(&[], 15), Vec::<std::ops::Range<usize>>::new());
    }

    #[test]
    fn a_machines_rounds_are_groups_of_their_own() {
        // Rounds of four: the primary holds chunks 1-4 and 9-12, then 17.
        let stamps = [1, 2, 3, 4, 9, 10, 11, 12, 17];
        assert_eq!(groups_of(&stamps, 15), vec![0..4, 4..8, 8..9]);
        // A round longer than a group is cut again.
        assert_eq!(groups_of(&stamps, 3), vec![0..3, 3..4, 4..7, 7..8, 8..9]);
    }

    #[test]
    fn groups_cover_a_block_once_none_is_missing() {
        let mut groups = BTreeMap::new();
        groups.insert(0, (4, ()));
        groups.insert(8, (3, ()));
        assert!(!groups_cover(&groups, 11));
        groups.insert(4, (4, ()));
        assert!(groups_cover(&groups, 11));
        assert!(groups_cover(&BTreeMap::<usize, (usize, ())>::new(), 0));
    }

    #[test]
    #[should_panic(expected = "overlaps")]
    fn groups_that_overlap_are_refused() {
        let mut groups = BTreeMap::new();
        groups.insert(0, (4, ()));
        groups.insert(3, (4, ()));
        groups_cover(&groups, 7);
    }
}

/// A machine's nodes of a block's second phase, as [`group_nodes_on_lanes`] proved them.
#[cfg(feature = "cuda")]
struct GroupNodes {
    /// The image node, on the machine that leads the tree.
    image: Option<SchedulerProof>,
    /// The nodes over this machine's groups: a group's first chunk (0-based) to its chunk count
    /// and its node.
    groups: std::collections::BTreeMap<usize, (usize, SchedulerProof)>,
    /// How long the group proofs took, the challenges' derivation included.
    second_phase: Duration,
    /// The steps' pieces and their times, for the log.
    steps: Vec<String>,
}

/// A machine's part of a block's second phase as pieces on its cards' prover lanes: the group
/// proofs over the tables it holds, then their nodes, each step's pieces handed out together.
/// The machine that leads the tree (`leads`) also proves the image group and its node.
///
/// `tables` are the tables this machine holds, by chunk; `group_len` chunks at most go to a
/// group ([`groups_of`]). When the tables are the whole block's (`whole`), the run stops here
/// if the sums the group proofs state do not add up to zero. `None` if the run is drained
/// first.
#[cfg(feature = "cuda")]
#[allow(clippy::too_many_arguments)]
fn group_nodes_on_lanes(
    lanes: &crossbeam::channel::Sender<PrefixPiece>,
    provers: &Arc<Vec<Arc<RiscvMachine>>>,
    nodes: &Arc<
        Vec<
            Arc<
                std::sync::Mutex<pico_vm::mle::machine::global_logup_nodes::GlobalLogUpNodeMachine>,
            >,
        >,
    >,
    vm_vk: &RiscvVmVk,
    tables: std::collections::BTreeMap<u32, pico_vm::mle::machine::global_logup::ChunkTable>,
    chain: &Arc<Vec<ChainDigest>>,
    group_len: usize,
    leads: bool,
    whole: bool,
    verify: bool,
) -> Option<GroupNodes> {
    type Piece<T> = Box<dyn FnOnce(usize) -> T + Send>;

    let t = Instant::now();
    // The second phase: the image group, then the chunk groups. Every machine of a block
    // derives the challenges from the chain's root, behind the same proof-of-work witness.
    let under =
        provers[0].global_challenges(chain.last().expect("the chain has its initial value"));
    let mut steps = vec![format!("challenges {:.3}s", t.elapsed().as_secs_f64())];
    let stamps: Vec<u32> = tables.keys().copied().collect();
    let groups = groups_of(&stamps, group_len);
    let tables: Arc<Vec<_>> = Arc::new(tables.into_values().collect());
    let image = leads.then(|| {
        let provers = Arc::clone(provers);
        let image: Piece<MleProof> = Box::new(move |card| {
            provers[card]
                .prove_global_logup_image(&under)
                .unwrap_or_else(|e| panic!("the global LogUp's second phase failed: {e}"))
        });
        image
    });
    let group_pieces = groups.iter().cloned().map(|group| {
        let (provers, tables) = (Arc::clone(provers), Arc::clone(&tables));
        let group: Piece<MleProof> = Box::new(move |card| {
            provers[card]
                .prove_global_logup_group(&tables[group], &under)
                .unwrap_or_else(|e| panic!("the global LogUp's second phase failed: {e}"))
        });
        group
    });
    let (mut proofs, times) =
        prefix_on_lanes(lanes, image.into_iter().chain(group_pieces).collect())?;
    // Only the group proofs read the tables.
    drop(tables);
    steps.push(piece_times(
        if leads {
            "group proofs (the image group's first)"
        } else {
            "group proofs"
        },
        &times,
    ));
    let group_proofs = proofs.split_off(usize::from(leads));
    let image_proof = proofs.pop();
    let second_phase = t.elapsed();
    assert!(
        !whole
            || pico_vm::mle::machine::global_logup::stated_sums_balance(
                image_proof.iter().chain(&group_proofs)
            ),
        "the global LogUp's prefix failed: the global LogUp does not balance: the block's \
         chunks disagree on a cross-chunk event"
    );

    // The nodes, in the order they lead the tree: the image node, then the groups' from the
    // last to the first.
    // A node piece that panicked on its lane (out of device memory, say) poisons its machine's
    // lock; the machine holds only the keys of nodes that were keygen'd whole, so a later run
    // takes it as it is.
    let pow_witness = under.pow_witness;
    // `first_chunk` counts from one, as the node's witness does; `None` is the image node.
    let node = |first_chunk: Option<usize>, proof: MleProof| {
        let (nodes, vm_vk, chain) = (Arc::clone(nodes), vm_vk.clone(), Arc::clone(chain));
        let node: Piece<SchedulerProof> = Box::new(move |card| {
            let mut machine = nodes[card]
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let deferred_digest = Default::default();
            let node = match first_chunk {
                None => machine
                    .image_witness(&vm_vk, &chain, pow_witness, deferred_digest)
                    .and_then(|witness| machine.prove_image_node(&proof, &witness)),
                Some(first_chunk) => machine
                    .group_witness(&vm_vk, &chain, pow_witness, first_chunk, deferred_digest)
                    .and_then(|witness| machine.prove_group_node(&proof, &witness)),
            }
            .unwrap_or_else(|e| panic!("a node of the global LogUp failed: {e:#}"));
            // Early-failure net only, as for a combine node: a bad group proof shows here, at
            // its node, and not at whatever takes the node in.
            if verify {
                machine.verify(&node).unwrap_or_else(|e| {
                    panic!("a node of the global LogUp failed self-verify: {e:#}")
                });
            }
            node
        });
        node
    };
    let firsts: Vec<usize> = groups
        .iter()
        .map(|group| stamps[group.start] as usize)
        .collect();
    let group_nodes = firsts
        .iter()
        .zip(group_proofs)
        .rev()
        .map(|(&first, proof)| node(Some(first), proof));
    let (mut proved, times) = prefix_on_lanes(
        lanes,
        image_proof
            .map(|proof| node(None, proof))
            .into_iter()
            .chain(group_nodes)
            .collect(),
    )?;
    steps.push(piece_times(
        if leads {
            "nodes (the image node, then the last group's first)"
        } else {
            "nodes (the last group's first)"
        },
        &times,
    ));
    let group_nodes = proved.split_off(usize::from(leads));
    Some(GroupNodes {
        image: proved.pop(),
        groups: groups
            .iter()
            .zip(&firsts)
            .rev()
            .zip(group_nodes)
            .map(|((group, &first), node)| (first - 1, (group.len(), node)))
            .collect(),
        second_phase,
        steps,
    })
}

/// Reduces the nodes that lead a tree, in their order, to one inner node, as pieces on the
/// cards' prover lanes: neighbours pair up layer by layer, an odd one out passing through. An
/// inner node asserts the nodes' continuity and nothing a root does. `None` if the run is
/// drained first.
#[cfg(feature = "cuda")]
fn reduce_on_lanes(
    lanes: &crossbeam::channel::Sender<PrefixPiece>,
    combines: &Arc<Vec<Arc<pico_vm::mle::machine::combine::GpuCombineMachine>>>,
    mut layer: Vec<SchedulerProof>,
    reduction_nodes: &AtomicUsize,
    verify: bool,
    steps: &mut Vec<String>,
) -> Option<SchedulerProof> {
    type Piece<T> = Box<dyn FnOnce(usize) -> T + Send>;

    while layer.len() > 1 {
        let odd = (layer.len() % 2 == 1).then(|| layer.pop().expect("an odd layer has a last"));
        let mut children = layer.into_iter();
        let mut pairs: Vec<Piece<SchedulerProof>> = Vec::new();
        while let Some(left) = children.next() {
            let pair = [left, children.next().expect("an even layer pairs up")];
            let combines = Arc::clone(combines);
            pairs.push(Box::new(move |card| {
                let prepared = combines[card].prepare_node(&pair, false);
                let built = combines[card].build_node_ctx(prepared);
                let node = combines[card]
                    .prove_built_node(built)
                    .unwrap_or_else(|e| panic!("reducing the global LogUp's nodes failed: {e:#}"))
                    .proof;
                if verify {
                    combines[card]
                        .verify_node(&node.1, &node.0)
                        .unwrap_or_else(|e| {
                            panic!(
                                "a node of the global LogUp's reduction failed self-verify: {e:?}"
                            )
                        });
                }
                node
            }));
        }
        reduction_nodes.fetch_add(pairs.len(), Ordering::SeqCst);
        let (mut next, times) = prefix_on_lanes(lanes, pairs)?;
        steps.push(piece_times("a reduction layer", &times));
        next.extend(odd);
        layer = next;
    }
    layer.pop()
}

/// The nodes over the secondary's groups, taken off the exchange as they come until, with this
/// machine's `groups`, they cover the block's `chunks` chunks. Returns how many came, or `None`
/// if the run is drained first.
#[cfg(feature = "cuda")]
fn gather_peer_groups(
    groups: &mut std::collections::BTreeMap<usize, (usize, SchedulerProof)>,
    chunks: usize,
) -> Option<usize> {
    let mut came = 0;
    while !groups_cover(groups, chunks) {
        if get_mle_scheduler().is_aborted() {
            return None;
        }
        for report in exchange().take_nodes(GlobalChain::ABORT_POLL) {
            let node: SchedulerProof = bincode::deserialize(&report.proof).unwrap_or_else(|e| {
                panic!(
                    "the secondary's node over chunks {}..{} does not decode: {e}",
                    report.first_chunk,
                    report.first_chunk + report.chunks
                )
            });
            // A report sent again after an answer that was lost: the first one stands.
            if let std::collections::btree_map::Entry::Vacant(slot) =
                groups.entry(report.first_chunk)
            {
                slot.insert((report.chunks, node));
                came += 1;
            }
        }
    }
    Some(came)
}

/// What the scheduler's proof tree holds: a **convert** proof with its vk.
///
/// The tree exists to pair adjacent proofs into combine tasks, and combine verifies *convert*
/// proofs — so the convert layer, not the riscv layer, is what gets reported. The riscv level
/// reports terminally (payload-free, [`GlobalScheduler::report_chunk_terminal`]) in every mode,
/// which is what keeps the riscv proof type out of this alias. Mirrors FRI, where a chunk task
/// spans riscv+convert inside the worker and the gateway reports the convert proof.
type SchedulerProof = ProofWithVk;

/// One block handed to [`run_pipeline`] from outside, in place of the fixture `--elf`/`--n` names.
///
/// The ethproofs entry point owns the block number (RSP chose it) and the witness bytes (RSP sent
/// them), so it builds the stdin itself; the fixture path in [`stdin_for_block`] stays for the
/// benchmark and sweep entry points. Nothing downstream of the stdin differs between the two.
pub struct BlockJob {
    /// The block this stdin proves. Carried only so a caller need not track it alongside.
    pub block: u64,
    pub stdin: EmulatorStdin,
}

/// What one block produced, for a caller that has to report it somewhere rather than only log it.
///
/// A benchmark run discards this -- the log lines are its product. The ethproofs entry needs the
/// same numbers as DATA, because they become `ProofInfo` fields that a public leaderboard reads.
#[derive(Default)]
pub struct BlockOutcome {
    /// Emulated RISC-V cycles, from `emulate_snapshot_pipeline`'s second return value. Reported to
    /// ethproofs as `proving_cycles`.
    pub cycles: u64,
    /// The `e2e=` window: emulate through the collapsed proof tree, excluding setup and root
    /// acceptance. NOT what gets reported as `proving_time` -- see the ethproofs entry, which
    /// measures from the gRPC boundary because that is the span a verifier can hold us to.
    pub e2e_wall: Duration,
    /// Host-side root acceptance, which follows the `e2e=` window rather than sitting inside it.
    /// Near zero when the root is left to the compress proof (`--step compress` without
    /// `MLE_VERIFY`).
    pub root_accept: Duration,
    /// `None` when `--step` stops before combine (there is no root), when the root is left to the
    /// compress proof (`--step compress` without `MLE_VERIFY`; see the export below), and on an MLE
    /// secondary (the root is proved and accepted on the primary by construction).
    pub root: Option<RootProofExport>,
    /// `--step compress` in whitelist mode: the compress proof, once this process has accepted it
    /// (the CPU compress machine and the standalone apex). The final proof, and much smaller than
    /// the root, so the ethproofs entry submits it whenever it is present.
    pub compress: Option<CompressProofExport>,
    /// The bytes the guest committed, from the emulation. Bound to a proof only by the root's
    /// `committed_value_digest`, which a verifier checks.
    pub committed: Vec<u8>,
    /// Embedded runs only: the guest failed, or a chunk of it was refused, and the run was
    /// drained rather than proved. Nothing it held is left behind, so the next block proves normally.
    pub guest_failure: Option<GuestFailure>,
    /// Embedded runs only: a pipeline thread panicked, with this message, and the run was drained.
    /// Whether the process can prove again is the caller's call ([`embed::prove`]).
    pub stage_failure: Option<String>,
}

/// Why a guest ended an embedded run early: its emulation failed, or a chunk of it cannot be
/// proved. The provers themselves did not fail.
#[derive(Debug)]
pub enum GuestFailure {
    /// The emulator's own error: a non-zero exit, a limit, a bad syscall, short stdin.
    Emulation(pico_vm::emulator::riscv::emulator::EmulationError),
    /// The emulation panicked before any other pipeline thread had failed. Any emulator panic
    /// counts, a host-side emulator bug included: it ends the run without poisoning.
    Panicked(String),
    /// A chunk selects the catch-all whitelist shape, which no card can prove.
    CatchAllShape(pico_vm::mle::machine::riscv::CatchAllShape),
    /// The block's chunks hold more cross-chunk events than one tree's global LogUp may count.
    TooManyGlobalRows(TooManyGlobalRows),
}

/// A block passed the global LogUp's real-row limit (`global_logup::MAX_COUNT`, in its units):
/// `count` is where the chunk that crossed it left the block's count. The tree's root refuses
/// such a block, whatever the provers do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TooManyGlobalRows {
    pub count: u64,
    pub max: u64,
}

impl fmt::Display for TooManyGlobalRows {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the block's chunks hold too many cross-chunk events for one proof: their real-row \
             count for the global LogUp reached {}, and a block may reach {}",
            self.count, self.max
        )
    }
}

impl fmt::Display for GuestFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Emulation(e) => write!(f, "{e}"),
            Self::Panicked(message) => write!(f, "the emulation panicked: {message}"),
            Self::CatchAllShape(e) => write!(f, "{e}"),
            Self::TooManyGlobalRows(e) => write!(f, "{e}"),
        }
    }
}

/// The combine root, packaged so somebody else can verify it.
///
/// The proof bytes are NOT self-contained: `CombineMachine::verify` checks a root against a vk the
/// verifying machine keygen'd itself, so it must first `register_shape(child_layouts, true)`. Ship
/// the layouts with the proof or the recipient has nothing to register and cannot check anything.
pub struct RootProofExport {
    /// `mle-core`'s canonical versioned wire format.
    pub proof: Vec<u8>,
    /// The root node's ORDERED child layouts.
    pub child_layouts: Vec<pico_vm::mle::compiler::recursion::RecursionVkLayout>,
    /// `RiscvVmVk::digest()`, the exe identity the root is pinned against.
    pub riscv_vk_digest: String,
    /// Whitelist mode only: bincode of the root's verifying key. A verifier does not trust it --
    /// the apex accepts it only as a member of the pinned whitelist -- which is what lets the root
    /// be checked from artifacts alone, without the child layouts (and without trusting them).
    pub root_vk: Option<Vec<u8>>,
}

/// The compress proof, packaged so somebody else can verify it. Whitelist mode only: the proof
/// verifies under the whitelist's one compress key, which `pico_verifier` ships
/// (`shipped_compress_vk`), so no key travels with it -- the reason it is so much smaller than a
/// root submission.
pub struct CompressProofExport {
    /// The proof in `mle-core`'s multiproof form, its WHIR Merkle openings deduplicated: the v5
    /// envelope body (`pico_verifier::envelope::MleCompressProofV5`), the compress proof's one wire
    /// form.
    pub proof: Vec<u8>,
    /// `RiscvVmVk::digest()`, the exe identity the proof is pinned against.
    pub riscv_vk_digest: String,
}

/// The compress proof's wire form (the v5 envelope body), checked to rebuild the proof, with its
/// size against the flat encoding logged.
#[cfg(feature = "cuda")]
fn compress_wire_bytes(proof: &ProofWithVk) -> Result<Vec<u8>, String> {
    let body = pico_verifier::envelope::MleCompressProofV5::from_proof(&proof.0, &proof.1)
        .map_err(|e| e.to_string())?;
    if let Ok(flat) = pico_vm::mle::machine::recursion::proof_wire_bytes(&proof.0) {
        info!(
            target: "bench",
            "MLE compress wire: multiproof {} B ({:.2} KiB), flat {} B, {:+.2}%",
            body.proof.len(),
            body.proof.len() as f64 / 1024.0,
            flat.len(),
            100.0 * (body.proof.len() as f64 / flat.len() as f64 - 1.0),
        );
    }
    Ok(body.proof)
}

/// Whether the run is ending without a root: its guest failed (an embedded run), or a pipeline
/// thread panicked. Stages drop what they hold rather than prove it, so the run drains fast.
fn run_stopped(guest_failed: &AtomicBool) -> bool {
    guest_failed.load(Ordering::SeqCst) || watch::failed()
}

/// Deferred records handed to the preparers and not yet taken by a prover (or dropped), which
/// the emulation waits on at a bound. They hold no history slot, so the slots alone let a
/// precompile-heavy guest queue hundreds of GB of them ahead of proving.
#[derive(Default)]
struct DeferredGate {
    waiting: AtomicUsize,
    bound: Option<usize>,
    peak: AtomicUsize,
    parked_us: AtomicU64,
}

/// `MLE_DEFERRED_RECORDS`: deferred records the emulation may run ahead of proving by; `0` lifts
/// the bound. Unset, a low-memory host takes [`host_memory::LOW_MEMORY_DEFERRED_RECORDS`].
const DEFAULT_DEFERRED_RECORDS: usize = 512;

/// The `MLE_DEFERRED_RECORDS` bound, `None` for none; an embedded caller checks it up front, where
/// a bad value poisons nothing.
pub(crate) fn deferred_records_bound() -> Result<Option<usize>, String> {
    let bound = match std::env::var("MLE_DEFERRED_RECORDS") {
        Ok(v) => v
            .trim()
            .parse::<usize>()
            .map_err(|_| format!("MLE_DEFERRED_RECORDS={v}: expected a count of records"))?,
        Err(_) if host_memory::low_memory_host() => host_memory::LOW_MEMORY_DEFERRED_RECORDS,
        Err(_) => DEFAULT_DEFERRED_RECORDS,
    };
    Ok((bound > 0).then_some(bound))
}

impl DeferredGate {
    fn from_env() -> Self {
        Self {
            bound: deferred_records_bound().unwrap_or_else(|e| panic!("{e}")),
            ..Default::default()
        }
    }

    /// Counts one more record in, first waiting below the bound unless the run stops.
    fn admit(&self, stopped: impl Fn() -> bool) {
        let Some(bound) = self.bound else {
            self.count_in();
            return;
        };
        let mut parked: Option<Instant> = None;
        loop {
            let now = self.waiting.load(Ordering::SeqCst);
            if now < bound || stopped() {
                if self
                    .waiting
                    .compare_exchange(now, now + 1, Ordering::SeqCst, Ordering::SeqCst)
                    .is_ok()
                {
                    self.peak.fetch_max(now + 1, Ordering::Relaxed);
                    break;
                }
                continue;
            }
            parked.get_or_insert_with(Instant::now);
            thread::sleep(Duration::from_millis(1));
        }
        if let Some(t) = parked {
            self.parked_us
                .fetch_add(t.elapsed().as_micros() as u64, Ordering::Relaxed);
        }
    }

    fn count_in(&self) {
        let now = self.waiting.fetch_add(1, Ordering::SeqCst) + 1;
        self.peak.fetch_max(now, Ordering::Relaxed);
    }

    /// One record out: taken by a prover, or dropped unproved here.
    fn release(&self) {
        let mut now = self.waiting.load(Ordering::SeqCst);
        while now > 0 {
            match self
                .waiting
                .compare_exchange(now, now - 1, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => break,
                Err(seen) => now = seen,
            }
        }
    }
}

/// The last run's deferred records: the most waiting at once, and how long the emulation parked
/// on the bound. For tests and logs.
static LAST_DEFERRED: std::sync::Mutex<(usize, Duration)> =
    std::sync::Mutex::new((0, Duration::ZERO));

#[doc(hidden)]
pub fn last_run_deferred_records() -> (usize, Duration) {
    *LAST_DEFERRED.lock().unwrap_or_else(|e| e.into_inner())
}

/// Joins a pipeline thread; `None` if it panicked. The CLI gives up on the run's first failure,
/// since its panic hook ends the process; an embedded run waits for the thread, and while the run
/// stops it drops the prepared chunks, whose history slots the emulation needs to reach its stop.
fn join_stage<T>(
    handle: thread::JoinHandle<T>,
    what: &str,
    embedded: bool,
    store: &DashMap<usize, PreparedChunk>,
    guest_failed: &AtomicBool,
) -> Option<T> {
    if !embedded {
        return Some(watch::join(handle, what));
    }
    watch::join_draining(handle, || {
        if run_stopped(guest_failed) {
            store.clear();
        }
    })
}

/// Take a chunk's prepared trace, waiting for the local emulator if it has not got there yet.
///
/// Single-node registered a chunk only after storing it, so acquiring one implied it was present
/// and an `expect` was safe. Two-machine breaks that: the chunk registry is global — the primary's
/// emulator drives it — while the store is per-process, and the two emulators run independently
/// (both emulate the whole block). So either side can be handed a chunk it owns before
/// its OWN emulator has produced the trace. Both machines hit this in turn, as
/// `prepared chunk missing for acquired task`.
///
/// Acquisition means "this chunk is yours", not "your trace is ready". Waiting is therefore the
/// correct reading, not a workaround — the trace is coming, from this machine's own emulator. The
/// timeout keeps a genuine loss (an emulator that died, a chunk index nobody will produce) from
/// becoming a silent hang.
///
/// `None` once the run stops ([`run_stopped`]): a stopped run drops its prepared chunks.
fn take_prepared_chunk(
    store: &DashMap<usize, PreparedChunk>,
    chunk_idx: usize,
    guest_failed: &AtomicBool,
) -> Option<PreparedChunk> {
    if let Some((_, chunk)) = store.remove(&chunk_idx) {
        return Some(chunk);
    }
    let t = Instant::now();
    let deadline = Duration::from_secs(600);
    loop {
        if let Some((_, chunk)) = store.remove(&chunk_idx) {
            info!(
                "chunk {chunk_idx}: waited {:.3}s for the local emulator",
                t.elapsed().as_secs_f64()
            );
            return Some(chunk);
        }
        if run_stopped(guest_failed) {
            return None;
        }
        assert!(
            t.elapsed() < deadline,
            "prepared chunk {chunk_idx} never arrived from this machine's emulator \
             ({}s); it was acquired from the scheduler, so either this machine's emulation \
             stopped early or the chunk index does not exist",
            deadline.as_secs()
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// `VK_VERIFICATION=true`, parsed as the e2e parses it: riscv chunks take whitelist shapes and the
/// recursion machines witness the whitelist. Off by default, as the prover ships.
fn vk_verification() -> bool {
    std::env::var("VK_VERIFICATION").is_ok_and(|v| v.eq_ignore_ascii_case("true"))
}

/// The whitelist artifact (`MLE_VK_MAP`, checked against `MLE_VK_ROOT` by the loader). The GPU
/// pipeline has no self-map fallback: it keygens convert VKs as chunks arrive, so the whitelist
/// must exist before the first proof.
#[cfg(feature = "cuda")]
fn whitelist_map() -> Arc<MleVkMap> {
    let path = std::env::var("MLE_VK_MAP")
        .expect("VK_VERIFICATION=true needs MLE_VK_MAP, the whitelist artifact");
    let map = MleVkMap::load(&path);
    info!(
        "whitelist: `{path}`, {} entries, root = {:?}",
        map.entries.len(),
        map.root()
    );
    Arc::new(map)
}

/// Whether this machine must build a `PreparedChunk` for `chunk_idx`.
///
/// Both machines emulate the whole block — the primary because it registers every chunk with the
/// scheduler, the secondary because records cannot be shipped — but each proves only its share,
/// so preparing the other's chunks is work whose only consumer is the eviction that throws it
/// away. Worse, a prepared chunk holds its record's slot until something drops it, and the other
/// machine's half is dropped only once that machine proves it and reports back: that is what
/// coupled emulation to the peer and made a bound of 64 records stall the emulator.
///
/// Deliberately routed through the scheduler's own predicate rather than re-deriving the split.
/// If this said "not mine" about a chunk the scheduler later handed us, `take_prepared_chunk`
/// would wait on a record that is never coming, so the two must agree by construction and not by
/// two copies of the same rule. Dynamic chunks answer `true` for both machines, which is correct:
/// either may be assigned one, so both must hold it ready.
fn prepares_chunk(chunk_idx: usize) -> bool {
    if !mle_two_machine_requested() {
        return true;
    }
    crate::common::machine_role::get_runtime_mode()
        .worker_can_handle_chunk_for_worker(&get_worker_label(), chunk_idx)
}

/// Whether the caller explicitly asked for MLE two-machine (`two_machine_mle.sh` does), which is
/// what decides if the single-node pin in [`run_pipeline`] is applied. Opt-in and off by
/// default, so single-node keeps the exact behaviour it had when the pin was unconditional.
fn mle_two_machine_requested() -> bool {
    std::env::var("MLE_TWO_MACHINE")
        .map(|v| {
            let v = v.trim().to_ascii_lowercase();
            !(v.is_empty() || v == "0" || v == "false")
        })
        .unwrap_or(false)
}

/// Two prover lanes per card — riscv and recursion — unless `MLE_RECURSION_LANE=0` asks for one.
///
/// Off is not "the second lane idles": the single lane takes riscv, convert and combine on one
/// `select!`, which is the shape the split was carved out of.
///
/// Read ONCE in `run_pipeline` and passed down as a `bool`. Everything derived from it has to
/// agree — which lane is handed the riscv queue, which one holds the [`RiscvLane`] handles, and
/// whether that lane's `items_open` starts live. Two reads of an env that moved in between would
/// give the queue to one lane and the exit condition to another, which does not error, it hangs.
///
/// Both sides are allow-lists, and a value outside them **warns**. That is stricter than the
/// neighbouring readers (`common::parse::env_flag` allows on-words and silently drops the rest;
/// `mle_two_machine_requested` above uses a deny-list), deliberately: this is the only one of the
/// three whose default is ON, so an unrecognised value would leave the faster shape running under
/// someone who had asked for the slower one, and they would have no reason to go looking. The name
/// reads like a count, which makes `MLE_RECURSION_LANE=2` a spelling people reach for — it does not
/// mean "two lanes", and now it says so instead of passing. An empty value reads as unset.
fn recursion_lane_enabled() -> bool {
    recursion_lane_from(std::env::var("MLE_RECURSION_LANE").ok().as_deref())
}

/// The word lists, split out from the read so they can be tested: they are this change's whole
/// user interface, and a value quietly falling through to the default is the failure that costs
/// someone a benchmark. Reading the env itself is not testable in-process — Rust runs tests in
/// threads of one process, so a test that set the variable would race every other test.
fn recursion_lane_from(raw: Option<&str>) -> bool {
    let Some(raw) = raw else { return true };
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "1" | "true" | "yes" | "on" => true,
        "0" | "false" | "no" | "off" => false,
        // `raw`, not the normalised form: the point of this line is to show the reader what they
        // typed, and echoing `" Two "` back as `"two"` hides half of what was wrong with it.
        _ => {
            warn!(
                "MLE_RECURSION_LANE={raw:?} is neither on (1/true/yes/on) nor off \
                 (0/false/no/off); keeping both prover lanes per card"
            );
            true
        }
    }
}

/// Pre-build each chunk's convert verify program during the riscv prove that precedes it —
/// **default ON**, `MLE_CONVERT_PREBUILD=0` restores the pre-change path exactly.
///
/// It ships on because it is measured: 58 paired ratios over 5 queues and 9 blocks put it at
/// **−2.63 % E2E on the production p99 blocks**, re-measured after a rebase at −1.9 to −3.0 %
/// with every cut's interval excluding 1.00. Correctness is unchanged by construction — the
/// program is a pure function of the layout, so pre-building computes the same program earlier,
/// and a pre-build that turns out wrong is discarded by the consumer's own equality check.
///
/// Same allow-list treatment as [`recursion_lane_from`], and for the same reason: this default is
/// ON, so an unrecognised value would silently leave the new path running under someone who asked
/// for the old one while they were trying to bisect a regression. An empty value reads as unset.
#[cfg(feature = "cuda")]
fn convert_prebuild_enabled() -> bool {
    convert_prebuild_from(std::env::var("MLE_CONVERT_PREBUILD").ok().as_deref())
}

/// The card a convert chunk belongs to: drawn round-robin the first time anyone asks, and
/// remembered so the pre-build and the preparer agree.
///
/// Both sides go through this. If they each drew for themselves the counter would advance twice
/// per chunk and the preparer would only ever see every other card — the same halving the routing
/// comment in the preparer warns about. The map is never pruned: it is one entry per chunk, and
/// removing on read would reintroduce the double draw for a chunk pre-built after its preparer ran.
///
/// Ungated so the tests below can reach it without CUDA — the double draw it exists to prevent is
/// a property of the counter and the map, not of any device.
#[cfg_attr(not(feature = "cuda"), allow(dead_code))]
fn convert_card_for(
    chunk_idx: usize,
    claimed: &DashMap<usize, usize>,
    card_rr: &AtomicUsize,
    cards: usize,
) -> usize {
    *claimed
        .entry(chunk_idx)
        .or_insert_with(|| card_rr.fetch_add(1, Ordering::Relaxed) % cards)
}

/// `MLE_CONVERT_PREBUILD_PK` has the pre-build warm the device proving key as well as the program.
/// **Default ON**, `MLE_CONVERT_PREBUILD_PK=0` restores the program-only pre-build.
///
/// It ships on because it is measured: with the combine half below, fourteen paired runs over the
/// p99 blocks put the two at **-2.15 % E2E**, eleven pairs faster, one tied, two slower, with peak
/// VRAM unchanged. What it costs is that those workers bind a card and do device work, which the
/// program half deliberately avoids — see [`ConvertPrebuild`].
///
/// Same allow-list treatment as [`convert_prebuild_from`], and for the same reason: the default is
/// ON, so an unrecognised value must not silently leave the new path running under someone who
/// asked for the old one.
#[cfg(feature = "cuda")]
fn convert_prebuild_pk_enabled() -> bool {
    convert_prebuild_from(std::env::var("MLE_CONVERT_PREBUILD_PK").ok().as_deref())
}

/// Split from the read so the word lists are testable; reading the env in-process is not, because
/// Rust runs tests as threads of one process and a test that set the variable would race.
///
/// Ungated so `cargo test -p distributed-vm` runs its tests without CUDA, exactly as the sibling
/// `recursion_lane_from` does — the word lists are this flag's whole user interface, and a
/// mistyped value silently keeping the new path on is what they exist to catch.
#[cfg_attr(not(feature = "cuda"), allow(dead_code))]
fn convert_prebuild_from(raw: Option<&str>) -> bool {
    let Some(raw) = raw else { return true };
    match raw.trim().to_ascii_lowercase().as_str() {
        "" | "1" | "true" | "yes" | "on" => true,
        "0" | "false" | "no" | "off" => false,
        _ => {
            warn!(
                "MLE_CONVERT_PREBUILD={raw:?} is neither on (1/true/yes/on) nor off \
                 (0/false/no/off); keeping the convert pre-build enabled"
            );
            true
        }
    }
}

#[cfg(test)]
mod convert_prebuild_tests {
    use super::{convert_card_for, convert_prebuild_from};
    use dashmap::DashMap;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    #[test]
    fn unset_and_empty_leave_the_prebuild_on() {
        assert!(convert_prebuild_from(None));
        assert!(convert_prebuild_from(Some("")));
        assert!(convert_prebuild_from(Some("   ")));
    }

    #[test]
    fn every_off_word_turns_the_prebuild_off() {
        for v in ["0", "false", "no", "off", " OFF ", "False"] {
            assert!(!convert_prebuild_from(Some(v)), "{v:?} should turn it off");
        }
    }

    #[test]
    fn every_on_word_leaves_it_on() {
        for v in ["1", "true", "yes", "on", " ON ", "True"] {
            assert!(convert_prebuild_from(Some(v)), "{v:?} should leave it on");
        }
    }

    #[test]
    fn a_value_in_neither_list_keeps_the_default() {
        // The kill switch is what someone reaches for mid-bisect; a typo in it must not read as
        // "off" by accident, and must not pass silently either.
        for v in ["disabled", "none", "nope", "-1", "2"] {
            assert!(
                convert_prebuild_from(Some(v)),
                "{v:?} should keep the default"
            );
        }
    }

    #[test]
    fn a_chunks_card_is_drawn_once_however_many_callers_ask() {
        let claimed = DashMap::new();
        let rr = AtomicUsize::new(0);

        // The pre-build and the preparer both ask for the same chunk: one draw, one answer. Two
        // draws would advance the counter twice per chunk and hand the preparer every other card.
        let first = convert_card_for(7, &claimed, &rr, 4);
        assert_eq!(convert_card_for(7, &claimed, &rr, 4), first);
        assert_eq!(rr.load(Ordering::Relaxed), 1);

        // And over a run the cards still come out round-robin, not halved.
        let cards: Vec<usize> = (0..8)
            .map(|c| convert_card_for(c, &claimed, &rr, 4))
            .collect();
        assert_eq!(cards, vec![1, 2, 3, 0, 1, 2, 3, 0]);
    }

    #[test]
    fn concurrent_askers_still_draw_a_chunks_card_once() {
        let claimed = Arc::new(DashMap::new());
        let rr = Arc::new(AtomicUsize::new(0));
        let seen: Vec<usize> = std::thread::scope(|s| {
            (0..16)
                .map(|_| {
                    let (claimed, rr) = (Arc::clone(&claimed), Arc::clone(&rr));
                    s.spawn(move || convert_card_for(3, &claimed, &rr, 4))
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|h| h.join().expect("asker panicked"))
                .collect()
        });
        assert!(
            seen.iter().all(|&c| c == seen[0]),
            "one chunk, one card: {seen:?}"
        );
        assert_eq!(rr.load(Ordering::Relaxed), 1);
    }
}

#[cfg(test)]
mod recursion_lane_tests {
    use super::recursion_lane_from;

    #[test]
    fn unset_and_empty_leave_both_lanes_on() {
        assert!(recursion_lane_from(None));
        assert!(recursion_lane_from(Some("")));
        assert!(recursion_lane_from(Some("   ")));
    }

    #[test]
    fn every_off_word_turns_the_lane_off() {
        for v in ["0", "false", "no", "off", " OFF ", "False"] {
            assert!(!recursion_lane_from(Some(v)), "{v:?} should turn it off");
        }
    }

    #[test]
    fn every_on_word_leaves_it_on() {
        for v in ["1", "true", "yes", "on", " ON ", "True"] {
            assert!(recursion_lane_from(Some(v)), "{v:?} should leave it on");
        }
    }

    #[test]
    fn a_value_in_neither_list_keeps_the_default() {
        // `2` is the one that matters: the name reads like a count, so it is a spelling people
        // reach for, and it is NOT "two lanes". It keeps the default and warns rather than being
        // read as an off word.
        for v in ["2", "disabled", "none", "nope", "-1"] {
            assert!(
                recursion_lane_from(Some(v)),
                "{v:?} should keep the default"
            );
        }
    }
}

/// The engine the snapshot pipeline's replay workers run, once per process.
/// `MLE_REPLAY_WORKERS=aot` replays each chunk on the AOT-compiled guest's recording bodies;
/// `=interpreter`, on the interpreter. Unset or empty means `aot` when this process registered a
/// program with recording bodies, and the interpreter otherwise (a build without `aot-emulator`, or
/// a refused registration). Both write the same records into the same history slots.
///
/// Both binaries call this right after registering the AOT program, so a value the process cannot
/// honour stops it before any setup. An explicit `aot` never falls back, since a fallback would run
/// under the name of the arm that was asked for; only the unset default picks the interpreter when
/// nothing is registered. This line names the process default; an embedded run that passes its own
/// options can differ, and what each block's replay actually ran is the pipeline's own `bench` line
/// (`emulate_snapshot_pipeline_with`).
pub fn replay_workers() -> ReplayWorkers {
    static RESOLVED: std::sync::OnceLock<ReplayWorkers> = std::sync::OnceLock::new();
    *RESOLVED.get_or_init(|| {
        let workers = replay_workers_from(
            std::env::var("MLE_REPLAY_WORKERS").ok().as_deref(),
            aot_registered(),
        )
        .unwrap_or_else(|e| panic!("{e}"));
        info!(
            target: "bench",
            "MLE replay workers: {}",
            match workers {
                ReplayWorkers::Aot => "aot",
                ReplayWorkers::Interpreter => "interpreter",
            }
        );
        workers
    })
}

/// What this process registered for the replay workers.
#[derive(Clone, Copy)]
struct AotRegistered {
    /// The snapshot thread's factory, installed for any program `pico_aot_runtime::register`
    /// accepts.
    program: bool,
    /// The replay workers' factory, installed only for a program with a recording entry point.
    replay: bool,
}

#[cfg(feature = "aot-emulator")]
fn aot_registered() -> AotRegistered {
    use pico_vm::emulator::aot;
    let program = aot::is_aot_factory_registered();
    AotRegistered {
        program,
        replay: program && aot::is_aot_replay_factory_registered(),
    }
}

/// Without `aot-emulator` no AOT program can register.
#[cfg(not(feature = "aot-emulator"))]
fn aot_registered() -> AotRegistered {
    AotRegistered {
        program: false,
        replay: false,
    }
}

/// Split from the read for the same reason as [`recursion_lane_from`]: the refusals are this
/// switch's whole interface, and a test that set the variable would race the others in-process.
fn replay_workers_from(
    raw: Option<&str>,
    registered: AotRegistered,
) -> Result<ReplayWorkers, String> {
    let word = raw.map(|raw| raw.trim().to_ascii_lowercase());
    let no_program = |word: &str| {
        format!(
            "MLE_REPLAY_WORKERS={word}, and this process registered no AOT program: it was built \
             without aot-emulator, or the registration was refused (logged above); set \
             MLE_REPLAY_WORKERS=interpreter"
        )
    };
    match word.as_deref() {
        None | Some("") if registered.replay => Ok(ReplayWorkers::Aot),
        None | Some("") | Some("interpreter") => Ok(ReplayWorkers::Interpreter),
        Some("aot") if registered.replay => Ok(ReplayWorkers::Aot),
        Some("aot") if registered.program => Err(
            "MLE_REPLAY_WORKERS=aot, and the registered AOT program has no recording entry point, \
             which the AOT replay workers run: regenerate it from the guest's ELF, or set \
             MLE_REPLAY_WORKERS=interpreter"
                .into(),
        ),
        Some("aot") => Err(no_program("aot")),
        Some("aot-recorder") => Err(
            "MLE_REPLAY_WORKERS=aot-recorder was removed: the AOT replay workers run the recording \
             bodies as aot; set MLE_REPLAY_WORKERS=aot"
                .into(),
        ),
        Some(_) => Err(format!(
            "MLE_REPLAY_WORKERS={:?} names no replay engine: expected aot or interpreter",
            raw.unwrap_or_default()
        )),
    }
}

#[cfg(test)]
mod replay_workers_tests {
    use super::{replay_workers_from, AotRegistered};
    use pico_vm::emulator::opts::ReplayWorkers;

    const NONE: AotRegistered = AotRegistered {
        program: false,
        replay: false,
    };
    /// A program without a recording entry point.
    const PROGRAM: AotRegistered = AotRegistered {
        program: true,
        replay: false,
    };
    const REPLAY: AotRegistered = AotRegistered {
        program: true,
        replay: true,
    };

    #[test]
    fn unset_and_empty_are_aot_with_a_registered_replay_program() {
        for raw in [None, Some(""), Some("  ")] {
            assert_eq!(replay_workers_from(raw, REPLAY), Ok(ReplayWorkers::Aot));
        }
    }

    #[test]
    fn unset_and_empty_are_the_interpreter_without_one() {
        // No program (a build without aot-emulator, or a refused registration), or a program
        // without a recording entry point: the default never refuses, it takes the interpreter.
        for raw in [None, Some(""), Some("  ")] {
            for registered in [NONE, PROGRAM] {
                assert_eq!(
                    replay_workers_from(raw, registered),
                    Ok(ReplayWorkers::Interpreter)
                );
            }
        }
    }

    #[test]
    fn each_engine_by_name() {
        for registered in [NONE, PROGRAM, REPLAY] {
            for raw in ["interpreter", " Interpreter "] {
                assert_eq!(
                    replay_workers_from(Some(raw), registered),
                    Ok(ReplayWorkers::Interpreter)
                );
            }
        }
        for raw in ["aot", " AOT "] {
            assert_eq!(
                replay_workers_from(Some(raw), REPLAY),
                Ok(ReplayWorkers::Aot)
            );
        }
    }

    #[test]
    fn aot_without_a_registered_program_refuses() {
        let err = replay_workers_from(Some("aot"), NONE).unwrap_err();
        assert!(err.contains("registered no AOT program"), "{err}");
        assert!(err.contains("=aot,"), "{err}");
    }

    #[test]
    fn aot_without_a_recording_entry_point_refuses() {
        let err = replay_workers_from(Some("aot"), PROGRAM).unwrap_err();
        assert!(err.contains("no recording entry point"), "{err}");
        assert!(err.contains("MLE_REPLAY_WORKERS=interpreter"), "{err}");
    }

    #[test]
    fn aot_recorder_is_refused_for_aot() {
        for raw in ["aot-recorder", " AOT-Recorder "] {
            for registered in [NONE, PROGRAM, REPLAY] {
                let err = replay_workers_from(Some(raw), registered).unwrap_err();
                assert!(err.contains("aot-recorder was removed"), "{raw:?}: {err}");
                assert!(
                    err.ends_with("set MLE_REPLAY_WORKERS=aot"),
                    "{raw:?}: {err}"
                );
            }
        }
    }

    #[test]
    fn any_other_word_refuses() {
        for raw in [
            "bogus",
            "interp",
            "1",
            "0",
            "true",
            "on",
            "recorder",
            "aot_recorder",
        ] {
            for registered in [NONE, PROGRAM, REPLAY] {
                let err = replay_workers_from(Some(raw), registered).unwrap_err();
                assert!(err.contains(&format!("{raw:?}")), "{err}");
            }
        }
    }
}

/// One item of GPU prove work, taken off one queue shared by every card, FIFO, no polling.
///
/// Which thread does the taking is what [`recursion_lane_enabled`] switches: the card's riscv lane
/// by default, or its single prover lane when the recursion lane is off. Prepare-kind work stays on
/// the CPU preparer pools either way. Combine work is not a variant here: the dispatcher routes
/// combine tasks to the combine preparers, whose output reaches the prover on its own ready lane as
/// [`CombineWork`].
enum ProverItem {
    /// A riscv chunk, by index — the `PreparedChunk` is resolved from the store at prove time, so
    /// buffering these descriptors costs no VRAM.
    Riscv { chunk_idx: usize },
}

/// Bind a prover thread to its card and to its telemetry lane. Every prover thread does this: the
/// device binding is per thread (the machines' keys are device-`k` resident and the ctxs routed
/// here were built on card `k`), and the lane id is what every span this thread records is keyed
/// on -- two threads sharing one would record over each other.
fn bind_prover_lane(k: usize, role: Role) {
    #[cfg(feature = "cuda")]
    pico_vm::mle::cuda_mle::runtime::context::set_device(k as i32)
        .unwrap_or_else(|e| panic!("{}-{k} could not bind card {k}: {e:?}", role.as_str()));
    spans::bind_lane(LaneId::new(role, k));
}

/// What the riscv lane's hook sends a pre-build worker: the chunk and its per-air heights.
#[cfg(feature = "cuda")]
type PrebuildTx = crossbeam::channel::Sender<(usize, Vec<Option<usize>>)>;

#[cfg(feature = "cuda")]
impl Drop for ConvertPrebuild {
    /// The backstop for the early returns between the explicit shutdown and the end of the
    /// pipeline: the machines outlive this pool, so no worker may still be keygening into them.
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Off-critical-path convert **program** pre-builds.
///
/// The riscv lane learns a chunk's committed trace heights when trace-gen returns, early in the
/// prove, and those heights fully determine the chunk's convert layout. Building the convert
/// verify program is the dominant term of a convert keygen miss and is pure CPU work on a
/// card-independent input, so building it during the rest of the prove takes it off the tail's
/// critical path.
///
/// A pool and not a spawn-per-chunk: the send has to be microseconds because it happens **on the
/// proving thread**, mid-prove. Width defaults to the card count — one chunk is in flight per card
/// and each wants its pre-build finished inside its own prove, so a width of 1 would serialise
/// those builds past the slack available.
///
/// Bounded and non-blocking by construction: the queue is unbounded and `send` never waits, and
/// nothing downstream depends on a pre-build completing. If a build is late, or the flag is off,
/// or the pool is saturated, the convert preparer simply builds the program itself exactly as it
/// does today. The program half is a pure host computation, so a dropped one costs only the CPU.
///
/// The key half (`MLE_CONVERT_PREBUILD_PK`, on by default) is not that cheap and not that inert: it
/// binds a card, runs the real keygen, and holds the card's pk-cache lock while it does — so a
/// preparer that would have hit the cache on that card can wait behind it, and a keygen that panics
/// takes the run with it, since the binary's panic hook exits the process. `=0` turns it off.
///
/// Under `MLE_CONVERT_PREBUILD_PK` a worker additionally warms the device proving key, and then
/// the card stops being irrelevant: a key lives on one card, so the worker claims the chunk's card
/// from the counter the preparers draw from and leaves it in the map for the preparer to follow.
#[cfg(feature = "cuda")]
struct ConvertPrebuild {
    /// Taken by [`Self::shutdown`]: dropping the last sender is what wakes the workers out of
    /// `recv`, so it cannot live on as a field while the shutdown waits for them.
    tx: std::sync::Mutex<Option<PrebuildTx>>,
    /// Set by [`Self::shutdown`]; a worker checks it before taking on more speculative work.
    stop: Arc<AtomicBool>,
    workers: std::sync::Mutex<Vec<thread::JoinHandle<()>>>,
}

#[cfg(feature = "cuda")]
impl ConvertPrebuild {
    /// `MLE_CONVERT_PREBUILD` gates the whole mechanism — **default ON**, `=0` is the kill switch.
    /// `MLE_CONVERT_PREBUILDERS` overrides the pool width. Returns `None` when disabled, in which
    /// case the riscv lane takes the unhooked path and the pre-change behaviour is restored
    /// exactly.
    fn new(
        machines: Vec<Arc<GpuConvertMachine>>,
        card_rr: Arc<AtomicUsize>,
        claimed: Arc<DashMap<usize, usize>>,
        lane_base: usize,
    ) -> Option<Self> {
        let cards = machines.len();
        if !convert_prebuild_enabled() {
            return None;
        }
        let width = std::env::var("MLE_CONVERT_PREBUILDERS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(cards)
            .max(1);
        let warm_pk = convert_prebuild_pk_enabled();
        let stop = Arc::new(AtomicBool::new(false));
        let mut workers = Vec::with_capacity(width);
        let (tx, rx) = crossbeam::channel::unbounded::<(usize, Vec<Option<usize>>)>();
        for w in 0..width {
            let rx = rx.clone();
            let machines = machines.clone();
            let card_rr = Arc::clone(&card_rr);
            let claimed = Arc::clone(&claimed);
            let stop = Arc::clone(&stop);
            workers.push(
                std::thread::Builder::new()
                    .name(format!("convert-prebuild-{w}"))
                    .spawn_watched(move || {
                        // Its own lane, of the preparers' role but past their indices: the keygen
                        // this thread does is convert preparation, and a span opened on a thread
                        // that binds no lane is dropped — which would take these keygens out of the
                        // record, and out of any comparison of the kinds of work two runs exported.
                        spans::bind_lane(LaneId::new(Role::ConvertPreparer, lane_base + w));
                        while let Some((chunk_idx, heights)) =
                            recv_idle(&rx, WorkKind::PrepareConvert)
                        {
                            let _b = spans::busy(WorkKind::PrepareConvert, Some(chunk_idx as u32));
                            // Speculative work only, so a backlog is dropped rather than drained: a
                            // key built after the pipeline has moved on lands in the NEXT block's
                            // cache (the machines are resident) and evicts an entry someone needs.
                            if stop.load(Ordering::Relaxed) {
                                break;
                            }
                            if !warm_pk {
                                // No card is bound and none is needed: `prebuild_program` touches no
                                // device and takes no pk-cache lock, so this thread cannot block a
                                // prove or a keygen.
                                machines[0].prebuild_program(&heights);
                                continue;
                            }
                            // Claim the chunk's card from the counter the preparer draws from, so the
                            // key lands on the card that will prove the node and the round-robin
                            // balance is the one this arm's control has.
                            let card =
                                convert_card_for(chunk_idx, &claimed, &card_rr, machines.len());
                            if let Err(e) =
                                pico_vm::mle::cuda_mle::runtime::context::set_device(card as i32)
                            {
                                warn!("convert pre-build: binding to card {card} failed: {e:?}");
                                continue;
                            }
                            machines[card].prebuild_pk(&heights);
                        }
                    })
                    .expect("spawning a convert pre-build worker"),
            );
        }
        info!("MLE convert prebuild: {width} worker(s) ({cards} card(s), pk = {warm_pk})");
        Some(Self {
            tx: std::sync::Mutex::new(Some(tx)),
            stop,
            workers: std::sync::Mutex::new(workers),
        })
    }

    /// A sender for the riscv lane's hook, or `None` once the pool has been shut down.
    fn sender(&self) -> Option<PrebuildTx> {
        self.tx
            .lock()
            .expect("convert pre-build sender poisoned")
            .clone()
    }

    /// Stop taking new work and wait for whatever is in flight, before the caller's machines are
    /// handed to the next block. One in-flight keygen is bounded; the queue behind it is dropped.
    fn shutdown(&self) {
        self.stop.store(true, Ordering::Relaxed);
        // Drop the pool's own sender first. The lanes' clones went with the lanes, so this is the
        // last one, and only then does `recv` return `Err` and let a parked worker see `stop`.
        drop(
            self.tx
                .lock()
                .expect("convert pre-build sender poisoned")
                .take(),
        );
        for h in self
            .workers
            .lock()
            .expect("convert pre-build worker list poisoned")
            .drain(..)
        {
            let _ = h.join();
        }
    }
}

/// A card's riscv proving: the handles a chunk prove needs, and the prove.
///
/// A struct rather than a free function's argument list because both lane shapes run exactly this
/// body -- the riscv lane's own thread by default, the single prover lane's riscv arm under
/// `MLE_RECURSION_LANE=0` -- and a body written out at both sites is where the two would drift.
///
/// Exactly ONE thread per card may hold it. It owns a `convert_tx` clone, and a spare clone parked
/// on a lane that never sends would keep the convert preparers' channel open past the last chunk:
/// the convert chain could then never drain and the final join would hang.
struct RiscvLane {
    /// Where each chunk's Global table commitment is recorded for the chain its convert leaf and
    /// the tree's prefix need; `None` when no convert follows.
    #[cfg(feature = "cuda")]
    global_chain: Option<Arc<GlobalChain>>,
    store: Arc<DashMap<usize, PreparedChunk>>,
    prover: Arc<RiscvMachine>,
    convert_tx: Option<crossbeam::channel::Sender<(usize, MleProof)>>,
    prove_nanos: Arc<AtomicU64>,
    prove_count: Arc<AtomicUsize>,
    verify: bool,
    with_combine: bool,
    /// Set once an embedded run's guest fails: see [`run_stopped`].
    guest_failed: Arc<AtomicBool>,
    deferred: Arc<DeferredGate>,
    /// Set only when `MLE_CONVERT_PREBUILD` is on. Shared by every card's riscv lane: the
    /// pre-build reads only `riscv_vk` (identical on every card) and writes into a
    /// PROCESS-GLOBAL program cache, so which card's machine backs it is irrelevant — which is
    /// exactly what makes the hoist survive the convert preparers picking a card round-robin.
    #[cfg(feature = "cuda")]
    convert_prebuild: Option<Arc<ConvertPrebuild>>,
}

/// When each prepared chunk was registered with the scheduler, kept only while the prover readings
/// are switched on, so its pick-up can say how long it waited.
static READY_AT: std::sync::LazyLock<DashMap<usize, Instant>> =
    std::sync::LazyLock::new(DashMap::new);

/// Whether the prover readings are switched on; a build without `cuda` has none to take.
fn readings_on() -> bool {
    #[cfg(feature = "cuda")]
    return pico_vm::mle::spans::device::switched_on();
    #[cfg(not(feature = "cuda"))]
    false
}

#[cfg(feature = "cuda")]
use pico_vm::mle::spans::device::TARGET as READINGS_TARGET;
#[cfg(not(feature = "cuda"))]
const READINGS_TARGET: &str = "gpu_tracegen";

/// How many chunks are still on the shared chunk lane as a riscv lane takes one, when the prover
/// readings are switched on.
fn lane_depth(items: &crossbeam::channel::Receiver<ProverItem>) -> Option<usize> {
    readings_on().then(|| items.len())
}

/// One pick-up from the shared chunk lane: what is still queued on the lane and in the scheduler's
/// cost-ordered queue, what was taken and its cost key, and how long it waited since registration.
fn log_pickup(chunk_idx: usize, worker_id: &str, depth: usize, chunk: &PreparedChunk) {
    let waited_us = READY_AT
        .remove(&chunk_idx)
        .map(|(_, t)| t.elapsed().as_micros().to_string());
    info!(
        target: READINGS_TARGET,
        "[queue-pickup] chunk={chunk_idx} pv_chunk={} lane={worker_id} queue.depth={depth} \
         queue.scheduler_depth={} queue.kind={} cost={} wait_us={}",
        chunk.record.chunk_index().saturating_sub(1),
        get_mle_scheduler().queued_chunks(),
        if chunk.record.is_cpu_chunk {
            "cpu"
        } else {
            "deferred"
        },
        chunk.cost,
        waited_us.as_deref().unwrap_or("unknown"),
    );
}

/// The shared chunk lane's capacity: one per card, or `MLE_CHUNK_CHANNEL_CAPACITY` when set. Zero
/// would make the lane a rendezvous, which the riscv lane's "is a chunk waiting" test cannot see.
fn chunk_channel_capacity(cards: usize) -> usize {
    match pico_vm::mle::env_u32("MLE_CHUNK_CHANNEL_CAPACITY") {
        None => cards,
        Some(0) => {
            warn!("MLE_CHUNK_CHANNEL_CAPACITY=0 would make the chunk lane a rendezvous; using {cards}");
            cards
        }
        Some(capacity) => {
            info!(target: "bench", "[chunk-lane] capacity={capacity} (MLE_CHUNK_CHANNEL_CAPACITY)");
            capacity as usize
        }
    }
}

impl RiscvLane {
    /// Prove one chunk and hand the proof on. `worker_id` is the calling lane's, so the `[bench]`
    /// lines are keyed on the thread that actually did the work under either shape.
    fn prove(&self, chunk_idx: usize, worker_id: &str, depth: Option<usize>) {
        if run_stopped(&self.guest_failed) {
            return;
        }
        let _b = spans::busy(WorkKind::ProveRiscv, Some(chunk_idx as u32));
        let Some(chunk) = take_prepared_chunk(&self.store, chunk_idx, &self.guest_failed) else {
            return;
        };
        if !chunk.record.is_cpu_chunk {
            self.deferred.release();
        }
        inject::at(inject::Stage::Prove);
        if let Some(depth) = depth {
            log_pickup(chunk_idx, worker_id, depth, &chunk);
        }
        let t = Instant::now();
        // Unlike the convert arm, this timer CANNOT exclude the debug-only verify: `verify` is a
        // parameter of `prove`, not a separate call, so hoisting it out would mean changing the
        // prove signature for a path only `MLE_VERIFY=1` takes. Consequence, stated rather than
        // hidden: under `MLE_VERIFY=1` this figure includes the verify it would be used to judge.
        // Benchmarks set `MLE_VERIFY=0`, so no published number is affected.
        // The hook fires the moment trace-gen has fixed this chunk's committed heights and its
        // Global table's commitment, before the commit of the rest starts. The chain steps over
        // the commitment then, and the convert program build overlaps the remaining ~505 ms of
        // this very prove. A chain step and a `send` on an unbounded channel are the only work
        // done on this thread; a secondary's report to the primary is sent off it.
        #[cfg(feature = "cuda")]
        let proof = {
            // One look at the sender, not two: it can be taken by the pool's shutdown at any
            // moment, and a `None` here just means this chunk proves without a pre-build.
            let prebuild = self.convert_prebuild.as_ref().and_then(|pb| pb.sender());
            let (stamp, prover) = (chunk.record.public_values.chunk, &self.prover);
            // The chain is over the chunks in the order of their stamps, which the scheduler's
            // indices follow from zero.
            assert_eq!(
                stamp as usize,
                chunk_idx + 1,
                "chunk {chunk_idx} of the scheduler is stamped {stamp}"
            );
            let global_chain = self.global_chain.as_deref();
            // A two-machine secondary: the primary's chain is over this chunk too, and its count
            // of the block's real rows takes this chunk's share.
            let peer_share = (global_chain.is_some() && is_mle_secondary())
                .then(|| prover.chunk_global_row_count(&chunk));
            let traced = std::sync::OnceLock::new();
            let hook = |heights: Vec<Option<usize>>| {
                if let Some(global_chain) = global_chain {
                    let commit = prover
                        .chunk_table_commit(stamp)
                        .expect("a traced chunk has its Global table committed");
                    global_chain.record(chunk_idx, commit);
                    if let Some(row_count) = peer_share {
                        mle_report_chunk_table(ChunkTableReport {
                            chunk_idx,
                            commit: encode_commit(&commit),
                            row_count,
                        });
                    }
                    let _ = traced.set(commit);
                }
                // A full queue cannot happen (unbounded) and a hung-up receiver only means the
                // workers are gone; either way a dropped pre-build is a no-op, because the
                // convert preparer builds the program itself on a miss.
                if let Some(tx) = &prebuild {
                    let _ = tx.send((chunk_idx, heights));
                }
            };
            let proof = chunk.prove_hooked(&self.prover, self.verify, Some(&hook));
            if let Some(global_chain) = global_chain {
                assert_eq!(
                    global_chain.commit_of(&proof),
                    traced.get().copied(),
                    "chunk {chunk_idx}'s proof does not open the Global table its traces committed"
                );
            }
            proof
        };
        #[cfg(not(feature = "cuda"))]
        let proof = chunk.prove(&self.prover, self.verify);
        let elapsed = t.elapsed();
        self.prove_nanos
            .fetch_add(elapsed.as_nanos() as u64, Ordering::SeqCst);
        self.prove_count.fetch_add(1, Ordering::SeqCst);
        // Per-chunk bench line, format-aligned with the FRI prover's `riscv-gpu-prover: running=`
        // lines for side-by-side extraction.
        info!(
            target: "bench",
            "[bench][{worker_id}](chunk-{chunk_idx}) mle-gpu-prover: running={} ms",
            elapsed.as_millis()
        );
        // `MLE_BREAKDOWN` one-line per-chunk phase split (us), mirroring the FRI prover's
        // `(Prep/Commit/...)` line. `residual = total - sum(measured)` captures un-instrumented
        // glue (H2D / transcript / alloc). zerocheck is folded into rap_constraints.
        #[cfg(feature = "cuda")]
        if pico_vm::mle::cuda_mle::breakdown::enabled() {
            let (tracegen, commit, rap, openings) = pico_vm::mle::cuda_mle::breakdown::take();
            let total = elapsed.as_micros() as u64;
            let residual = total.saturating_sub(tracegen + commit + rap + openings);
            info!(
                target: "bench",
                "[bench][{worker_id}](chunk-{chunk_idx}) mle-breakdown: total={total}us \
                 (tracegen={tracegen} commit={commit} rap_constraints={rap} \
                 openings={openings} residual={residual})"
            );
        }
        match (&self.convert_tx, self.with_combine) {
            // Combine mode: this chunk task spans riscv + convert (the FRI shape), so it is NOT
            // reported here — the convert prove reports the convert proof, which is what enters the
            // proof tree. `in_flight` therefore stays held across both halves, which is also what
            // stops completion from latching early.
            (Some(convert_tx), true) => convert_tx
                .send((chunk_idx, proof))
                .expect("convert preparer hung up"),
            // Convert-only: the riscv proof flows into the convert pipeline; the scheduler keeps its
            // riscv-level bookkeeping via the terminal report, and convert completion is joined via
            // the channels draining.
            (Some(convert_tx), false) => {
                mle_report_chunk_terminal(chunk_idx);
                convert_tx
                    .send((chunk_idx, proof))
                    .expect("convert preparer hung up");
            }
            // Riscv-only: chunk proofs are terminal. Payload-free by design — this is exactly what
            // `report_proof`'s no-combine branch does (it drops the proof anyway), and it keeps the
            // riscv proof type out of the scheduler's `P`.
            (None, _) => mle_report_chunk_terminal(chunk_idx),
        }
        info!("[{worker_id}] chunk {chunk_idx}: MLE prove OK");
    }
}

/// A card's recursion proving: the machines a convert or a combine node needs, the counters they
/// report into, and the two run-wide flags they read.
///
/// A struct rather than an argument list for the same reason as [`RiscvLane`]: both of the card's
/// lanes can run exactly this body -- the recursion lane always, the riscv lane once no further
/// chunk can arrive -- and a body written out at both sites is where the two would drift.
///
/// Unlike [`RiscvLane`] it may be held by more than one thread at a time: it owns no sender, so a
/// spare handle keeps no channel open.
#[cfg(feature = "cuda")]
struct CardRecursion {
    convert: Option<Arc<GpuConvertMachine>>,
    combine: Option<Arc<pico_vm::mle::machine::combine::GpuCombineMachine>>,
    root_slot: Arc<std::sync::Mutex<Option<RootRecord>>>,
    convert_prove_nanos: Arc<AtomicU64>,
    convert_done: Arc<AtomicUsize>,
    combine_nanos: Arc<AtomicU64>,
    combine_count: Arc<AtomicUsize>,
    verify: bool,
    with_combine: bool,
    guest_failed: Arc<AtomicBool>,
}

#[cfg(feature = "cuda")]
impl CardRecursion {
    /// Prove one convert off this card's ready lane. `worker_id` is the calling lane's, so the
    /// `[bench]` line names the thread that did the work rather than the card.
    fn prove_convert(&self, chunk_idx: usize, work: ConvertWork, worker_id: &str) {
        let Self {
            convert,
            convert_prove_nanos,
            convert_done,
            verify,
            with_combine,
            guest_failed,
            ..
        } = self;
        // A stopped run drops the work, and the device context it carries with it.
        if run_stopped(guest_failed) {
            return;
        }
        let _b = spans::busy(WorkKind::ProveConvert, Some(chunk_idx as u32));
        let machine = convert
            .as_ref()
            .expect("convert work with no convert machine");
        let t = Instant::now();
        let ConvertWork(built) = work;
        let (convert_proof, vk) = machine
            .prove_built(built)
            .unwrap_or_else(|e| panic!("convert prove failed for chunk {chunk_idx}: {e:?}"));
        // Stop the clock before the debug-only verify, so `MLE_VERIFY=1`
        // does not inflate the figure it would be used to judge.
        let elapsed = t.elapsed();
        if *verify {
            machine
                .verify(&vk, &convert_proof)
                .unwrap_or_else(|e| panic!("convert verify failed for chunk {chunk_idx}: {e:?}"));
        }
        convert_prove_nanos.fetch_add(elapsed.as_nanos() as u64, Ordering::SeqCst);
        convert_done.fetch_add(1, Ordering::SeqCst);
        info!(
            target: "bench",
            "[bench][{worker_id}](chunk-{chunk_idx}) mle-convert-prover: running={} ms",
            elapsed.as_millis()
        );
        // Drain this prove's thread-local phase timers, as the riscv and combine
        // arms do: undrained, they leak into whichever arm reports next on this lane.
        if pico_vm::mle::cuda_mle::breakdown::enabled() {
            let (tracegen, commit, rap, openings) = pico_vm::mle::cuda_mle::breakdown::take();
            let total = elapsed.as_micros() as u64;
            let residual = total.saturating_sub(tracegen + commit + rap + openings);
            // Not `mle-breakdown`: the riscv arm prints that under the same
            // `(chunk-N)` key, and the two would collide in any extractor
            // that keys on the chunk rather than the lane.
            info!(
                target: "bench",
                "[bench][{worker_id}](chunk-{chunk_idx}) mle-convert-breakdown: total={total}us \
                 (tracegen={tracegen} commit={commit} rap_constraints={rap} \
                 openings={openings} residual={residual})"
            );
        }
        // Combine mode: THIS is where the chunk task ends. The convert proof
        // enters the scheduler's proof tree (which is what combine pairs),
        // releasing the `in_flight` slot taken at chunk acquisition. Without it
        // the tree stays empty and no combine task is ever generated.
        if *with_combine {
            mle_report_proof(
                IndexedProof::new((convert_proof, vk), chunk_idx, chunk_idx),
                worker_id,
            );
        }
    }

    /// Prove one combine node off this card's ready lane. Same reason for `worker_id`.
    fn prove_combine(&self, work: CombineWork, worker_id: &str) {
        let Self {
            combine,
            root_slot,
            combine_nanos,
            combine_count,
            verify,
            guest_failed,
            ..
        } = self;
        if run_stopped(guest_failed) {
            return;
        }
        let combine = combine
            .as_ref()
            .expect("combine work with no combine machine — no_combine is misset");
        let CombineWork {
            start_chunk: start,
            end_chunk: end,
            built,
        } = work;
        let _b = spans::busy(WorkKind::ProveCombine, Some(start as u32));
        let t = Instant::now();
        // Prove only: the ctx was built on the preparer under the
        // window, so the `running=` figure covers the GPU half
        // alone; keygen/setup are on the preparer's
        // `gpu_combine_timing` line.
        let node = combine
            .prove_built_node(built)
            .unwrap_or_else(|e| panic!("combine prove failed for [{start},{end}]: {e:?}"));
        // The shape truth, baked at keygen by the preparer — using
        // it here means the reported role can never diverge from
        // what was proven.
        let is_final = node.is_complete;
        let elapsed = t.elapsed();
        combine_nanos.fetch_add(elapsed.as_nanos() as u64, Ordering::SeqCst);
        combine_count.fetch_add(1, Ordering::SeqCst);
        info!(
            target: "bench",
            "[bench][{worker_id}](combine-{start}-{end}) mle-combine-prover: \
             running={} ms is_final={is_final}",
            elapsed.as_millis()
        );
        // Drain the thread-local phase timers for THIS prove.
        //
        // What actually leaks is `tracegen`, and only that: `breakdown.rs` SETS
        // commit/rap/openings, so the next prove overwrites them whatever we do here.
        // `tracegen` is different: a convert ctx build sets it on THIS thread, so
        // an undrained value survives to be reported against whichever chunk or
        // node reports next. Draining all four is still right (one operation, no
        // partial state), but the reason is the one field, not all of them.
        if pico_vm::mle::cuda_mle::breakdown::enabled() {
            let (tracegen, commit, rap, openings) = pico_vm::mle::cuda_mle::breakdown::take();
            let total = elapsed.as_micros() as u64;
            let residual = total.saturating_sub(tracegen + commit + rap + openings);
            info!(
                target: "bench",
                "[bench][{worker_id}](combine-{start}-{end}) mle-breakdown: total={total}us \
                 (tracegen={tracegen} commit={commit} rap_constraints={rap} \
                 openings={openings} residual={residual})"
            );
        }
        // Early-failure net only — NOT the security check (no honest-vk substitution).
        if *verify {
            combine
                .verify_node(&node.proof.1, &node.proof.0)
                .unwrap_or_else(|e| {
                    panic!("combine node [{start},{end}] failed self-verify: {e:?}")
                });
        }

        // Build the IndexedProof first so the root stash shares its `Arc`.
        let indexed = IndexedProof::new(node.proof, start, end);
        if is_final {
            let prev = root_slot
                .lock()
                .expect("root slot mutex poisoned")
                .replace(RootRecord {
                    proof: indexed.get_inner(),
                    child_layouts: node.child_layouts,
                });
            assert!(
                prev.is_none(),
                "two final combine nodes were proved — the tree collapsed twice"
            );
        }
        mle_report_proof(indexed, worker_id);
        info!("[{worker_id}] combine [{start},{end}]: OK (is_final={is_final})");
    }
}

/// Per-card VRAM watermark, off unless `MLE_VRAM_POLL_MS=<n>` asks for it.
///
/// Two prover lanes on a card means two working sets on it, so whether the second fits is a number
/// the split has to be judged on, and there was no per-card instrument: the bench script's figure
/// is nvidia-smi's whole-box maximum, which reads a neighbouring CARD's allocation as ours. This
/// asks the driver about one card. It still cannot separate our use of that card from a co-tenant's
/// -- `cudaMemGetInfo` is total minus free for the device, not for the process.
///
/// Per CARD and not per lane, so it is deliberately NOT tied to `MLE_RECURSION_LANE`: the one-lane
/// shape is exactly the arm whose residency this is used to compare against. Unset (the default) it
/// spawns nothing and prints nothing, on either shape.
struct VramWatch {
    stop: Arc<AtomicBool>,
    peaks: Vec<Arc<AtomicUsize>>,
    threads: Vec<thread::JoinHandle<()>>,
}

impl VramWatch {
    fn start(prover_count: usize) -> Self {
        let poll_ms: u64 = std::env::var("MLE_VRAM_POLL_MS")
            .ok()
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0);
        let stop = Arc::new(AtomicBool::new(false));
        // Only the `cuda` build pushes into these.
        #[cfg_attr(not(feature = "cuda"), allow(unused_mut))]
        let mut peaks = Vec::new();
        #[cfg_attr(not(feature = "cuda"), allow(unused_mut))]
        let mut threads = Vec::new();
        #[cfg(feature = "cuda")]
        if poll_ms > 0 {
            for k in 0..prover_count {
                let peak = Arc::new(AtomicUsize::new(0));
                peaks.push(Arc::clone(&peak));
                let stop = Arc::clone(&stop);
                threads.push(
                    thread::Builder::new()
                        .name(format!("mle-vram-{k}"))
                        .spawn(move || {
                            if pico_vm::mle::cuda_mle::runtime::context::set_device(k as i32)
                                .is_err()
                            {
                                return;
                            }
                            while !stop.load(Ordering::Relaxed) {
                                let used = pico_vm::mle::cuda_mle::runtime::memory_manager::
                                    device_memory_used();
                                peak.fetch_max(used, Ordering::Relaxed);
                                thread::sleep(Duration::from_millis(poll_ms));
                            }
                        })
                        .expect("spawn mle-vram"),
                );
            }
        }
        #[cfg(not(feature = "cuda"))]
        let _ = (poll_ms, prover_count);
        Self {
            stop,
            peaks,
            threads,
        }
    }
}

/// Stop the samplers and report on the way out. In `Drop` rather than a `finish()` the caller has
/// to remember: `run_pipeline` returns early on an empty program and asserts on a lone chunk, and
/// on either path the samplers would otherwise poll their card for the life of the process --
/// which `MLE_REPEAT` then accumulates. A no-op when the watch was never armed.
impl Drop for VramWatch {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for h in self.threads.drain(..) {
            let _ = h.join();
        }
        for (k, peak) in self.peaks.iter().enumerate() {
            info!(
                target: "bench",
                "[bench] mle-vram-peak: card={k} peak={} MiB",
                peak.load(Ordering::Relaxed) >> 20
            );
        }
    }
}

/// Convert work arriving at the prover slot: a ctx already built on the preparer.
///
/// A convert ctx is a few hundred MB and parks in the lane. The bound is not one: the build
/// precedes the blocking send, so every preparer blocked on the bounded(1) lane holds a built ctx
/// of its own — up to `MLE_CONVERT_PREPARERS` + 1 per card. That residency is what sizes the pool
/// (see `preparer_pool`); twelve of them is what a single card cannot afford.
#[cfg(feature = "cuda")]
struct ConvertWork(pico_vm::mle::machine::convert::BuiltConvert);
/// CPU build: uninhabited — the ready lane closes without ever carrying an item, and the prover's
/// match arm is `match work {}`.
#[cfg(not(feature = "cuda"))]
enum ConvertWork {}

/// Combine work arriving at the prover slot: a node ctx already built on its preparer. Same size
/// and same bound as [`ConvertWork`], with `MLE_COMBINE_PREPARERS` setting it here.
#[cfg(feature = "cuda")]
struct CombineWork {
    start_chunk: usize,
    end_chunk: usize,
    built: pico_vm::mle::machine::combine::BuiltCombine,
}
/// CPU build: uninhabited, exactly like [`ConvertWork`].
#[cfg(not(feature = "cuda"))]
enum CombineWork {}

const RV64_DIR: &str = "./perf/bench_data/rv64";

/// Where the witnesses are. `MLE_INPUT_DIR` is what `sweep_reth_mle.sh` exports and what its
/// `[input-dir]` argument means, and until this read existed that argument was a lie: the launcher
/// discovered and hash-validated one directory while the prover proved from another, so the
/// script's own usage example panicked on the first block.
///
/// Witnesses only, deliberately. The guest ELF is not part of the pool — a witness set is moved,
/// copied and shared between trees while the guest belongs to the tree that built it — so pointing
/// this at a pool must not take the ELF path with it.
///
/// ⚠️ Not the same knob as `RETH_INPUT_DIR` ([`crate::io::stdins::load_reth_input_for_block`]),
/// which the FRI and two-machine launchers export: that one defaults to `perf/bench_data/bins` and
/// names files `<block>.bin`, and nothing on this binary's path reads it. Two names for one concept
/// is a trap, and the reason this path keeps its own is that the launcher that feeds it already
/// exports this name; unifying them would change three other launchers for no defect.
/// The five aliases, as data rather than as a match arm — `load_reth_input` needs the table in both
/// directions (a selector to a block, and a block back to the spelling a witness file may carry),
/// and `sweep_reth_mle.sh` parses THIS to check its own copy has not drifted. Adding a pair here is
/// the only edit needed; writing it as a match arm is what made a reverse lookup a second copy.
const RETH_ALIASES: [(u32, u32); 5] = [
    (171, 17106222),
    (188, 18884864),
    (239, 23993050),
    (240, 24000020),
    (246, 24600825),
];

fn rv64_input_dir() -> String {
    std::env::var("MLE_INPUT_DIR").unwrap_or_else(|_| RV64_DIR.to_string())
}

fn load_elf(name: &str) -> Vec<u8> {
    let path = format!("{RV64_DIR}/{name}-elf");
    std::fs::read(&path).unwrap_or_else(|e| panic!("failed to read ELF {path}: {e}"))
}

fn load_reth_input(n: u32) -> Vec<u8> {
    let block = RETH_ALIASES
        .iter()
        .find_map(|&(alias, real)| (alias == n).then_some(real))
        .unwrap_or(n);
    let dir = rv64_input_dir();
    // Every spelling the launcher accepts, because it accepts three and `ci/test_sweep_launcher.sh`
    // asserts all three — `reth-<block>.bin`, a bare `<block>.bin`, and the five alias names — while
    // resolving any of them to a block NUMBER before handing it over. So the prover cannot recover
    // the filename it was given and has to try the spellings back: opening only the first turns a
    // pool of bare-named files (what `perf/bench_data/bins` and `io/stdins.rs` use, and what an
    // archive dump produces) into a first-block panic on a directory just hash-validated, and
    // opening only the first two does the same to an alias-named pool.
    //
    // Safe to try several: the launcher's dedup refuses a directory where two names resolve to one
    // block, so no other witness can be sitting under one of these spellings.
    let mut names = vec![format!("reth-{block}.bin"), format!("{block}.bin")];
    if let Some(&(alias, _)) = RETH_ALIASES.iter().find(|&&(_, real)| real == block) {
        names.push(format!("{alias}.bin"));
    }
    let mut last: Option<std::io::Error> = None;
    for name in &names {
        let path = format!("{dir}/{name}");
        match std::fs::read(&path) {
            Ok(bytes) => return bytes,
            // Only a missing file falls through to the next spelling. A permission or I/O error is
            // reported against the name it happened on rather than reported as "not found".
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => last = Some(e),
            Err(e) => panic!("failed to read reth input {path}: {e}"),
        }
    }
    panic!(
        "failed to read reth input for block {block} in {dir}: tried {} ({})",
        names.join(", "),
        last.map(|e| e.to_string()).unwrap_or_default()
    )
}

/// The file names an input of `reth-amsterdam` for block `n` may have, in the order they are
/// tried: the fixture spelling, then the bare `<block>.bin` that RSP's `eth-proofs --stdin-dir`
/// writes. No aliases: the number is the block's.
fn reth_amsterdam_input_names(n: u32) -> [String; 2] {
    [format!("reth-amsterdam-{n}.bin"), format!("{n}.bin")]
}

/// The input of the `reth-amsterdam` guest for block `n`, from [`rv64_input_dir`].
///
/// It is not an input `reth` can read, nor the other way round: this guest takes one buffer made
/// of the witness blob, the contract codes, the bincode-serialized client input and the lengths
/// of the codes and of the blob. A directory therefore holds the inputs of one of the two guests,
/// or spells them `reth-<block>.bin` and `reth-amsterdam-<block>.bin`; a bare `<block>.bin` is
/// handed to whichever guest is asked for that block.
fn load_reth_amsterdam_input(n: u32) -> Vec<u8> {
    let dir = rv64_input_dir();
    let names = reth_amsterdam_input_names(n);
    let mut last: Option<std::io::Error> = None;
    for name in &names {
        let path = format!("{dir}/{name}");
        match std::fs::read(&path) {
            Ok(bytes) => return bytes,
            // As in `load_reth_input`: only a missing file moves on to the next spelling.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => last = Some(e),
            Err(e) => panic!("failed to read reth-amsterdam input {path}: {e}"),
        }
    }
    panic!(
        "failed to read reth-amsterdam input for block {n} in {dir}: tried {} ({})",
        names.join(", "),
        last.map(|e| e.to_string()).unwrap_or_default()
    )
}

#[cfg(test)]
mod reth_amsterdam_input_tests {
    use super::reth_amsterdam_input_names;

    #[test]
    fn the_fixture_spelling_is_tried_before_the_bare_block_number() {
        assert_eq!(
            reth_amsterdam_input_names(12125459),
            [
                "reth-amsterdam-12125459.bin".to_string(),
                "12125459.bin".to_string()
            ]
        );
    }

    /// `reth`'s five selectors are block numbers here, not aliases: 188 is block 188.
    #[test]
    fn a_reth_alias_is_not_an_alias_here() {
        assert_eq!(
            reth_amsterdam_input_names(188),
            ["reth-amsterdam-188.bin".to_string(), "188.bin".to_string()]
        );
    }
}

/// Build `(elf_bytes, stdin)` for the configured program.
///
/// `KoalaBearPoseidon2` is used only as the stdin builder's config type-parameter
/// (mirroring `test_mle_riscv`); it does not pull in any FRI proving.
/// The guest ELF for the configured program. **Block-independent**: which ELF to run is a property
/// of `--elf`, not of `--n`, so a process that proves several blocks compiles it once.
///
/// An ELF from disk is read once per process and name, so a file replaced or deleted under a
/// running server neither changes nor breaks what it proves.
///
/// `reth-amsterdam` is RSP's client on reth v2.11.0 and evm2, which executes blocks of the
/// Amsterdam fork. It is another program than `reth`, with another input (see
/// [`load_reth_amsterdam_input`]), so it has a name and a file of its own, `reth-amsterdam-elf`,
/// instead of taking `reth-elf`'s place: what proves today's mainnet stays as it is.
fn load_program_elf(cfg: &MleSingleNodeConfig) -> Arc<[u8]> {
    if let Some(embedded) = &cfg.embedded {
        #[cfg(feature = "aot-emulator")]
        crate::aot::ensure_generated_from(&embedded.elf, "the embedded ELF");
        return Arc::clone(&embedded.elf);
    }
    static FIB: std::sync::OnceLock<Arc<[u8]>> = std::sync::OnceLock::new();
    static RETH: std::sync::OnceLock<Arc<[u8]>> = std::sync::OnceLock::new();
    static RETH_AMSTERDAM: std::sync::OnceLock<Arc<[u8]>> = std::sync::OnceLock::new();
    let (name, read) = match cfg.elf.as_str() {
        "fib" | "fibonacci" | "f" => ("fib", &FIB),
        "reth" => ("reth", &RETH),
        "reth-amsterdam" => ("reth-amsterdam", &RETH_AMSTERDAM),
        other => panic!("unsupported --elf {other} (supported: fib | reth | reth-amsterdam)"),
    };
    let elf = Arc::clone(read.get_or_init(|| load_elf(name).into()));
    #[cfg(feature = "aot-emulator")]
    crate::aot::ensure_generated_from(&elf, &format!("{RV64_DIR}/{name}-elf"));
    elf
}

/// The stdin for **one** block. This is the only thing a sweep changes between blocks; everything
/// else it holds resident, which is the whole point of the split.
fn stdin_for_block(cfg: &MleSingleNodeConfig, n: u32) -> EmulatorStdin {
    let mut stdin = EmulatorStdin::new_builder::<KoalaBearPoseidon2>();
    match cfg.elf.as_str() {
        "fib" | "fibonacci" | "f" => {
            stdin.write(&n);
            info!("MLE single-node: fibonacci n={n}");
        }
        "reth" => {
            stdin.write_slice(&load_reth_input(n));
            info!("MLE single-node: reth block selector {n}");
        }
        "reth-amsterdam" => {
            stdin.write_slice(&load_reth_amsterdam_input(n));
            info!("MLE single-node: reth-amsterdam block {n}");
        }
        other => panic!("unsupported --elf {other} (supported: fib | reth | reth-amsterdam)"),
    }
    stdin.finalize()
}

/// Receive, recording the block as `Idle` — a shortage of input, to be fixed upstream, as against
/// `Wait`, which is contention over something someone else holds.
///
/// Every stage loop below begins this way, so the three lines that draw that distinction are written
/// once instead of four times; and because it returns an `Option`, those loops keep the plain
/// `while let` shape they had before any of this was instrumented.
fn recv_idle<T>(rx: &crossbeam::channel::Receiver<T>, work: WorkKind) -> Option<T> {
    let _i = spans::idle(work);
    rx.recv().ok()
}

/// `MLE_VRAM_CENSUS` (cached): the block-boundary census. Cached because the alternative is an
/// environment read per boundary, and because a switch that could change mid-process would make
/// the rows it produces incomparable with each other.
#[cfg(feature = "cuda")]
fn vram_census_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| env_flag("MLE_VRAM_CENSUS"))
}

/// `MLE_VRAM_PROBE` (cached): the in-block probes, on a SEPARATE switch from the census and off
/// unless asked for.
///
/// Separate because of where they sit. The boundary census runs in `run`, outside the window
/// `e2e=` measures; ten of the thirteen probe points are inside it -- two run before `t_e2e`
/// starts and one after it is read. Sharing one switch meant that turning the census on for a
/// sweep also put driver reads, a device rebind and a manager lock inside every block's measured
/// window -- and `d_malloc` holds that same lock across its OOM self-heal, so a probe could stall
/// the thread it was measuring. Off, what the window pays is one atomic load per point.
#[cfg(feature = "cuda")]
fn vram_probe_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| env_flag("MLE_VRAM_PROBE"))
}

/// Which side of a block a census line is taken on. Not decoration: the `Pre` line is the one that
/// zeroes the pools' high-water marks, so a wrong value here silently stops the peaks from being
/// per-block.
#[derive(Clone, Copy)]
enum CensusPhase {
    Pre,
    Post,
}

#[cfg(feature = "cuda")]
impl CensusPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pre => "pre",
            Self::Post => "post",
        }
    }
}

/// Restores the calling thread's CUDA device when the census leaves, including out of a panic in
/// one of the caches it reads. Leaving the thread bound to the last card walked would silently
/// move where the next block's keygen lands.
#[cfg(feature = "cuda")]
struct DeviceBinding(Option<i32>);

#[cfg(feature = "cuda")]
impl Drop for DeviceBinding {
    fn drop(&mut self) {
        if let Some(dev) = self.0 {
            let _ = pico_vm::mle::cuda_mle::runtime::context::set_device(dev);
        }
    }
}

/// Per-card device-memory census at a block boundary, behind `MLE_VRAM_CENSUS=1`. Only the
/// directory sweep reaches it: a single-block or `MLE_REPEAT` run sets the flag and gets nothing.
///
/// A block boundary is the quiescent point: `run_pipeline` joins the threads it spawned before
/// returning, so these numbers are what a block LEFT BEHIND rather than what it was using. That
/// distinction is the whole instrument — a boundary `nvidia-smi` sample catches the next block's
/// ramp at a random phase and shows no trend where there is one. The one path that returns without
/// joining is the degenerate zero-chunk program, which proves nothing anyway. Joining is not
/// enough on its own; each card is synchronised first, or the read lands while its stream drains.
///
/// The quantities separate failures that look alike:
///   - `pool_used` / `tracked_live` / `out_of_pool` are the RESTING live set. A climb here is
///     something holding device memory across blocks — the counts on the same line say who.
///   - `tracked_peak` / `pool_used_high` / `pool_reserved_high` are the block's own PEAK, zeroed
///     at its `pre`. A `pre` line therefore carries whatever accumulated since the last reset —
///     the previous block, or for the first one, process start-up.
///   - `pool_reserved` climbing is NOT by itself evidence: the external pool never releases below
///     its threshold and the default one is asked to do the same, best-effort — `MLE_POOL_RETAIN=0`
///     or a failing driver call leaves it releasing eagerly, and that verdict is cached for the
///     process. It means something only when the peaks beside it are flat, and then fragmentation.
///
/// Four ways a figure here misleads rather than lies:
///   - `dev_used` is `cudaMemGetInfo`, which reports the whole card, so a co-tenant process lands
///     entirely in `out_of_pool`.
///   - a pool whose attribute read fails contributes zero rather than an error, so an
///     `out_of_pool` that jumps by a whole reservation while `pool_reserved` collapses on the same
///     line is a failed read and not a leak.
///   - `set_device` forces a primary context, so this walk CREATES one on any card the prover has
///     not reached yet and then reports it as that card's `out_of_pool`.
///   - the first `pre` line runs before `init_mle_gpu_pool` does, so it always reports
///     `ext_pool=0` with neither pool's threshold raised yet. Otherwise `ext_pool=1` means a
///     distinct external pool was counted into the pool totals; zero is ordinary when none is
///     registered or the registered one IS the device default, in which case `pool_*` already
///     covers it exactly once, and abnormal when the card's manager could not be read at all.
///
/// Not a read-only observer, which is why it is behind a flag as much as for its cost: the `pre`
/// line zeroes both pools' high-water attributes on a pool shared with pico, and the tracked peak
/// that the `GPU mem:` line's `peak=` and the `gpu_mem.local_peak_bytes` gauge report.
///
/// A card that could not be read emits a `vram_census_note:` line instead of a census row, so a
/// `vram_census:` row is always one per card per boundary with every field present.
#[cfg(feature = "cuda")]
fn vram_census(phase: CensusPhase, epoch: usize, block: u32, cards: usize) {
    use pico_vm::mle::cuda_mle::runtime::{context, memory_manager as mm, stream};
    if !vram_census_enabled() {
        return;
    }
    const MIB: f64 = (1024 * 1024) as f64;
    let phase_name = phase.as_str();
    let _binding = DeviceBinding(context::get_device().ok());
    for k in 0..cards {
        if context::set_device(k as i32).is_err() {
            // Said out loud, because this card also skips the high-water reset below: the next
            // `post` line's two peaks are then the process's, not that block's, and silently look
            // like a peak jump.
            info!(
                target: "bench",
                "vram_census_note: phase={phase_name} epoch={epoch} block={block} card={k} \
                 skipped=set_device"
            );
            continue;
        }
        if stream::device_synchronize().is_err() {
            // Every figure below is then read off a faulted context and looks perfectly plausible.
            info!(
                target: "bench",
                "vram_census_note: phase={phase_name} epoch={epoch} block={block} card={k} \
                 degraded=device_synchronize"
            );
        }
        let (live, peak) = mm::tracked_bytes_for(k);
        let pools = mm::pool_bytes_for(k);
        let (free, total) = mm::device_mem_info();
        let dev_used = total.saturating_sub(free) as u64;
        // Everything the driver counts that neither pool backs: the plain `cudaMalloc` sites in
        // the `.cu` units, loaded JIT modules, the CUDA context itself.
        let out_of_pool = dev_used.saturating_sub(pools.reserved_total());
        let resident = resident_snapshot();
        let resident = resident.as_deref();
        let (conv_n, conv_cap) = resident
            .and_then(|r| r.converts.get(k))
            .map_or((0, 0), |m| m.cache_len());
        let (comb_n, comb_cap) = resident
            .and_then(|r| r.combines.get(k))
            .map_or((0, 0), |m| m.cache_len());
        let comb = resident
            .and_then(|r| r.combines.get(k))
            .map(|m| m.shape_stats());
        let (modules, kernels) = pico_vm::mle::cuda_mle::jit_cache_len(k as i32);
        info!(
            target: "bench",
            "vram_census: phase={phase_name} epoch={epoch} block={block} card={k} \
             tracked_live_mib={:.2} tracked_peak_mib={:.2} \
             pool_used_mib={:.2} pool_used_high_mib={:.2} \
             pool_reserved_mib={:.2} pool_reserved_high_mib={:.2} \
             dev_used_mib={:.2} out_of_pool_mib={:.2} ext_pool={} bufcache_mib={:.2} \
             air_entries={} jit_modules={modules} jit_kernels={kernels} \
             streams_created={} streams_recycled={} \
             pk_convert={conv_n}/{conv_cap} pk_combine={comb_n}/{comb_cap} \
             comb_keygens={} comb_evictions={}",
            live as f64 / MIB,
            peak as f64 / MIB,
            pools.used_total() as f64 / MIB,
            pools.used_high_total() as f64 / MIB,
            pools.reserved_total() as f64 / MIB,
            pools.reserved_high_total() as f64 / MIB,
            dev_used as f64 / MIB,
            out_of_pool as f64 / MIB,
            u8::from(pools.external.is_some()),
            pico_vm::mle::cuda_mle::logup_zerocheck::gkr_buf_cache_bytes(k as i32) as f64 / MIB,
            pico_vm::mle::cuda_mle::air_data_cache_len(k as u32),
            pico_vm::cuda_adaptor::streams_created(k),
            // Streams handed back by threads that finished on this card. After the hand-back
            // landed, `streams_created` is flat by construction, so this is the count that says
            // how many threads a card has been through — the axis a per-thread leak grows along.
            pico_vm::cuda_adaptor::release_stats(k).0,
            comb.as_ref().map_or(0, |c| c.keygens),
            comb.as_ref().map_or(0, |c| c.evictions),
        );
        // Reset AFTER reading, and only at the block's start, so the `post` line's two high-water
        // figures belong to this block instead of to the whole process.
        if matches!(phase, CensusPhase::Pre) {
            mm::reset_tracked_peak_for(k);
            mm::reset_pool_high_water(k);
        }
    }
}

/// Device totals at a named point INSIDE a block, for locating which phase of the pipeline a
/// per-block leak happens in. Behind its own `MLE_VRAM_PROBE`, off by default, with the same
/// caveats as the census: `dev_used` is the whole card, and binding a card the prover has not reached creates
/// its primary context.
///
/// Deliberately thinner than the census, and with no `device_synchronize`: these points sit
/// between pipeline stages with work still in flight, and syncing here would change what is being
/// measured. So a single reading is not a live set — the signal is one probe point compared ACROSS
/// blocks, where a systematic offset from unsettled work cancels. It also does not reset anything,
/// which is why it needs none of the census's write caveats.
///
/// The labels say where the reading was taken, not which stage drained there. Every prover LANE
/// drains at `after_workers` — a lane only exits once its own feeds are closed — so no per-stage
/// attribution can be read out of the points after it. Nor are those points purely host
/// bookkeeping: with `MLE_CONVERT_PREBUILD_PK` on, which is the default, the pre-build pool is
/// still keygening on a card until its shutdown, which sits between `after_workers` and
/// `after_convert_report`.
///
/// Two things it can do that the boundary census cannot. `pool_bytes_for` takes the card's manager
/// lock, which `d_malloc` holds across its OOM self-heal (a whole-device synchronise plus two pool
/// trims), so a probe can stall the very thread it is measuring — likeliest on exactly the filling
/// card this exists to explain. And `dev_used` and the pool figures are read at different instants
/// with no lock between them and the pool figures first: a pool trimmed in between
/// clamps `out_of_pool` to 0.00, which reads identically to "nothing outside the pools", while one
/// growing in between overstates it.
#[cfg(feature = "cuda")]
fn vram_probe(at: &str, epoch: usize, cards: usize) {
    use pico_vm::mle::cuda_mle::runtime::{context, memory_manager as mm};
    // First statement, and a cached load: ten of the thirteen call sites are inside the window
    // `e2e=` measures, so what this costs when switched off has to be countable.
    if !vram_probe_enabled() {
        return;
    }
    const MIB: f64 = (1024 * 1024) as f64;
    let _binding = DeviceBinding(context::get_device().ok());
    for k in 0..cards {
        if context::set_device(k as i32).is_err() {
            // Said out loud for the census's reason: a card that silently emits nothing reads as a
            // card that had nothing to report.
            info!(
                target: "bench",
                "vram_probe_note: at={at} epoch={epoch} card={k} skipped=set_device"
            );
            continue;
        }
        let pools = mm::pool_bytes_for(k);
        let (free, total) = mm::device_mem_info();
        let dev_used = total.saturating_sub(free) as u64;
        info!(
            target: "bench",
            "vram_probe: at={at} epoch={epoch} card={k} dev_used_mib={:.2} \
             pool_reserved_mib={:.2} out_of_pool_mib={:.2}",
            dev_used as f64 / MIB,
            pools.reserved_total() as f64 / MIB,
            dev_used.saturating_sub(pools.reserved_total()) as f64 / MIB,
        );
    }
}

#[cfg(not(feature = "cuda"))]
fn vram_probe(_at: &str, _epoch: usize, _cards: usize) {}

/// The census is GPU-only; the CPU build keeps the call sites rather than cfg-ing them.
#[cfg(not(feature = "cuda"))]
fn vram_census(_phase: CensusPhase, _epoch: usize, _block: u32, _cards: usize) {}

/// Single-node entry: dispatch on the requested proving step. `riscv` and `convert` are wired
/// (`convert` = the riscv pipeline with the streaming convert stage spliced in, FRI-style);
/// `combine` is planned.
///
/// `iteration` is which `MLE_REPEAT` pass this call is, `None` for a plain single run. It reaches
/// only the span export, which names its file after it (see [`spans::csv_path_for_iteration`]).
pub fn run(cfg: &MleSingleNodeConfig, iteration: Option<usize>) {
    // Directory sweep: prove every block in `MLE_BLOCKS` from this one process, reusing
    // the compiled program and the per-card machines across all of them (see `Resident`).
    //
    // The epoch index is what names the span export (`run.spans.csv.iterK`), which the sweep's
    // `manifest.csv` maps back to a block number — so it must count blocks, not restart per block.
    // `MLE_REPEAT` keeps its own meaning: it repeats whatever this resolves to.
    if let Ok(list) = std::env::var("MLE_BLOCKS") {
        let blocks: Vec<u32> = list
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| {
                s.parse::<u32>()
                    .unwrap_or_else(|_| panic!("MLE_BLOCKS: '{s}' is not a block number"))
            })
            .collect();
        assert!(
            !blocks.is_empty(),
            "MLE_BLOCKS was set but parsed to nothing"
        );
        info!("MLE sweep: {} block(s) in one process", blocks.len());
        for (i, n) in blocks.iter().enumerate() {
            let mut per_block = cfg.clone();
            per_block.n = *n;
            // A delimiter pair per block, because every existing way of slicing this log is wrong
            // here: a slicer keyed on `MLE repeat:` markers sees nothing, since they only appear
            // when MLE_REPEAT > 1. Without these, the per-block extractors -- `tail -1`,
            // `grep -m1`, `grep -c` -- all read some other block's numbers and report them under
            // this block's name.
            info!(
                target: "bench",
                "MLE block: {}/{} block={n} starting", i + 1, blocks.len()
            );
            vram_census(CensusPhase::Pre, i + 1, *n, cfg.prover_count.max(1));
            run_step(&per_block, Some(i + 1), None);
            vram_census(CensusPhase::Post, i + 1, *n, cfg.prover_count.max(1));
            info!(
                target: "bench",
                "MLE block: {}/{} block={n} done", i + 1, blocks.len()
            );
        }
        return;
    }
    run_step(cfg, iteration, None);
}

/// One block, on whichever step was configured.
pub fn run_step(
    cfg: &MleSingleNodeConfig,
    iteration: Option<usize>,
    job: Option<BlockJob>,
) -> BlockOutcome {
    match cfg.step {
        Step::Riscv => run_pipeline(cfg, false, false, iteration, job),
        #[cfg(feature = "cuda")]
        Step::Convert => run_pipeline(cfg, true, false, iteration, job),
        #[cfg(not(feature = "cuda"))]
        Step::Convert => panic!("--step convert requires the `cuda` feature"),
        #[cfg(feature = "cuda")]
        Step::Combine => run_pipeline(cfg, true, true, iteration, job),
        #[cfg(not(feature = "cuda"))]
        Step::Combine => panic!("--step combine requires the `cuda` feature"),
        // The combine pipeline; `run_pipeline` reads the compress stage off `cfg.step`.
        #[cfg(feature = "cuda")]
        Step::Compress => run_pipeline(cfg, true, true, iteration, job),
        #[cfg(not(feature = "cuda"))]
        Step::Compress => panic!("--step compress requires the `cuda` feature"),
    }
}

/// CPU preparer pool size for one work kind: one on a single card, the multi-card size above that.
///
/// A convert or combine preparer blocked on its bounded ready lane parks a device-resident ctx, so
/// twelve of them leave the memory pool with nothing to trim and a 16 GiB allocation on a heavy
/// block fails outright — block 24600825 aborts every time at 6/12/7 and completes every time at
/// 1/1/1. The riscv pool comes down with them for a different reason: its lane is unbounded and
/// `prepare_chunk_shaped` takes no device memory, so it never held ctxs, but one preparer already
/// keeps a single prover lane fed.
///
/// Do not re-derive these from a measured prepare/prove ratio. That was tried: a four-card A/B put
/// the ratio-matched sizes 10-19% behind 6/12/7, because the ratio moves with every guest rebuild.
fn preparer_pool(kind: &str, env: &str, multi_card_size: usize, cards: usize) -> usize {
    let n = std::env::var(env)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(if cards <= 1 { 1 } else { multi_card_size })
        .max(1);
    // Logged because the pools are no longer pinned by the bench box: a report that cannot say
    // which sizes ran cannot be read against another arm's.
    info!("MLE {kind} preparers: {n} ({cards} card(s))");
    n
}

/// Keygen the root's shape for acceptance as soon as the final combine node's children are known,
/// under the root's own preparation and GPU prove — **default ON**. `MLE_ROOT_EARLY_KEYGEN=0`
/// keygens it inside acceptance, after the prove, as before. The keygen's inputs and acceptance's
/// checks are the same either way; only when the keygen runs moves.
#[cfg(feature = "cuda")]
fn root_early_keygen_enabled() -> bool {
    pico_vm::mle::env_opt_out("MLE_ROOT_EARLY_KEYGEN")
}

/// The CPU machine root acceptance verifies on, before any shape is registered.
#[cfg(feature = "cuda")]
fn acceptance_machine(vm_vk: RiscvVmVk, vk_map: Option<&Arc<MleVkMap>>) -> CombineMachine {
    let mut machine = CombineMachine::new(
        pico_vm::mle::recursion_params_with_128_bits_security(),
        vm_vk,
        vk_map.is_some(),
    );
    if let Some(map) = vk_map {
        machine.set_vk_map(Arc::clone(map));
    }
    machine
}

/// One block's early root keygen: started by the combine preparer that prepares the final node,
/// taken by acceptance.
///
/// The thread derives the child layouts exactly as `prepare_node` derives the root's (the same
/// function on the same children, in order), builds the machine acceptance would build, and
/// registers the shape on it. Acceptance then registers the root's own layouts on that machine as
/// it always has, which finds the shape instead of keygenning it. A block that never reaches
/// acceptance drops the handle; the thread finishes its keygen, holds no lock or channel, and its
/// machine goes with it.
#[cfg(feature = "cuda")]
#[derive(Clone)]
struct EarlyRootKeygen {
    slot: Arc<std::sync::Mutex<Option<thread::JoinHandle<CombineMachine>>>>,
    vm_vk: RiscvVmVk,
    vk_map: Option<Arc<MleVkMap>>,
}

#[cfg(feature = "cuda")]
impl EarlyRootKeygen {
    fn new(vm_vk: RiscvVmVk, vk_map: Option<Arc<MleVkMap>>) -> Self {
        Self {
            slot: Arc::new(std::sync::Mutex::new(None)),
            vm_vk,
            vk_map,
        }
    }

    /// Start the keygen for the final node `[start, end]` with these children, in order.
    fn start(&self, children: Vec<ProofWithVk>, start: usize, end: usize) {
        let (vm_vk, vk_map) = (self.vm_vk.clone(), self.vk_map.clone());
        let handle = thread::Builder::new()
            .name("mle-root-keygen".into())
            .spawn(move || {
                info!("MLE root keygen: start (early, node [{start},{end}])");
                let t = Instant::now();
                let layouts: Vec<_> = children
                    .iter()
                    .map(|(proof, vk)| {
                        pico_vm::mle::machine::recursion::extract_recursion_vk_layout(
                            vk,
                            Some(proof),
                        )
                    })
                    .collect();
                let mut machine = acceptance_machine(vm_vk, vk_map.as_ref());
                machine
                    .register_shape(&layouts, /* is_complete = */ true)
                    .unwrap_or_else(|e| panic!("{e}"));
                info!(
                    "MLE root keygen: done in {:.3}s (early, node [{start},{end}])",
                    t.elapsed().as_secs_f64()
                );
                machine
            })
            .expect("spawn mle-root-keygen");
        let prev = self
            .slot
            .lock()
            .expect("early root keygen mutex poisoned")
            .replace(handle);
        assert!(
            prev.is_none(),
            "two final combine nodes were prepared — the tree collapsed twice"
        );
    }

    fn take(&self) -> Option<thread::JoinHandle<CombineMachine>> {
        self.slot
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }
}

/// The block-independent half of the pipeline: the compiled program and the per-card machines.
///
/// Held while the program stays the same, so a sweep pays for it once. Everything in here is a
/// function of the ELF and the card count alone — `RiscvMachine::new` takes the program and a
/// config constant and nothing else, and the code below it asserts the keygen is deterministic
/// across cards, so there is nothing per-block to get wrong by keeping it.
///
/// What is deliberately **not** here: the scheduler reset, the transfer-stats reset, and the nine
/// per-block accumulators. Those live where they already were, below this, inside the proving
/// window. Moving them up is the single most dangerous mistake available in this refactor and it
/// does not announce itself — `reset_mle_scheduler` is what clears `completed`, the proof tree and
/// `emulation_done`, so a setup-side reset leaves block 2's dispatcher taking `Complete` on its
/// first poll and proving nothing, and leaves `emulation_done` latched so every later block
/// silently measures stale lane behaviour while the report claims otherwise.
#[derive(Clone)]
struct Resident {
    program: Arc<Program>,
    provers: Vec<Arc<RiscvMachine>>,
    /// The caller's machine card 0 adopted, by address; `None` when card 0 keygen'd its own.
    card0_from: Option<usize>,
    #[cfg(feature = "cuda")]
    converts: Vec<Arc<GpuConvertMachine>>,
    #[cfg(feature = "cuda")]
    riscv_vm_vk: Option<RiscvVmVk>,
    #[cfg(feature = "cuda")]
    combines: Vec<Arc<pico_vm::mle::machine::combine::GpuCombineMachine>>,
    /// The provers of the global LogUp's nodes, one per card, with a combine stage; empty
    /// without. Their keys are made as the blocks need them and kept across blocks.
    #[cfg(feature = "cuda")]
    global_logup_nodes: Vec<
        Arc<std::sync::Mutex<pico_vm::mle::machine::global_logup_nodes::GlobalLogUpNodeMachine>>,
    >,
    /// The whitelist, in whitelist mode: the root verify reads it after the tree; the apex holds
    /// its own reference.
    #[cfg(feature = "cuda")]
    vk_map: Option<Arc<MleVkMap>>,
    /// The standalone apex verifier, in whitelist mode with a combine stage: built once, against
    /// the deployment's pinned root (`MLE_VK_ROOT`, else the artifact's own), and reused for every
    /// block: on the root when it is accepted here, and on the compress proof.
    #[cfg(feature = "cuda")]
    apex: Option<Arc<MleApexVerifier>>,
    /// `--step compress`: the GPU prover, on card 0 after the tree, and the CPU machine that
    /// accepts its proof (it keygens per root layout, hence the mutex).
    #[cfg(feature = "cuda")]
    compress: Option<(
        Arc<GpuCompressMachine>,
        Arc<std::sync::Mutex<CompressMachine>>,
    )>,
    /// Reported once, in `setup.csv`. A resident process pays it on block 1 and never again, so
    /// carrying it in the per-block table would describe a cost that is not there.
    keygen_wall: Duration,
    /// The shape these machines were built for. A second block asking for a different one is a
    /// caller bug: the machines are per-card and the lane count decides the spawn count.
    shape: (usize, bool, bool, bool),
}

/// What the resident machines were built from. A block whose key differs gets new machines: the
/// keys are per program, so reusing them would prove another program.
#[derive(PartialEq, Eq)]
struct ResidentKey {
    elf: Arc<[u8]>,
    vk_on: bool,
    log_stacked_height: usize,
    embedded_root: Option<[KoalaBear; 8]>,
}

/// What card 0 of resident machines that otherwise fit a run is to prove on.
enum Card0 {
    /// The machine it has.
    Keep,
    /// The caller's.
    Adopt(Arc<RiscvMachine>),
    /// One keygen'd for the resident.
    Keygen,
}

/// The caller's riscv machine, when card 0 can prove on it: built for the program whose identity
/// `expected` gives (under the machine's parameters) at this height and bucketing, and holding no
/// Global tables of a prove of its own.
fn adoptable(
    caller: Option<&Arc<RiscvMachine>>,
    expected: impl FnOnce(&RiscvMachine) -> Option<pico_vm::mle::machine::riscv::ProgramIdentity>,
    log_stacked_height: usize,
    bucket: bool,
) -> Option<Arc<RiscvMachine>> {
    let machine = caller?;
    if machine.has_chunk_tables() {
        return None;
    }
    // The settings first: `expected` may commit the program's image table.
    if !machine.built_for(log_stacked_height, bucket)
        || machine.program_identity().is_none()
        || machine.program_identity() != expected(machine)
    {
        warn!(
            "MLE keygen: the caller's riscv machine is for another program or setting; card 0 \
             keygens its own"
        );
        return None;
    }
    Some(Arc::clone(machine))
}

/// What two riscv machines of one program must agree on: the vk's pre-hash, and the
/// program-table commitment it leaves out.
fn riscv_keys(machine: &RiscvMachine) -> impl PartialEq + std::fmt::Debug {
    (
        machine.vk_pre_hash(),
        pico_vm::mle::machine::riscv::riscv_program_commit(machine.vk()),
    )
}

static RESIDENT: std::sync::Mutex<Option<(ResidentKey, Arc<Resident>)>> =
    std::sync::Mutex::new(None);

/// The resident machines for `key`, built by `build` when the slot holds none or holds another
/// program's. The old machines are dropped before the new ones are built, so their device memory
/// returns to the pool first.
///
/// Card 0 proves on the caller's machine, `caller`, when `card0` adopts it. Machines that fit but
/// whose card 0 is not the one the run should prove on swap that machine alone: a caller's machine
/// serves only that caller's runs, so its batch proves cannot touch another run's Global tables.
fn resident_for(
    key: ResidentKey,
    caller: Option<&Arc<RiscvMachine>>,
    card0: impl FnOnce(&Resident) -> Card0,
    keygen_card0: impl FnOnce(&Arc<Program>) -> Arc<RiscvMachine>,
    build: impl FnOnce(Arc<[u8]>) -> Resident,
) -> Arc<Resident> {
    let mut slot = RESIDENT.lock().unwrap_or_else(|e| e.into_inner());
    let decision = match slot.as_ref() {
        Some((held, resident)) if *held == key => {
            let caller = caller.map(|m| Arc::as_ptr(m) as usize);
            if resident.card0_from.is_some() && resident.card0_from == caller {
                Card0::Keep
            } else {
                card0(resident)
            }
        }
        Some(_) => {
            info!("MLE resident: program or settings changed; rebuilding the machines");
            *slot = None;
            Card0::Keygen
        }
        None => Card0::Keygen,
    };
    let Some((key, held)) = slot.take() else {
        let resident = Arc::new(build(Arc::clone(&key.elf)));
        *slot = Some((key, Arc::clone(&resident)));
        return resident;
    };
    let (adopted, from) = match decision {
        Card0::Keep => {
            *slot = Some((key, Arc::clone(&held)));
            return held;
        }
        Card0::Adopt(machine) => {
            let from = Arc::as_ptr(&machine) as usize;
            (Some(machine), Some(from))
        }
        Card0::Keygen => (None, None),
    };
    let mut next = (*held).clone();
    drop(held);
    let old = next.provers.remove(0);
    let old_keys = riscv_keys(&old);
    // Unless its caller still holds it, the old card-0 key leaves the card before a new one is
    // made there.
    drop(old);
    let machine = adopted.unwrap_or_else(|| keygen_card0(&next.program));
    assert_eq!(
        riscv_keys(&machine),
        old_keys,
        "card 0's new riscv machine has another vk than the one it replaces"
    );
    info!("MLE resident: card 0 swaps its riscv machine; the other machines stay");
    next.provers.insert(0, machine);
    next.card0_from = from;
    let resident = Arc::new(next);
    *slot = Some((key, Arc::clone(&resident)));
    resident
}

/// The resident machines, if any.
#[cfg(feature = "cuda")]
fn resident_snapshot() -> Option<Arc<Resident>> {
    RESIDENT
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .as_ref()
        .map(|(_, resident)| Arc::clone(resident))
}

/// The riscv machine card 0 of the resident machines proves on, if there are any.
#[cfg(feature = "cuda")]
pub(crate) fn resident_card0_riscv() -> Option<Arc<RiscvMachine>> {
    resident_snapshot().map(|resident| Arc::clone(&resident.provers[0]))
}

/// Drops the device keys the resident recursion pk caches added during `run`; returns how many.
#[cfg(feature = "cuda")]
pub(crate) fn drop_pk_keys_added_in(run: u64) -> usize {
    resident_snapshot().map_or(0, |resident| {
        resident
            .converts
            .iter()
            .map(|m| m.drop_keys_added_in(run))
            .chain(resident.combines.iter().map(|m| m.drop_keys_added_in(run)))
            .chain(resident.global_logup_nodes.iter().map(|m| {
                m.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .drop_keys_added_in(run)
            }))
            .sum()
    })
}

/// The single-node proving pipeline: keygen (+ eager JIT warmup) first on the quiescent main
/// thread, then an emulate thread streams records to a preparer thread which publishes prepared
/// chunks to the scheduler; a worker pool proves chunks as they arrive.
///
/// With `with_convert`, the streaming convert stage is spliced in FRI-style: each riscv chunk
/// proof flows (never batched) into a convert-preparer pool (CPU: layout + keygen-cache + emulate)
/// and on to a convert-prover pool (GPU: trace-gen + prove); the step completes when every chunk's
/// convert proof is done. The GlobalScheduler keeps tracking the riscv level (chunks report
/// terminal there); convert completion is joined via the pipeline channels draining.
///
/// With `with_combine` (which implies `with_convert`), the scheduler additionally runs its combine
/// tree: convert proofs are reported into its proof tree, which pairs adjacent ones into
/// `SchedulerTask::Combine`, and the same worker pool proves those nodes. See the `no_combine`
/// switch below for why the riscv level must then stop reporting terminally.
fn run_pipeline(
    cfg: &MleSingleNodeConfig,
    with_convert: bool,
    with_combine: bool,
    iteration: Option<usize>,
    job: Option<BlockJob>,
) -> BlockOutcome {
    assert!(
        with_convert || !with_combine,
        "with_combine implies with_convert"
    );
    // The compress stage runs after the tree, on the root, so it needs the combine pipeline.
    let with_compress = cfg.step == Step::Compress;
    assert!(
        with_combine || !with_compress,
        "with_compress implies with_combine"
    );
    watch::reset();
    // Scheduling mode. This used to be an unconditional `set_var("USECASE", "local_single_node")`
    // nail: the GlobalScheduler reads the mode from USECASE / MACHINE_ROLE, and a stray two-machine
    // value (these benchmark hosts also run two-machine FRI) would role-partition chunks so the
    // riscv-only worker pool never acquired them all and hung.
    //
    // The nail is now an opt-out rather than a clobber: single-node remains the default and is
    // still pinned exactly as before, so the env cannot leak in by accident, but asking for
    // two-machine explicitly is no longer overwritten.
    //
    // Removing the pin alone is NOT sufficient to make two-machine work: MLE's worker ids must also
    // carry the role label (see `worker_label` below), or `worker_index_for_id` falls through to
    // `unwrap_or(0)` and elects every worker on both machines the leader.
    if !mle_two_machine_requested() {
        std::env::set_var("USECASE", "local_single_node");
    }
    // Chunk-assignment sizing, set before anything reads it. Inert in single-node (the assignment
    // is only consulted in the two-machine modes), but set here so the value travels with the MLE
    // entry point rather than being remembered at launch time: FRI's 8/16 leaves an 8-chunk MLE
    // block entirely inside the primary's reserved range. See
    // `set_mle_chunk_assignment_defaults` for the values and the trade-off.
    set_mle_chunk_assignment_defaults();
    // Two machines prove a block to its tree's root. The scheduler completes such a block by its
    // proof tree; without one it completes by a count of proved chunks, which the secondary's
    // never enter (`mle_report_chunk_terminal`), and the primary would wait for them until its
    // dispatcher gives the run up. Refused before either side is brought up: a primary that
    // served and then stopped would leave its secondary retrying the connection.
    assert!(
        with_combine || !mle_two_machine_requested(),
        "a two-machine run proves a block to its tree's root: `--step combine` or `--step \
         compress`"
    );
    // Bring up whichever half of the two-machine shape this process is, before the pipeline starts:
    // the primary must be serving before a secondary can acquire, and the secondary must hold a
    // client before its first `mle_register_chunk`. A no-op in single-node, and for the blocks
    // of a process after its first.
    if mle_two_machine_requested() {
        two_machine::init_mle_two_machine();
    }

    // `prover_count` = number of GPU cards, each getting two prover threads (riscv, recursion) —
    // one under `MLE_RECURSION_LANE=0` — plus its own machine set: proving keys and pk caches are
    // device-resident, so nothing device-touching is shared between cards. Per-card threads bind
    // their card at spawn (`set_device`), and the machine layer resolves the device from the
    // calling thread.
    let prover_count = cfg.prover_count.max(1);
    assert!(
        cfg!(feature = "cuda") || prover_count == 1,
        "prover_count={prover_count}: the CPU build has no multi-card path"
    );
    // Read here and never again -- see `recursion_lane_enabled` for why a second read is a hang
    // rather than an error. Logged because a report that cannot say which topology ran cannot be
    // read against another arm's, the same reason `preparer_pool` logs its sizes.
    let rec_lane = recursion_lane_enabled();
    // Derived once, so the spawn count, the log line and the bench headline cannot disagree about
    // the shape that actually ran.
    let lanes_per_card = if rec_lane { 2 } else { 1 };
    info!(
        // `bench`, like the `MLE lane:` lines this is the header for, so an archived log filtered
        // to that target alone still says which shape produced it.
        target: "bench",
        "MLE prover lanes: {lanes_per_card} per card ({prover_count} card(s)){}",
        if rec_lane {
            ""
        } else {
            " — MLE_RECURSION_LANE=0: one lane takes riscv, convert and combine"
        }
    );

    // GPU proving shares pico's memory pool: initialize one per card at process entry (an invalid
    // card index fails loudly here, before any thread spawns). Process-level resources, so the
    // provers below need no pool setup of their own.
    #[cfg(feature = "cuda")]
    for k in 0..prover_count {
        pico_vm::mle::machine::riscv::init_mle_gpu_pool(k);
    }
    vram_probe("enter", iteration.unwrap_or(0), prover_count);

    let t_total = Instant::now();
    // Host-side verification of the intermediate proofs: riscv chunks, converts, combine nodes,
    // the global LogUp's nodes and their reduction, and the root when compress follows. (A group
    // proof of the global LogUp is verified by its node.) The final proof (the root under
    // `--step combine`, the compress proof under `--step compress`) is accepted either way.
    let verify = env_flag("MLE_VERIFY");
    // Negative-test hook: tamper one cross-chunk pass-through cell, so that the chunks' events no
    // longer balance. With a tree, the prefix stage sees the global LogUp's sums not add up to
    // zero and stops the run.
    let corrupt_memory = env_flag("CORRUPT_MEMORY");
    // The binaries resolved and logged it at startup; every block of the process reads it back.
    let replay = replay_workers();

    // Time each setup stage (program load / compile / pools) so per-run variance
    // (disk / page-cache effects) is attributable from the bench log.
    // Per block. The ELF and the compiled program are resident (see `Resident`); only this is not.
    let t_load = Instant::now();
    // A caller-supplied block wins over the fixture selector: the ethproofs entry has already
    // turned RSP's `input_buffer` into a stdin and there is no file for it to name.
    let stdin = match job {
        Some(job) => job.stdin,
        None => stdin_for_block(cfg, cfg.n),
    };
    info!(
        "MLE program load done in {:.3}s",
        t_load.elapsed().as_secs_f64()
    );

    // Work scheduler + prepared-chunk store.
    //
    // `no_combine` off means the scheduler runs its full path: reported proofs enter the proof
    // tree, adjacent pairs become `SchedulerTask::Combine`, and completion switches from
    // count-based (`chunks_proven == total`) to tree-based (`is_proof_tree_complete`).
    //
    // IMPORTANT: that switch is why the riscv level must NOT call `report_chunk_terminal` in
    // combine mode. That entry point only ever consults the count-based predicate, and the
    // predicate checks neither the `no_combine` flag nor the combine queue. With combine on, it
    // would latch completion as soon as every chunk was proven — with combine tasks still queued —
    // and wake every worker with `Complete`. See the reporting match in the worker loop.
    // The singleton, not a private `Arc`. Holding its own instance meant MLE's scheduler and the one
    // a gRPC server would serve were two different objects, so a secondary connecting in would find
    // no work. Same object now, which is what a two-machine run needs.
    //
    // A singleton outlives the run where a fresh `GlobalScheduler` did not, and `MLE_REPEAT` calls
    // this function N times in one process — so reset before anything registers a chunk, or
    // iteration 2 inherits iteration 1's proof tree and completion state.
    reset_mle_scheduler();
    // Per-block, not cumulative: `MLE_REPEAT` runs this function several times in one process and
    // the figure is wanted per block.
    crate::common::transfer_stats::reset();
    let scheduler: Arc<GlobalScheduler<SchedulerProof>> = get_mle_scheduler();
    // On two machines the block has a number: each machine counts the blocks it proves from
    // one, and both prove the same blocks in the same order. The primary's scheduler service
    // holds back a request for a block it has not reached and ends one for a block it has
    // left, and the global LogUp's messages name their block the same way.
    if mle_two_machine_requested() {
        static BLOCKS: AtomicU64 = AtomicU64::new(0);
        let block = BLOCKS.fetch_add(1, Ordering::SeqCst) + 1;
        scheduler.set_block_num(block);
        #[cfg(feature = "cuda")]
        if !is_mle_secondary() {
            exchange().open(block);
        }
    }
    scheduler.set_no_combine(!with_combine);
    // The tree's root joins the chunks with the global LogUp's nodes, which lead it.
    #[cfg(feature = "cuda")]
    if with_combine {
        crate::common::mle_scheduler_singleton::mle_expect_prefix();
    }
    // Largest riscv chunk first when chunks queue up, so that the cheap ones are what is left to
    // even out the cards' ends; `MLE_CHUNK_ORDER=fifo` keeps arrival order instead.
    scheduler.set_chunk_order_by_cost(!matches!(
        std::env::var("MLE_CHUNK_ORDER").as_deref(),
        Ok("fifo")
    ));
    let store: Arc<DashMap<usize, PreparedChunk>> = Arc::new(DashMap::new());

    // Per-chunk prove timing (pure-prove throughput), independent of emulate/transport.
    let prove_nanos = Arc::new(AtomicU64::new(0));
    let prove_count = Arc::new(AtomicUsize::new(0));

    // The bound on records held at once must be set before emulation starts. Streaming lowers the
    // requirement from "≥ total chunk count" (collect-all held every record at once — a bound
    // below the chunk count deadlocked) to "≥ in-flight chunks": when emulation runs ahead of
    // proving, a record's slot take waiting on a full bound is natural backpressure, released as
    // workers finish chunks and drop their records. Each slot is a chunk's pinned history, the
    // upload's source, so the slots are pinned here, before any timer starts. The embedded entry
    // states its count (`EmbeddedProgram::event_pool_size`); the CLI reads `MLE_HISTORY_SLOTS`.
    // An emulation elsewhere in the process that lifts the bound waits for this run, and this run
    // for it.
    let _bounded = pico_vm::emulator::riscv::record_slots::bounded_run();
    let record_slots = match &cfg.embedded {
        Some(embedded) => embedded.event_pool_size,
        None => record_slots_from_env().unwrap_or_else(|e| panic!("{e}")),
    };
    let record_slots = init_record_slots(record_slots.get());
    info!("MLE records held at once: at most {record_slots}, each in a pinned history slot");

    // Keygen (+ eager JIT warmup) on the main thread BEFORE the emulate/preparer/worker threads
    // spawn: `RiscvMachine::new` nvrtc-compiles the JIT kernels here, and that must run while the
    // process is quiescent or libnvrtc deadlocks in the heavily-threaded prover. Cost: the old
    // keygen↔emulate overlap is gone (~7s more end-to-end wall), but sum(prove)/e2e= are
    // unaffected (both exclude setup). No-op when JIT is off.
    //
    // One machine per card, built sequentially with the main thread bound to the target card
    // (proving keys are device-resident). Card 0 compiles the JIT kernels; later cards load the
    // same cubins from the shared disk cache and only pay the module load.
    //
    // Held across blocks while the program and settings stay the same (see `resident_for`). The
    // block a machine proves is an argument to `prove_chunk`, not a property of the machine, so
    // nothing below this line is per-block — which is exactly why it can be hoisted and why the
    // per-block state above it must not be.
    let embedded = cfg.embedded.as_ref();
    let vk_on = embedded.is_some() || vk_verification();
    let resident_key = ResidentKey {
        elf: load_program_elf(cfg),
        vk_on,
        log_stacked_height: cfg.log_stacked_height,
        embedded_root: embedded.map(|e| e.trusted_root),
    };
    let caller_riscv = embedded.and_then(|e| e.riscv.as_ref());
    // Card 0's own machine, keygen'd on card 0 (the others in the loop below, on theirs).
    let keygen_riscv = |program: &Arc<Program>, card: usize| {
        #[cfg(feature = "cuda")]
        pico_vm::mle::cuda_mle::runtime::context::set_device(card as i32)
            .unwrap_or_else(|e| panic!("binding the main thread to card {card} failed: {e:?}"));
        #[cfg(not(feature = "cuda"))]
        let _ = card;
        Arc::new(
            RiscvMachine::new(program.clone(), cfg.log_stacked_height, vk_on)
                .unwrap_or_else(|e| panic!("{e}")),
        )
    };
    // Card 0 proves on the caller's machine when it can (see `resident_for`).
    let card0 = |resident: &Resident| {
        match (
            // Card 0's machine holds this program's identity: read, not committed again.
            adoptable(
                caller_riscv,
                |_| resident.provers[0].program_identity(),
                cfg.log_stacked_height,
                vk_on,
            ),
            resident.card0_from,
        ) {
            (Some(machine), _) => Card0::Adopt(machine),
            (None, None) => Card0::Keep,
            // Another caller's machine: not this run's to prove on.
            (None, Some(_)) => Card0::Keygen,
        }
    };
    let build = |elf: Arc<[u8]>| {
        let t_compile = Instant::now();
        let program: Arc<Program> = Compiler::new(SourceType::RISCV, &elf)
            .expect("failed to parse RISC-V ELF")
            .compile();
        info!(
            "MLE program compile done in {:.3}s",
            t_compile.elapsed().as_secs_f64()
        );
        #[cfg(feature = "cuda")]
        let vk_map: Option<Arc<MleVkMap>> = match embedded {
            Some(e) => Some(Arc::clone(&e.whitelist)),
            None => vk_on.then(whitelist_map),
        };
        let t_keygen = Instant::now();
        let mut provers: Vec<Arc<RiscvMachine>> = Vec::with_capacity(prover_count);
        // Card 0 takes the caller's machine when it already holds this program's keys, which
        // keygenning again would only cost time and a second pk on the card.
        let adopted = adoptable(
            caller_riscv,
            |m| {
                pico_vm::mle::machine::riscv::ProgramIdentity::new(&program, &m.vk().inner.params)
                    .ok()
            },
            cfg.log_stacked_height,
            vk_on,
        );
        let card0_from = adopted.as_ref().map(|m| Arc::as_ptr(m) as usize);
        if adopted.is_some() {
            info!("MLE keygen: card 0 reuses the caller's riscv keys");
        }
        for k in 0..prover_count {
            let machine = match (k, &adopted) {
                (0, Some(machine)) => Arc::clone(machine),
                _ => keygen_riscv(&program, k),
            };
            provers.push(machine);
        }
        // Card 0's machine doubles as the vk source below; keygen is deterministic, so every card
        // holds the same vk (asserted here rather than surfacing later as a verify failure).
        let prover = Arc::clone(&provers[0]);
        for (k, p) in provers.iter().enumerate().skip(1) {
            assert_eq!(
                riscv_keys(p),
                riscv_keys(&prover),
                "card {k} keygen'd a different riscv vk than card 0 — keygen is not deterministic"
            );
        }
        let keygen_wall = t_keygen.elapsed();
        info!(
            "MLE keygen done in {:.3}s ({prover_count} card(s))",
            keygen_wall.as_secs_f64()
        );

        // Convert machine + JIT warmup, STILL on the quiescent main thread (the warmup keygen
        // nvrtc-compiles the recursion kernels; libnvrtc deadlocks once the prover threads exist).
        // GPU-only: the convert stage does not exist in a CPU build.
        #[cfg(not(feature = "cuda"))]
        let _ = with_convert;
        // `riscv_vm_vk` is kept: combine hands the root back to the CPU `CombineMachine`, whose
        // acceptance pins the root's `riscv_vk_digest` against this trusted identity.
        #[cfg(feature = "cuda")]
        let (converts, riscv_vm_vk) = if with_convert {
            let t = Instant::now();
            let riscv_vk = Arc::new(prover.vk().clone());
            let riscv_vm_vk = RiscvVmVk::from_program_and_vk(&program, &riscv_vk);
            // The identity a verifier has to be handed (an ethproofs VK bundle's `vm_vk`): the
            // digest preimage without its domain tag, as canonical u32s. Logged from the binary
            // that proves, so the bundle cannot drift from what the roots are pinned against.
            {
                use p3_field::PrimeField32;
                let preimage = riscv_vm_vk.digest_preimage();
                let vm_vk: Vec<String> = preimage[1..]
                    .iter()
                    .map(|e| e.as_canonical_u32().to_string())
                    .collect();
                info!(
                    "exe identity: digest {} | vm_vk ({} u32) = {}",
                    riscv_vm_vk.digest_hex(),
                    vm_vk.len(),
                    vm_vk.join(" ")
                );
            }
            // One machine per card: the per-shape pk cache is device-resident. The warmup keygen
            // nvrtc-compiles once (card 0); later cards hit the cubin disk cache.
            let mut machines = Vec::with_capacity(prover_count);
            for k in 0..prover_count {
                pico_vm::mle::cuda_mle::runtime::context::set_device(k as i32).unwrap_or_else(
                    |e| panic!("binding the main thread to card {k} failed: {e:?}"),
                );
                let mut machine = GpuConvertMachine::new(
                    Arc::clone(&riscv_vk),
                    riscv_vm_vk.clone(),
                    pico_vm::mle::recursion_params_with_128_bits_security(),
                    vk_on,
                );
                if let Some(map) = &vk_map {
                    machine.set_vk_root(map.root());
                }
                let machine = Arc::new(machine);
                machine.pre_keygen_warmup();
                machines.push(machine);
            }
            info!(
                "MLE convert warmup keygen done in {:.3}s ({prover_count} card(s))",
                t.elapsed().as_secs_f64()
            );
            (machines, Some(riscv_vm_vk))
        } else {
            (Vec::new(), None)
        };

        // Combine machines (per card, like convert). Not warmed up: convert's warmup already
        // compiled every cubin combine needs (same chips, same constraint-only JIT sources).
        // Construction is host-side; the pk cache fills lazily on the (bound) preparer threads.
        #[cfg(feature = "cuda")]
        let combines: Vec<Arc<pico_vm::mle::machine::combine::GpuCombineMachine>> = if with_combine
        {
            (0..prover_count)
                .map(|k| {
                    // Bind to the target card first, exactly as the riscv and convert loops above do.
                    // Construction is NOT purely host-side: the JIT kernel handles reached through this
                    // machine are `CUfunction`s, which belong to the loading device's primary context
                    // (see `cuda/jit.rs`'s cache, keyed by device for this reason). Without the bind the
                    // whole vector was built on whatever card the convert loop left current —
                    // `prover_count - 1` — so every card but the last proved against another card's
                    // handles: `cuLaunchKernel` 400, then a sticky illegal access surfacing at an
                    // unrelated free. Invisible at N=1, where that leftover card IS card 0.
                    pico_vm::mle::cuda_mle::runtime::context::set_device(k as i32).unwrap_or_else(
                        |e| panic!("binding the main thread to card {k} failed: {e:?}"),
                    );
                    let mut machine = pico_vm::mle::machine::combine::GpuCombineMachine::new(
                        pico_vm::mle::recursion_params_with_128_bits_security(),
                        vk_on,
                    );
                    if let Some(map) = &vk_map {
                        machine.set_vk_map(Arc::clone(map));
                    }
                    Arc::new(machine)
                })
                .collect()
        } else {
            Vec::new()
        };
        #[cfg(feature = "cuda")]
        let global_logup_nodes: Vec<_> = if with_combine {
            (0..prover_count)
                .map(|k| {
                    // A machine's device engine belongs to the card that is current when it
                    // is made (as the combine machines above).
                    pico_vm::mle::cuda_mle::runtime::context::set_device(k as i32).unwrap_or_else(
                        |e| panic!("binding the main thread to card {k} failed: {e:?}"),
                    );
                    let mut nodes =
                        pico_vm::mle::machine::global_logup_nodes::GlobalLogUpNodeMachine::new(
                            pico_vm::mle::recursion_params_with_128_bits_security(),
                            &prover.vk().inner.params,
                            vk_on,
                        );
                    if let Some(map) = &vk_map {
                        nodes.set_vk_root(map.root());
                    }
                    nodes.use_device();
                    Arc::new(std::sync::Mutex::new(nodes))
                })
                .collect()
        } else {
            Vec::new()
        };
        #[cfg(feature = "cuda")]
        let apex = match (&vk_map, &riscv_vm_vk) {
            (Some(map), Some(vm_vk)) if with_combine => {
                let trusted_root = match embedded {
                    Some(e) => e.trusted_root,
                    None => pinned_root_from_env().unwrap_or_else(|| map.root()),
                };
                Some(Arc::new(MleApexVerifier::new(
                    pico_vm::mle::recursion_params_with_128_bits_security(),
                    pico_vm::mle::compress_params_with_128_bits_security(),
                    Arc::clone(map),
                    vm_vk.clone(),
                    trusted_root,
                )))
            }
            _ => None,
        };
        // Compress machines: one, on card 0, which the main thread proves it on once every lane
        // has joined. Construction binds the card for the same reason the combine loop does.
        #[cfg(feature = "cuda")]
        let compress = match &riscv_vm_vk {
            Some(vm_vk) if with_compress => {
                pico_vm::mle::cuda_mle::runtime::context::set_device(0)
                    .expect("binding the main thread to card 0 failed");
                let params = pico_vm::mle::compress_params_with_128_bits_security;
                let mut gpu = GpuCompressMachine::new(params(), vk_on);
                let mut cpu = CompressMachine::new(params(), vm_vk.clone(), vk_on);
                if let Some(map) = &vk_map {
                    gpu.set_vk_map(Arc::clone(map));
                    cpu.set_vk_map(Arc::clone(map));
                }
                Some((Arc::new(gpu), Arc::new(std::sync::Mutex::new(cpu))))
            }
            _ => None,
        };
        Resident {
            program,
            provers,
            card0_from,
            #[cfg(feature = "cuda")]
            converts,
            #[cfg(feature = "cuda")]
            riscv_vm_vk,
            #[cfg(feature = "cuda")]
            combines,
            #[cfg(feature = "cuda")]
            global_logup_nodes,
            #[cfg(feature = "cuda")]
            vk_map,
            #[cfg(feature = "cuda")]
            apex,
            #[cfg(feature = "cuda")]
            compress,
            keygen_wall,
            shape: (prover_count, with_convert, with_combine, with_compress),
        }
    };
    let resident = resident_for(
        resident_key,
        caller_riscv,
        card0,
        |program| keygen_riscv(program, 0),
        build,
    );
    // A second block asking for a different shape would silently prove against machines built for
    // the first one — wrong card count, or a convert stage that was never constructed.
    assert_eq!(
        resident.shape,
        (prover_count, with_convert, with_combine, with_compress),
        "resident machines were built for a different shape; one process serves one shape"
    );
    // What an embedded run's drain returns the cards' pools to: their use with the resident
    // machines built, whichever block or program built them.
    #[cfg(feature = "cuda")]
    if embedded.is_some() {
        embed::mark_run_start(prover_count);
    }
    // Rebound with the names the pipeline below already uses, so the proving window is untouched
    // by the hoist. Every one of these is an `Arc` clone.
    let program = Arc::clone(&resident.program);
    let provers = resident.provers.clone();
    #[cfg(feature = "cuda")]
    let converts = resident.converts.clone();
    #[cfg(feature = "cuda")]
    let riscv_vm_vk = resident.riscv_vm_vk.clone();
    // The global LogUp's chain over this block's chunks, which every convert leaf and the tree's
    // prefix take their values from.
    #[cfg(feature = "cuda")]
    let global_chain: Option<Arc<GlobalChain>> = (!converts.is_empty()).then(|| {
        Arc::new(GlobalChain::new(
            pico_vm::mle::machine::global_logup::Chain::new(&provers[0].vk().inner.params),
            (mle_two_machine_requested() && !is_mle_secondary()).then(exchange),
        ))
    });
    // The block's real-row count, which the tree's root bounds.
    #[cfg(feature = "cuda")]
    let global_row_count = with_combine.then(|| Arc::new(GlobalRowCount::new()));
    // The pieces of the tree's prefix (group proofs, nodes, reduction steps), which the cards'
    // prover lanes take ahead of their other work. The lanes serve the queue until its sender
    // goes: with the prefix stage, or at once in a run without one.
    let (prefix_pieces_tx, prefix_pieces_rx) = crossbeam::channel::unbounded::<PrefixPiece>();
    // The tree's prefix: once every chunk's table is committed, the global LogUp's second phase
    // over the tables, its nodes, and their reduction to the one proof the scheduler joins with
    // the chunks at the root.
    // A chunk's table is committed as the chunk is traced, so the second phase starts when the
    // last chunk's proof does. Committing each table as its record leaves the emulator would
    // start it earlier, at a GPU task a chunk in the middle of the block; that is not done.
    // Combine nodes the prefix stage proves on its own, reducing the global LogUp's nodes: they
    // go through a card's combine machine without being tasks of the tree.
    #[cfg(feature = "cuda")]
    let prefix_reduction_nodes = Arc::new(AtomicUsize::new(0));
    #[cfg(feature = "cuda")]
    let tree_prefix = match (&global_chain, &riscv_vm_vk) {
        (Some(global_chain), Some(vm_vk)) if with_combine => {
            let (global_chain, vm_vk) = (Arc::clone(global_chain), vm_vk.clone());
            let provers = Arc::new(provers.clone());
            let nodes = Arc::new(resident.global_logup_nodes.clone());
            let combines = Arc::new(resident.combines.clone());
            let reduction_nodes = Arc::clone(&prefix_reduction_nodes);
            let lanes = prefix_pieces_tx;
            let group_len = global_logup_group_len();
            // Of two machines the primary leads the tree: it proves the image node, and reduces
            // its group nodes with the secondary's into the prefix. One machine does both alone.
            let (two_machine, leads) = (mle_two_machine_requested(), !is_mle_secondary());
            let stage = thread::Builder::new()
                .name("mle-global-logup-prefix".into())
                .spawn_watched(move || {
                    let Some(chain) = global_chain.whole() else {
                        return;
                    };
                    let t = Instant::now();
                    let mut tables = std::collections::BTreeMap::new();
                    for prover in provers.iter() {
                        tables.extend(prover.take_chunk_tables());
                    }
                    let chunks = chain.len() - 1;
                    // One machine holds every chunk's table; of two, each those of the chunks
                    // it proved.
                    assert!(
                        if two_machine {
                            tables
                                .keys()
                                .all(|chunk| (1..=chunks as u32).contains(chunk))
                        } else {
                            tables.keys().copied().eq(1..=chunks as u32)
                        },
                        "the provers kept the Global tables of chunks {:?}, the block has \
                         1..={chunks}",
                        tables.keys().collect::<Vec<_>>()
                    );
                    let chain = Arc::new(chain);
                    let Some(own) = group_nodes_on_lanes(
                        &lanes,
                        &provers,
                        &nodes,
                        &vm_vk,
                        tables,
                        &chain,
                        group_len,
                        leads,
                        !two_machine,
                        verify,
                    ) else {
                        return;
                    };
                    let mut steps = own.steps;
                    let mut groups = own.groups;
                    let own_groups = groups.len();
                    let Some(image) = own.image else {
                        // The secondary: its nodes go to the primary, which waits for them.
                        let t_hand = Instant::now();
                        for (&first_chunk, (chunks, node)) in &groups {
                            mle_report_group_node(first_chunk, *chunks, node);
                        }
                        info!("MLE global LogUp pieces: {}", steps.join("; "));
                        info!(
                            "MLE global LogUp: this machine's {own_groups} group node(s) of the \
                             block's {chunks} chunk(s) proved in {:.3}s (second phase {:.3}s, \
                             GPU) and handed to the primary in {:.3}s",
                            (t_hand - t).as_secs_f64(),
                            own.second_phase.as_secs_f64(),
                            t_hand.elapsed().as_secs_f64(),
                        );
                        info!("MLE global LogUp: {}", global_chain.timing());
                        return;
                    };
                    if two_machine {
                        let t_wait = Instant::now();
                        let Some(came) = gather_peer_groups(&mut groups, chunks) else {
                            return;
                        };
                        steps.push(format!(
                            "{came} group node(s) of the other machine, the last {:.3}s after \
                             this machine's",
                            t_wait.elapsed().as_secs_f64()
                        ));
                    }
                    // The early look at the block's sums again, over the nodes' public values:
                    // of the other machine's group proofs only the nodes are here. Nothing is
                    // verified, as for the group proofs.
                    assert!(
                        pico_vm::mle::machine::global_logup_nodes::published_sums_balance(
                            std::iter::once(&image).chain(groups.values().map(|(_, node)| node))
                        ),
                        "the global LogUp's prefix failed: the global LogUp does not balance: \
                         the block's chunks disagree on a cross-chunk event"
                    );
                    // The nodes in the order they lead the tree: the image node, then the
                    // groups' from the last to the first.
                    let layer = std::iter::once(image)
                        .chain(groups.into_values().rev().map(|(_, node)| node))
                        .collect();
                    let Some(prefix) = reduce_on_lanes(
                        &lanes,
                        &combines,
                        layer,
                        &reduction_nodes,
                        verify,
                        &mut steps,
                    ) else {
                        return;
                    };
                    info!("MLE global LogUp pieces: {}", steps.join("; "));
                    info!(
                        "MLE global LogUp: the tree's prefix proved over {chunks} chunk(s) in \
                         {:.3}s: second phase {:.3}s ({} group proof(s), GPU), nodes and their \
                         reduction {:.3}s (GPU)",
                        t.elapsed().as_secs_f64(),
                        own.second_phase.as_secs_f64(),
                        own_groups + 1,
                        (t.elapsed() - own.second_phase).as_secs_f64(),
                    );
                    info!("MLE global LogUp: {}", global_chain.timing());
                    crate::common::mle_scheduler_singleton::mle_report_prefix(prefix);
                })
                .expect("spawn mle-global-logup-prefix");
            Some(stage)
        }
        _ => {
            drop(prefix_pieces_tx);
            None
        }
    };
    #[cfg(not(feature = "cuda"))]
    drop(prefix_pieces_tx);
    #[cfg(feature = "cuda")]
    let combines = resident.combines.clone();
    #[cfg(feature = "cuda")]
    let vk_map = resident.vk_map.clone();
    #[cfg(feature = "cuda")]
    let apex = resident.apex.clone();
    #[cfg(feature = "cuda")]
    let compress = resident.compress.clone();
    let keygen_wall = resident.keygen_wall;
    // Per-block shape statistics, by snapshot-and-difference rather than by reset.
    //
    // The combine machines are resident, so `shapes` and the pk cache it indexes accumulate across
    // blocks — deliberately. A tree's shapes fit its cache and survive into the next block, which
    // is the whole source of the cross-block hits a sweep is expected to show.
    //
    // Resetting `shapes` per block is the obvious alternative and breaks the credit path: a hit is
    // credited by finding the record whose `shape_id` matches the cache entry's, so clearing the
    // records leaves block 2's hit on block 1's pk with nothing to credit. `shape_nodes` then comes
    // out short of `nodes` and the assertion below fires on a run that is entirely correct — in
    // exactly the case this design predicts and wants to measure.
    #[cfg(feature = "cuda")]
    let shape_baseline: Vec<(usize, usize, usize)> = combines
        .iter()
        .map(|m| {
            let s = m.shape_stats();
            (s.keygens, s.hits, s.evictions)
        })
        .collect();
    // Machine construction is done — rebind the main thread to card 0 (it constructed card k's
    // machines while bound to k; everything it does from here on is host-side or card-0).
    #[cfg(feature = "cuda")]
    pico_vm::mle::cuda_mle::runtime::context::set_device(0)
        .expect("rebinding the main thread to card 0 failed");
    vram_probe("after_setup", iteration.unwrap_or(0), prover_count);

    // The root node's proof + its ordered child layouts, stashed by whichever worker proves the
    // final node. Written exactly once (asserted), read on the main thread after the join.
    #[cfg(feature = "cuda")]
    let root_slot: Arc<std::sync::Mutex<Option<RootRecord>>> =
        Arc::new(std::sync::Mutex::new(None));
    // Per block, like the root slot: a keygen a failed block leaves behind is never handed to the
    // next one. The secondary never prepares the final node, so it has none to start, and a root
    // left to the compress proof is not accepted here (see `accept_root`), so it needs no keygen.
    #[cfg(feature = "cuda")]
    let early_root = (with_combine
        && !is_mle_secondary()
        && root_early_keygen_enabled()
        && (verify || compress.is_none()))
    .then(|| {
        EarlyRootKeygen::new(
            riscv_vm_vk
                .clone()
                .expect("combine implies convert, which builds the exe identity"),
            vk_map.clone(),
        )
    });
    // Combine node timing. Kept OUT of `prove_nanos` / `prove_count` on purpose: those two are the
    // riscv chunk figures the `chunks=` / `sum(prove)` bench fields report, and mixing combine into
    // them would break comparability with the riscv/convert baselines.
    #[cfg(feature = "cuda")]
    let combine_nanos = Arc::new(AtomicU64::new(0));
    #[cfg(feature = "cuda")]
    let combine_count = Arc::new(AtomicUsize::new(0));

    // --- Emulation via the shared snapshot+sequencer pipeline. ---
    // Segments through `emulate_snapshot_pipeline` (same emulator + `bench_riscv_ops` opts, the
    // replay workers on the engine `replay_workers` resolved). The pipeline self-inits the memory
    // pool + recycler threads; `MEMORY_POOL_SIZE` keeps the pool larger than the chunk count so the
    // blocking snapshot `recv` never starves. The emulation-only witness carries no proving keys —
    // MLE proves with its own `RiscvMachine`. `handle_record` forwards each record to the preparer
    // thread (crossbeam Sender is Send+Sync, which the pipeline's handler requires); the event
    // precompute in `prepare_chunk_shaped` stays off this thread.
    // The embedded entry states its replay engine with its options; the CLI's is `replay`.
    // In whitelist mode a CPU chunk needs a row of the core ladder, so the split is asked to
    // close chunks to it; an embedded entry is a whitelist prover and states it with its options.
    let emulator_opts = embedded
        .map(|e| e.emulator_opts)
        .unwrap_or_else(|| EmulatorOpts::bench_riscv_ops().with_replay_workers(replay))
        .with_ladder_fit(vk_on);
    let emulation_workers = embedded.map(|e| e.emulation_workers);
    // `MLE_PREWARM=1`: pay the process's first-touch page-fault cost HERE, before the `e2e=` window
    // opens, instead of inside the first chunk's emulate/prepare where it lands on the pipeline's
    // critical path. The prove lane IS the critical path at that moment but has nothing to work on
    // yet, so every millisecond the first chunk spends faulting pages in passes 1:1 into
    // `prove(wall)`. Measured on reth-171 (n>=3, control and treatment interleaved): the first
    // iteration's `e2e=` runs 419±52 ms slower than the warm ones, and this drops that to
    // 42±107 ms — indistinguishable from zero, with the warm iterations unchanged.
    //
    // Two things get pre-paid: the emulator memory pool's `Lazy` (which would otherwise initialize
    // inside the window), and `MLE_HEAP_PREWARM_GB` GB of heap pages that are touched and then
    // freed, so the ~30 per-chunk event `Vec`s in `prepare_chunk_shaped` — the single biggest
    // contributor, 201 of the 419 ms — reuse warm pages instead of faulting fresh ones.
    //
    // REQUIRES `TCMALLOC_RELEASE_RATE=0` to do most of its work: gperftools tcmalloc hands freed
    // large spans back to the kernel with `MADV_DONTNEED`, which throws the pre-faulted pages away
    // before `prepare_chunk_shaped` ever asks for them. Prewarm alone recovers only ~1/3 of the
    // gap; `TCMALLOC_RELEASE_RATE=0` alone recovers nothing (nothing has been freed yet on the
    // first iteration, so there are no pages to retain). `single_node_mle.sh` sets both.
    //
    // Process-level, not per-iteration: `MLE_REPEAT` calls this function N times, and re-growing
    // and re-freeing the arena on every iteration churns exactly the pages the previous iteration
    // warmed — which cost ~50 ms per warm iteration when this was first written per-iteration.
    if env_flag("MLE_PREWARM") {
        static PREWARMED: std::sync::Once = std::sync::Once::new();
        PREWARMED.call_once(|| {
            let t = Instant::now();
            // At the size the run's own check gives an unset MEMORY_POOL_SIZE: the pool keeps the
            // size it is built at, and that check comes after this.
            init_memory_pool_for(
                emulation_workers.unwrap_or_else(pipeline_workers_from_env),
                emulator_opts.snapshot_main,
            );
            let gb: usize = std::env::var("MLE_HEAP_PREWARM_GB")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(0);
            let mut bufs: Vec<Vec<u8>> = Vec::with_capacity(gb);
            for _ in 0..gb {
                bufs.push(vec![1u8; 1 << 30]);
            }
            drop(bufs);
            info!("MLE prewarm done in {:.3}s", t.elapsed().as_secs_f64());
        });
    }
    // Rendezvous with the peer before the window opens, so the two machines emulate against the
    // same clock instead of whenever each personally finished building. Without it the halves ran
    // in SERIES rather than parallel — see `wait_for_peer_worker` for the reth-24006677 timeline
    // showing zero overlap between the two machines' chunk proving.
    //
    // Primary side only. The secondary is already gated: it blocks on connecting to the primary's
    // scheduler at launch, so it cannot start before the primary is serving. This closes the other
    // direction, which was open.
    if mle_two_machine_requested() && !is_mle_secondary() {
        let secs = std::env::var("MLE_PEER_WAIT_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(600);
        let t_wait = Instant::now();
        info!("MLE primary: waiting for the peer machine's pipeline before starting");
        if crate::common::machine_role::wait_for_peer_worker(Duration::from_secs(secs)) {
            info!(
                "MLE primary: peer ready after {:.3}s — starting the pipeline",
                t_wait.elapsed().as_secs_f64()
            );
        } else {
            // Not fatal: fall through to the pre-barrier behaviour rather than fail a run that
            // could still complete. Loud, because a run that silently lost half its hardware is
            // exactly the thing that took a long time to notice in the first place.
            warn!(
                "MLE primary: no peer worker polled within {secs}s — starting alone. Two-machine \
                 will be no faster than single-node, and probably slower."
            );
        }
    }
    // Pipeline scope start — the FRI-`E2E_total`-comparable window (emulate→prove;
    // the compile/keygen/pools setup above this line is excluded). Reported as `e2e=`.
    let t_e2e = Instant::now();
    #[cfg(feature = "cuda")]
    if let Some(global_chain) = &global_chain {
        global_chain.start_clock();
    }
    // Span recording starts with the window, so the one-time setup above — which no per-chunk change
    // can move — is outside it and stays unrecorded. Every span timestamp is relative to here.
    spans::set_origin(t_e2e);
    // Records are index-stamped at the source with the position they hold in the emulation, because
    // the scheduler, the combine tree and the tail barrier are all keyed by that index. Delivery is
    // not in that order once anything upstream runs concurrently — several riscv preparers, or
    // `NUM_THREADS > 1` in the emulator — so it is the stamp that downstream restores order from.
    // Where the stamp comes from is at the send below.
    let (record_tx, record_rx) = crossbeam::channel::unbounded::<(usize, EmulationRecord)>();
    // Set once the guest's emulation fails in an embedded run: the run drains instead of proving.
    let guest_failed = Arc::new(AtomicBool::new(false));
    // Set by a riscv preparer that refuses a chunk's shape in an embedded run; drains the same way.
    let refused_shape = Arc::new(std::sync::Mutex::new(
        None::<pico_vm::mle::machine::riscv::CatchAllShape>,
    ));
    // Set by the riscv preparer whose chunk takes the block past the global LogUp's real-row
    // limit in an embedded run; drains the same way.
    let over_global_row_count = Arc::new(std::sync::Mutex::new(None::<TooManyGlobalRows>));
    let embedded_run = embedded.is_some();
    // Two machines: the chunks the other machine traces reach this machine's chain on a thread
    // of their own, which ends with the chain whole, or at `peer_chunks_done`.
    #[cfg(feature = "cuda")]
    let peer_chunks_done = Arc::new(AtomicBool::new(false));
    #[cfg(feature = "cuda")]
    let peer_chunks = match &global_chain {
        Some(global_chain) if mle_two_machine_requested() => {
            let (global_chain, count) = (Arc::clone(global_chain), global_row_count.clone());
            let (done, guest_failed) = (Arc::clone(&peer_chunks_done), Arc::clone(&guest_failed));
            let over = Arc::clone(&over_global_row_count);
            let peer = thread::Builder::new()
                .name("mle-global-chain-peer".into())
                .spawn_watched(move || {
                    follow_peer_chunks(
                        &global_chain,
                        count.as_deref(),
                        &done,
                        &guest_failed,
                        |too_many| {
                            stop_over_global_rows(too_many, embedded_run, &over, &guest_failed)
                        },
                    );
                })
                .expect("spawn mle-global-chain-peer");
            Some(peer)
        }
        _ => None,
    };
    let deferred = Arc::new(DeferredGate::from_env());
    let emulate_handle = {
        let program = program.clone();
        let guest_failed = Arc::clone(&guest_failed);
        let deferred = Arc::clone(&deferred);
        thread::Builder::new()
            .name("mle-emulate".into())
            .spawn_watched(move || {
            let t = Instant::now();
            // Inside the thread, so the window the phase probes localised the leak to can be split
            // between this thread's own work and everything running beside it. The first of these
            // is also this thread's first CUDA call, so whatever per-thread state that costs shows
            // up as `preparers_spawned -> emu_start` rather than inside the thread's own span.
            vram_probe("emu_start", iteration.unwrap_or(0), prover_count);
            let corrupted = Arc::new(AtomicBool::new(false));
            let witness = ProvingWitness::<KoalaBearPoseidon2, RiscvChipType<KoalaBear>>::
                setup_for_mle_riscv(program, stdin, emulator_opts);
            vram_probe("emu_witness", iteration.unwrap_or(0), prover_count);
            let emulated = {
                let corrupted = Arc::clone(&corrupted);
                let refused = Arc::clone(&guest_failed);
                let on_record = move |mut record: EmulationRecord, _done: bool| {
                    inject::at(inject::Stage::Emulate);
                    // Nothing downstream will take it: end the emulation rather than run on.
                    if watch::failed() {
                        panic!("emulation stopped: the pipeline failed");
                    }
                    // A preparer refused a chunk, for its shape or for the block's limit on
                    // cross-chunk rows: the run fails whatever comes next.
                    if refused.load(Ordering::SeqCst) {
                        panic!("emulation stopped: a preparer refused a chunk");
                    }
                    if corrupt_memory && !corrupted.load(Ordering::Relaxed) {
                        // Tamper the first tamperable record (exactly one).
                        if corrupt_one_record(&mut record) {
                            corrupted.store(true, Ordering::Relaxed);
                        }
                    }
                    // Stamp with the record's own position: `public_values.chunk`, 1-based, so the
                    // sinks' 0-based index is one less. Not an arrival counter — under
                    // `NUM_THREADS > 1` records finish out of order, and a counter would have the
                    // combine tree pairing chunks that are not adjacent. FRI's coordinator keys on
                    // the same field.
                    let seq = record.chunk_index() - 1;
                    if !record.is_cpu_chunk {
                        deferred.admit(|| run_stopped(&refused));
                    }
                    record_tx.send((seq, record)).expect("preparer hung up");
                };
                // The embedded entry states its replay workers; the CLI reads `NUM_THREADS`.
                let run = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    match emulation_workers {
                        Some(workers) => emulate_snapshot_pipeline_with(
                            &witness,
                            workers,
                            DeferredSplit::FromChunk16,
                            on_record,
                        ),
                        None => emulate_snapshot_pipeline(&witness, on_record),
                    }
                }));
                // record_tx drops here → the preparer sees the end of the stream.
                //
                // The cycle count used to go with it: the whole tuple was discarded by the
                // `.expect`, and ethproofs requires `proving_cycles` on every submission, so there
                // was no way to fill that field without re-emulating the block.
                match run {
                    Ok(Ok((_reports, total_cycles, pv_stream))) => Ok((total_cycles, pv_stream)),
                    // An embedded caller gets the guest's failure back and the run drains; the
                    // CLI still stops on it.
                    Ok(Err(e)) if embedded_run => Err(GuestFailure::Emulation(e)),
                    Ok(Err(e)) => panic!("snapshot pipeline failed: {e:?}"),
                    // A panic is the emulation's own unless another pipeline thread failed first,
                    // or it is the symptom of one that is still unwinding (a closed channel).
                    Err(payload)
                        if embedded_run
                            && !watch::failed()
                            && !watch::is_symptom(&watch::panic_message(&*payload)) =>
                    {
                        Err(GuestFailure::Panicked(watch::panic_message(&*payload)))
                    }
                    Err(payload) => std::panic::resume_unwind(payload),
                }
            };
            let (emulated_cycles, committed, failure) = match emulated {
                Ok((cycles, committed)) => (cycles, committed, None),
                Err(failure) => {
                    guest_failed.store(true, Ordering::SeqCst);
                    mle_abort_run();
                    (0, Vec::new(), Some(failure))
                }
            };
            if corrupt_memory && failure.is_none() && !corrupted.load(Ordering::Relaxed) {
                panic!(
                    "CORRUPT_MEMORY: no pass-through cell found to tamper; negative test could not run"
                );
            }
            vram_probe("emu_end", iteration.unwrap_or(0), prover_count);
            (t.elapsed(), emulated_cycles, committed, failure)
        })
        .expect("spawn mle-emulate")
    };
    vram_probe("emulate_spawned", iteration.unwrap_or(0), prover_count);

    // ---- Stage topology: one GPU card = two prover lanes, or one under MLE_RECURSION_LANE=0. ----
    //
    //   CPU  mle-riscv-preparer xR  --(idx, PreparedChunk)--> store, then a scheduler task
    //        mle-convert-preparer xC --(ConvertWork)--> the card's recursion-serving lane
    //        mle-combine-preparer xB --(CombineWork)--> the card's recursion-serving lane
    //   GPU  mle-prover-k:     riscv, plus its card's ready lanes once the chunk feed is drained --
    //                          a lane with nothing left to do should not sit parked while its card
    //                          has work, which is what the pre-split single lane already did
    //        mle-prover-rec-k: convert + combine, selecting across the two ready lanes
    //        one mle-dispatch thread feeds a single shared chunk lane that any idle card drains,
    //        routes combine tasks to the preparer pool, and closes the drain channel when no
    //        further chunk can be dispatched.
    //
    // Under `MLE_RECURSION_LANE=0` there is no `mle-prover-rec-k`: `mle-prover-k` selects across
    // all three feeds from the start, which is the shape the second lane was split out of — and
    // the drain transition above does NOT apply to it. That lane is its card's only recursion
    // consumer, so deferring recursion behind a queued chunk there would push the whole combine
    // tree past the last riscv prove. Nothing else in this
    // diagram moves -- the preparer pools are sized by CARD (`preparer_pool`), the ready lanes are
    // one per card either way, and the riscv queue is untouched (see its own note below).
    //
    // Card affinity: a chunk has none. The old rule was `idx % N` fixed at the riscv routing
    // point, but the riscv preparers are an unrouted pool and `prepare_chunk_shaped` allocates no
    // device memory, so a prepared chunk is host-side and whichever card is free proves it.
    // Convert work is handed out round-robin as well — its preparer binds the card it is about to
    // send to, which is all the per-card pk cache requires — as are combine nodes. Every
    // GPU-touching thread binds its card; the machine layer resolves the device from the thread.
    // Preparer pools: one per kind on a single card, the benchmarked multi-card sizes above that
    // (see `preparer_pool`); the env overrides for A/B work. The pool used to be pinned to
    // 1 because ordering depended on it; it no longer does (see the publish branch below), so the
    // env is honored.
    let riscv_preparer_count = preparer_pool("riscv", "MLE_RISCV_PREPARERS", 6, prover_count);

    // Upstream's upload-ahead preparer barrier is not here: `prepare_chunk_shaped` allocates no
    // device memory, so a prepare cannot contend with a tail's prove.
    let preparer_handle = {
        let mut hs = Vec::new();
        for pidx in 0..riscv_preparer_count {
            let record_rx = record_rx.clone();
            let store = Arc::clone(&store);
            let shaper = Arc::clone(&provers[0]);
            let guest_failed = Arc::clone(&guest_failed);
            let refused_shape = Arc::clone(&refused_shape);
            #[cfg(feature = "cuda")]
            let (global_row_count, over_global_row_count) =
                (global_row_count.clone(), Arc::clone(&over_global_row_count));
            let deferred = Arc::clone(&deferred);
            hs.push(
                thread::Builder::new()
                    .name(format!("mle-riscv-preparer-{pidx}"))
                    .spawn_watched(move || {
                        spans::bind_lane(LaneId::new(Role::RiscvPreparer, pidx));
                        let t = Instant::now();
                        let mut n = 0usize;
                        while let Some((idx, record)) =
                            recv_idle(&record_rx, WorkKind::PrepareRiscv)
                        {
                            // A stopped run: drop the record, which returns its history slot. Not a
                            // `break`, which would leave the rest of the records, and their slots,
                            // on the channel.
                            if run_stopped(&guest_failed) {
                                continue;
                            }
                            // This lane has no `Wait`: `prepare_chunk_shaped` takes no gate
                            // (`:505-506` records that it allocates no device memory) and its
                            // downstream is unbounded, so it can only ever block for want of input.
                            let _b = spans::busy(WorkKind::PrepareRiscv, Some(idx as u32));
                            // Not ours to prove: drop the record now, which returns its event
                            // buffer to the pool immediately instead of holding it until the
                            // other machine proves the chunk and says so. Still registered
                            // below — the scheduler learns the block's chunks from the primary,
                            // which must announce every one of them, including the secondary's.
                            if !prepares_chunk(idx) {
                                if !record.is_cpu_chunk {
                                    deferred.release();
                                }
                                drop(record);
                                mle_register_chunk(idx);
                                n += 1;
                                continue;
                            }
                            // Whitelist mode: the shape goes on the record before the device
                            // event staging copies it (decided from the event counter the
                            // packaging computes anyway); plain packaging otherwise.
                            let shaped = if inject::refuses(idx + 1) {
                                Err(pico_vm::mle::machine::riscv::CatchAllShape {
                                    chunk: idx + 1,
                                    natural: "injected by MLE_INJECT_FAILURE".into(),
                                })
                            } else {
                                shaper.try_prepare_chunk_shaped(record)
                            };
                            let chunk = match shaped {
                                Ok(chunk) => chunk,
                                // An embedded caller gets the refusal back and the run drains,
                                // as for a failed guest; the CLI still stops on it.
                                Err(e) if embedded_run => {
                                    let mut slot =
                                        refused_shape.lock().unwrap_or_else(|e| e.into_inner());
                                    // The earliest chunk, whichever preparer got there first.
                                    if slot.as_ref().is_none_or(|kept| e.chunk < kept.chunk) {
                                        *slot = Some(e);
                                    }
                                    drop(slot);
                                    guest_failed.store(true, Ordering::SeqCst);
                                    mle_abort_run();
                                    continue;
                                }
                                Err(e) => panic!("{e}"),
                            };
                            // Stopped while it prepared: dropped, not stored, for the slot's sake.
                            if run_stopped(&guest_failed) {
                                continue;
                            }
                            // The chunk that takes the block past the real-row limit ends the
                            // run as a refused shape does.
                            #[cfg(feature = "cuda")]
                            if let Some(Err(over)) = global_row_count
                                .as_ref()
                                .map(|count| count.add(idx, shaper.chunk_global_row_count(&chunk)))
                            {
                                stop_over_global_rows(
                                    over,
                                    embedded_run,
                                    &over_global_row_count,
                                    &guest_failed,
                                );
                                continue;
                            }
                            let cost = chunk.cost;
                            // Stamps need not arrive ascending: the store is a map and
                            // `register_chunk` keeps only a min/max. They must be distinct — an
                            // overwrite drops a chunk while `register_chunk` early-returns on
                            // the duplicate, leaving the block proven a chunk short.
                            let displaced = store.insert(idx, chunk);
                            assert!(
                                displaced.is_none(),
                                "chunk stamp {idx} arrived twice — the earlier chunk was lost"
                            );
                            if readings_on() {
                                READY_AT.insert(idx, Instant::now());
                            }
                            mle_register_chunk_with_cost(idx, cost);
                            n += 1;
                        }
                        (n, t.elapsed())
                    })
                    .expect("spawn mle-riscv-preparer"),
            );
        }
        #[cfg(feature = "cuda")]
        let global_chain = global_chain.clone();
        // Aggregator: keeps the downstream join's single (chunk_count, wall) shape across R
        // preparers, and owns finalize_emulation.
        thread::Builder::new()
            .name("mle-riscv-preparer-join".into())
            .spawn_watched(move || {
                let mut total = 0usize;
                let mut wall = Duration::ZERO;
                // Every preparer joined before a panic goes on: one left running would read the
                // next run's failure flag.
                let mut panicked = None;
                for h in hs {
                    match h.join() {
                        Ok((n, w)) => {
                            total += n;
                            wall = wall.max(w);
                        }
                        Err(payload) => {
                            panicked.get_or_insert(watch::panic_message(&*payload));
                        }
                    }
                }
                if let Some(message) = panicked {
                    panic!("riscv preparer panicked: {message}");
                }
                if let Some(delay) = inject::finalize_delay() {
                    thread::sleep(delay);
                }
                mle_finalize_emulation();
                #[cfg(feature = "cuda")]
                if let Some(global_chain) = &global_chain {
                    global_chain.set_total(total);
                }
                (total, wall)
            })
            .expect("spawn mle-riscv-preparer-join")
    };
    vram_probe("preparers_spawned", iteration.unwrap_or(0), prover_count);
    // The preparers hold the live receivers: a record left on the channel holds its history slot.
    drop(record_rx);

    // Convert work reaches the prover on its own bounded(1) ready lane, carrying device-built
    // prepares — each parked ctx is a few hundred MB of VRAM (see `ConvertWork`), so the preparer
    // count bounds real residency, not just backpressure. One lane per card: a convert proves on
    // the card its preparer picked round-robin, which is where that preparer cached its pk.
    let (convert_ready_txs, convert_ready_rxs): (Vec<_>, Vec<_>) = (0..prover_count)
        .map(|_| crossbeam::channel::bounded::<(usize, ConvertWork)>(1))
        .unzip();

    #[cfg(feature = "cuda")]
    let convert_prove_nanos = Arc::new(AtomicU64::new(0));
    #[cfg(feature = "cuda")]
    let convert_done = Arc::new(AtomicUsize::new(0));
    // CPU build: no convert stage — the prover reports terminally (the `None` arm below).
    #[cfg(not(feature = "cuda"))]
    let convert_tx: Option<crossbeam::channel::Sender<(usize, MleProof)>> = None;
    // Shared by the convert preparers and the pre-build: one round-robin counter so both hand out
    // the same cards, and the map of the cards the pre-build has already claimed.
    #[cfg(feature = "cuda")]
    let convert_card_rr = Arc::new(AtomicUsize::new(0));
    #[cfg(feature = "cuda")]
    let prebuilt_cards: Arc<DashMap<usize, usize>> = Arc::new(DashMap::new());
    #[cfg(feature = "cuda")]
    let (convert_tx, convert_stage) = if !converts.is_empty() {
        let (convert_tx, convert_rx) = crossbeam::channel::unbounded::<(usize, MleProof)>();
        let num_preparers = preparer_pool("convert", "MLE_CONVERT_PREPARERS", 12, prover_count);
        let mut handles = Vec::new();
        for p in 0..num_preparers {
            let machines = converts.clone();
            let global_chain =
                Arc::clone(global_chain.as_ref().expect("converts come with the chain"));
            let convert_rx = convert_rx.clone();
            let convert_ready_txs = convert_ready_txs.clone();
            let convert_card_rr = Arc::clone(&convert_card_rr);
            let prebuilt_cards = Arc::clone(&prebuilt_cards);
            handles.push(
                thread::Builder::new()
                    .name(format!("mle-convert-preparer-{p}"))
                    .spawn_watched(move || {
                        spans::bind_lane(LaneId::new(Role::ConvertPreparer, p));
                        while let Some((chunk_idx, riscv_proof)) =
                            recv_idle(&convert_rx, WorkKind::PrepareConvert)
                        {
                            if watch::failed() {
                                break;
                            }
                            // A keygen miss inside `prepare_one` opens its own span, which splits
                            // this one around it — see the span module on why that is automatic.
                            let _b = spans::busy(WorkKind::PrepareConvert, Some(chunk_idx as u32));
                            // Pick the card round-robin, NOT by `chunk_idx % cards`. The old form
                            // inherited the riscv stage's card for the chunk, but that stage no
                            // longer pins one, and the modulo had the same defect it did there: a
                            // machine in two-machine mode owns chunks 0-3, 8-11, 16-19..., all
                            // `% 8 < 4`, so convert work only ever reached half the cards
                            // (reth-239: 12 chunks each on cards 0-3, none on 4-7).
                            //
                            // Whatever card is chosen, prepare and prove agree on it, which is all
                            // the pk cache requires: `prepare_one` does GPU work on a keygen cache
                            // miss and the pk it caches must live on the card that proves with it,
                            // so this thread binds the card it is about to send to. Spreading the
                            // chunks warms the pk on all eight cards rather than four, which
                            // single-node already did by owning every index.
                            // The leaf enters the global LogUp's chain at the value after
                            // the chunks before it, known once their tables are committed.
                            // Waited for before a card is bound or device memory taken, and
                            // counted as waiting, not as preparing.
                            let chain_in = {
                                let _w =
                                    spans::wait(WorkKind::PrepareConvert, Some(chunk_idx as u32));
                                global_chain.before(chunk_idx)
                            };
                            // The chunk's card, claimed by whichever of this thread and the
                            // pre-build asked first. A key warmed under
                            // `MLE_CONVERT_PREBUILD_PK` is on that card; if the pre-build has not
                            // finished, or never ran, this keygens here exactly as it did before.
                            let card = convert_card_for(
                                chunk_idx,
                                &prebuilt_cards,
                                &convert_card_rr,
                                machines.len(),
                            );
                            pico_vm::mle::cuda_mle::runtime::context::set_device(card as i32)
                                .unwrap_or_else(|e| {
                                    panic!("binding preparer to card {card} failed: {e:?}")
                                });
                            inject::at(inject::Stage::Convert);
                            let prepared = machines[card].prepare_one(&riscv_proof, chain_in);
                            info!("[mle-convert-preparer-{p}] chunk {chunk_idx} prepared");
                            // Built here, off the prover lane, so the prover never queues behind
                            // a ~10 ms build.
                            let work = ConvertWork(machines[card].build_convert_ctx(prepared));
                            // The bounded(1) send backpressures this preparer, which is fine —
                            // there is nowhere for more staged work to go anyway.
                            //
                            // That backpressure is `Wait`, not work: the lane is blocked because
                            // the prover has not drained the lane, which is downstream capacity.
                            // Left inside the `Busy` span it would report as this stage doing
                            // something, inflating exactly the figure someone would use to decide
                            // whether the host-side prepare is the constraint.
                            {
                                let _w =
                                    spans::wait(WorkKind::PrepareConvert, Some(chunk_idx as u32));
                                convert_ready_txs[card]
                                    .send((chunk_idx, work))
                                    .expect("prover hung up");
                            }
                        }
                    })
                    .expect("spawn mle-convert-preparer"),
            );
        }
        (Some(convert_tx), handles)
    } else {
        (None, Vec::new())
    };

    // Combine work reaches the prover the same way convert work does: a bounded(1) ready lane
    // carrying device-built prepares — each parked node holds a device ctx of its own (not free),
    // so the preparer count bounds how many. Per card; a node's card is assigned round-robin at
    // prepare time (combine children are host-side proofs, so any card can prove any node — the
    // assignment just has to match where its pk was keygen'd).
    let (combine_ready_txs, combine_ready_rxs): (Vec<_>, Vec<_>) = (0..prover_count)
        .map(|_| crossbeam::channel::bounded::<CombineWork>(1))
        .unzip();
    // The dispatcher's combine feed. Unbounded like the convert feed: tasks are Arc'd proof pairs
    // (KiB-scale, host-side), and bounding it would stall the dispatcher — which is also the riscv
    // task pump — on combine backpressure.
    #[cfg(feature = "cuda")]
    let (combine_task_tx, combine_task_rx) =
        crossbeam::channel::unbounded::<CombineTask<SchedulerProof>>();
    // Combine preparers: the CPU stage of each node (layout extraction, shape keygen, PV preflight,
    // recursion emulation) runs here, off the prover slot. What the slot keeps is the prove.
    // Round-robin card assignment for combine nodes, shared across the preparer pool.
    #[cfg(feature = "cuda")]
    let combine_card_seq = Arc::new(AtomicUsize::new(0));
    #[cfg(feature = "cuda")]
    let combine_stage = if !combines.is_empty() {
        let num_preparers = preparer_pool("combine", "MLE_COMBINE_PREPARERS", 7, prover_count);
        let mut handles = Vec::new();
        for p in 0..num_preparers {
            let machines = combines.clone();
            let scheduler = Arc::clone(&scheduler);
            let combine_task_rx = combine_task_rx.clone();
            let combine_ready_txs = combine_ready_txs.clone();
            let combine_card_seq = Arc::clone(&combine_card_seq);
            let early_root = early_root.clone();
            handles.push(
                thread::Builder::new()
                    .name(format!("mle-combine-preparer-{p}"))
                    .spawn_watched(move || {
                        spans::bind_lane(LaneId::new(Role::CombinePreparer, p));
                        while let Some(task) = recv_idle(&combine_task_rx, WorkKind::PrepareCombine)
                        {
                            if watch::failed() {
                                break;
                            }
                            let (start, end) = (task.left.start_chunk, task.right.end_chunk);
                            // A node spans a chunk range; the span is labelled with its first, which
                            // is what orders it against the riscv work.
                            let _b = spans::busy(WorkKind::PrepareCombine, Some(start as u32));
                            // Assign the node a card and bind to it: `prepare_node`'s keygen
                            // (cache miss) is GPU work, and the pk it caches must live where the
                            // node will be proven.
                            let card =
                                combine_card_seq.fetch_add(1, Ordering::Relaxed) % machines.len();
                            pico_vm::mle::cuda_mle::runtime::context::set_device(card as i32)
                                .unwrap_or_else(|e| {
                                    panic!("binding preparer to card {card} failed: {e:?}")
                                });
                            // `IndexedProof` hands out `Arc<P>`, but the witness builder needs
                            // owned `Proof`s. Recursion proofs are KiB-scale, so the clone is
                            // noise.
                            let children =
                                [(*task.left.inner).clone(), (*task.right.inner).clone()];
                            // Recomputed here rather than trusted from the task: the answer is
                            // monotonic (false -> true only), so a recompute can promote a node
                            // to the root but never demote one.
                            let is_final = scheduler
                                .is_final_combine(task.left.start_chunk, task.right.end_chunk);
                            if let Some(early) = early_root.as_ref().filter(|_| is_final) {
                                early.start(children.to_vec(), start, end);
                            }
                            inject::at(inject::Stage::Combine);
                            let prepared = machines[card].prepare_node(&children, is_final);
                            info!(
                                "[mle-combine-preparer-{p}] node [{start},{end}] prepared \
                                 (is_final={is_final})"
                            );
                            // Built here, off the prover lane — same reasoning as the convert
                            // preparer above.
                            let work = CombineWork {
                                start_chunk: start,
                                end_chunk: end,
                                built: machines[card].build_node_ctx(prepared),
                            };
                            // Blocked on the prover draining its lane is downstream capacity, so
                            // `Wait` — see the convert preparer above for why leaving it inside
                            // `Busy` would misreport this stage as doing work.
                            {
                                let _w = spans::wait(WorkKind::PrepareCombine, Some(start as u32));
                                combine_ready_txs[card].send(work).expect("prover hung up");
                            }
                        }
                    })
                    .expect("spawn mle-combine-preparer"),
            );
        }
        handles
    } else {
        Vec::new()
    };
    #[cfg(feature = "cuda")]
    drop(combine_task_rx); // preparers hold the only receivers now

    // The clones above are the live ends now.
    drop(convert_ready_txs);
    drop(combine_ready_txs);

    // ---- Prover lanes (+ their dispatcher), per card. ----
    // The dispatcher forwards scheduler tasks as descriptors over bounded(1): the staged ctx lives
    // in the store either way, so this capacity is fairness, not VRAM — it keeps at most one
    // scheduler task in hand, letting convert work interleave instead of queueing behind a
    // 106-chunk riscv backlog. Waiter-based pull, so the 2 ms WaitForMore poll is gone.
    let t_prove = Instant::now();
    // ONE shared lane, drained by whichever card is free, rather than a per-card lane picked by
    // `chunk_idx % cards`. The per-card form assumed a chunk's record was card-resident, but the
    // riscv preparers are an unrouted pool and `prepare_chunk_shaped` allocates no device memory
    // (:708), so a prepared chunk is host-side and any card can prove it.
    //
    // Load-bearing under two-machine, and the reason 8+8 was no faster than 8: a machine proves
    // only the chunks it owns, and the static split hands the primary chunks 0-3, 8-11, 16-19...
    // — every one of them `% 8 < 4`. Half the cards were therefore unaddressable and sat idle for
    // the whole run (reth-239: provers 0-3 took 12 chunks each, provers 4-7 took none). Pulling
    // from a shared queue makes the mapping independent of which indices this machine owns.
    // It also drops the dispatcher's head-of-line stall: a full lane no longer blocks the chunk
    // behind it, because any idle card can take it.
    //
    // Capacity is `prover_count`, not 1: enough for every card to have work in hand without a
    // dispatcher round-trip each, and still far from the 106-chunk riscv backlog that capacity
    // was originally holding back so convert work could interleave.
    let (items_tx, items_rx) =
        crossbeam::channel::bounded::<ProverItem>(chunk_channel_capacity(prover_count));
    // Closed by the dispatcher when no further chunk can be dispatched, which is long before the
    // run completes. A channel rather than a flag because the riscv lane is parked in a `select!`,
    // and only a channel can wake one.
    let (drain_tx, drain_rx) = crossbeam::channel::bounded::<()>(0);
    // Two prover lanes per card (riscv, recursion), or one when the recursion lane is off, plus
    // the dispatcher.
    let mut workers = Vec::with_capacity(lanes_per_card * prover_count + 1);

    {
        // No `Arc::clone(&scheduler)` here any more: the dispatcher reaches the scheduler through
        // the singleton, which is the whole point of this change.
        // Role-labelled, and load-bearing rather than cosmetic: `worker_index_for_id`
        // (`machine_role.rs`) picks the worker index by testing `worker_id.contains(label)` against
        // ["primary", "secondary"] and falls back to `unwrap_or(0)`. An unlabelled id therefore
        // makes EVERY worker on BOTH machines the leader — partitioning collapses and the root pin
        // in `try_acquire_combine_task` lapses. FRI avoids this by construction (its ids are
        // `format!("{}-gpu-prover", get_worker_label())`); MLE's did not. Single-node is unaffected
        // either way, since the label is "primary" and the index is 0.
        // The SCHEDULER's block number, not the ELF selector.
        //
        // `SchedulerService::acquire_task` gates on `block_num != scheduler.get_block_num()` and
        // returns `Wait` when they differ. MLE never sets a block number, so the scheduler's is 0 —
        // passing the reth selector (188) here meant the secondary long-polled, was told to wait
        // every time, and proved nothing while the primary sat on the four chunks reserved for it
        // until its 300s "system is broken" timeout. Reading it back off the scheduler keeps the
        // two in step by construction rather than by a matching constant.
        let block_num = get_mle_scheduler().get_block_num();
        // The dispatcher needs the store to evict records for chunks proved on the other machine
        // (see the acquire loop below), and the prover threads already took the original.
        let store = Arc::clone(&store);
        let deferred = Arc::clone(&deferred);
        let dispatch_id: &'static str =
            Box::leak(format!("{}-mle-dispatch", get_worker_label()).into_boxed_str());
        #[cfg(feature = "cuda")]
        let combine_task_tx = combine_task_tx.clone();
        workers.push(
            thread::Builder::new()
                .name(dispatch_id.into())
                .spawn_watched(move || {
                    spans::bind_lane(LaneId::new(Role::Dispatch, 0));
                    let rt = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .expect("dispatch runtime");
                    let sched = get_mle_scheduler();
                    let mut drain_tx = Some(drain_tx);
                    loop {
                        // Asked here because this is the thread that empties the queue, so the
                        // answer can only have changed as a result of the iteration just finished.
                        // A two-machine secondary never latches `emulation_done` locally, so this
                        // never fires there; its lane instead meets `drain` and `items` closing
                        // together when this thread exits, and by then there is nothing left to
                        // serve either way.
                        if drain_tx.is_some() && sched.chunk_feed_closed() {
                            drain_tx = None;
                        }
                        // Nothing to route yet: a shortage of input, so `Idle`.
                        let acquired = {
                            let _i = spans::idle(WorkKind::Dispatch);
                            let (acquired, proven_elsewhere) =
                                rt.block_on(mle_acquire_task_unified_async(dispatch_id, block_num));
                            // Drop prepared records for chunks somebody else already proved.
                            //
                            // Load-bearing under two-machine, not tidiness. Each machine emulates
                            // the whole block and stores every chunk, but proves only its share,
                            // and a record's slot goes back only when a worker finishes its chunk
                            // and drops the record. Without this the other machine's half is never
                            // dropped: the slots run out, the take waits, emulation stalls and
                            // stops registering, and both sides idle into the scheduler's 300s
                            // "system is broken" timeout. reth-239 stalled at 61 of 122 chunks
                            // against `MLE_HISTORY_SLOTS=64`. FRI does the same thing via
                            // `record_store::send_proven_chunks` on every acquire.
                            //
                            // A no-op in single-node: this machine already removed each chunk in
                            // `take_prepared_chunk` when it proved it.
                            for idx in &proven_elsewhere {
                                if let Some((_, chunk)) = store.remove(idx) {
                                    if !chunk.record.is_cpu_chunk {
                                        deferred.release();
                                    }
                                }
                            }
                            acquired
                        };
                        match acquired {
                            MleAcquireResult::ChunkProof { chunk_idx } => {
                                // Blocking here means every card is saturated, not that one
                                // card's lane is full. Downstream capacity, so `Wait`, not `Idle`.
                                let _w = spans::wait(WorkKind::Dispatch, Some(chunk_idx as u32));
                                if items_tx.send(ProverItem::Riscv { chunk_idx }).is_err() {
                                    break;
                                }
                            }
                            // Combine tasks go to the preparer pool, not the prover: the
                            // prover only ever sees prepared nodes on the ready lane.
                            MleAcquireResult::Combine(task) => {
                                #[cfg(feature = "cuda")]
                                combine_task_tx
                                    .send(task)
                                    .expect("combine preparers hung up");
                                #[cfg(not(feature = "cuda"))]
                                {
                                    let _ = task;
                                    unreachable!(
                                        "CPU build: --step combine requires the `cuda` \
                                             feature"
                                    )
                                }
                            }
                            // The async path parks on a waiter; WaitForMore only leaks through
                            // on races. Back off a hair so a pathology cannot hot-spin.
                            MleAcquireResult::WaitForMore => {
                                thread::sleep(Duration::from_millis(1))
                            }
                            MleAcquireResult::Complete => break,
                        }
                    }
                    // items_tx drops here -> every prover knows the scheduler is drained.
                })
                .expect("spawn mle-dispatch"),
        );
    }

    let _vram = VramWatch::start(prover_count);

    // One pre-build pool for the whole process, shared by every card's riscv lane. Default ON:
    // `None` only when `MLE_CONVERT_PREBUILD` is set to an off-word or program sharing is off,
    // and then the lanes take the unhooked path (see [`ConvertPrebuild`]). Built here, after the
    // convert machines exist and before any riscv lane is handed out.
    #[cfg(feature = "cuda")]
    let convert_prebuild = (!converts.is_empty())
        .then(|| {
            ConvertPrebuild::new(
                converts.clone(),
                Arc::clone(&convert_card_rr),
                Arc::clone(&prebuilt_cards),
                // Past the preparer pool's own indices, so the two never share a lane.
                preparer_pool("convert", "MLE_CONVERT_PREPARERS", 12, prover_count),
            )
        })
        .flatten()
        .map(Arc::new);

    for k in 0..prover_count {
        // The riscv handles. Built per call site rather than once and moved, so that they and the
        // queue are handed out by the SAME conditional below: exactly one thread per card may hold
        // them, and it must be the one holding the queue. A lane with the queue and no handles
        // panics on its first chunk; a lane with the handles and no queue never releases the
        // `convert_tx` inside them, and the convert chain cannot drain (see [`RiscvLane`]).
        let riscv_lane = || RiscvLane {
            store: Arc::clone(&store),
            prover: Arc::clone(&provers[k]),
            #[cfg(feature = "cuda")]
            global_chain: global_chain.clone(),
            convert_tx: convert_tx.clone(),
            prove_nanos: Arc::clone(&prove_nanos),
            prove_count: Arc::clone(&prove_count),
            verify,
            with_combine,
            guest_failed: Arc::clone(&guest_failed),
            deferred: Arc::clone(&deferred),
            #[cfg(feature = "cuda")]
            convert_prebuild: convert_prebuild.clone(),
        };

        // The default: riscv gets a thread of its own, told apart from the recursion lane by its
        // `Role` (the lane INDEX is the card, for both). Separate threads and not a wider
        // `select!`, because one thread can only be inside one prove at a time whatever it selects
        // on -- sharing the thread is exactly what kept a convert or combine node waiting behind
        // the chunk in front of it on the same card, and is what `MLE_RECURSION_LANE=0` goes back
        // to on the lane below.
        // One per card, shared: with the riscv lane joining the ready lanes once its feed is
        // drained, more than one thread proves this card's recursion work.
        #[cfg(feature = "cuda")]
        let card_rec = Arc::new(CardRecursion {
            convert: converts.get(k).cloned(),
            combine: combines.get(k).cloned(),
            root_slot: Arc::clone(&root_slot),
            convert_prove_nanos: Arc::clone(&convert_prove_nanos),
            convert_done: Arc::clone(&convert_done),
            combine_nanos: Arc::clone(&combine_nanos),
            combine_count: Arc::clone(&combine_count),
            verify,
            with_combine,
            guest_failed: Arc::clone(&guest_failed),
        });

        if rec_lane {
            // `Option`, and dropped the moment the feed closes: it owns this card's `convert_tx`
            // clone and this lane no longer ends there, so holding it would keep the convert
            // preparers' channel open past the last chunk and the final join would hang.
            let mut riscv = Some(riscv_lane());
            // Every card drains the one shared lane; the clone is this card's handle on it.
            let items = items_rx.clone();
            let drain = drain_rx.clone();
            #[cfg(feature = "cuda")]
            let rec = Arc::clone(&card_rec);
            // Held from the start although nothing is read from them until the drain: the arm
            // that attaches them runs inside the closure, so they have to be captured here. The
            // cost is that a live receiver keeps the preparers' `send` from erroring, so if the
            // recursion lane dies the preparer routed to this card blocks instead of panicking
            // with `prover hung up`. That diagnostic is not what reports a dead lane anyway --
            // the process-wide panic hook prints the real cause and exits first.
            let ready_src = convert_ready_rxs[k].clone();
            let combine_src = combine_ready_rxs[k].clone();
            let prefix_src = prefix_pieces_rx.clone();
            let prefix_failed = Arc::clone(&guest_failed);
            // Role-labelled for the same reason as `dispatch_id` above.
            let worker_id = format!("{}-mle-prover-{k}", get_worker_label());
            workers.push(
                thread::Builder::new()
                    .name(worker_id.clone())
                    .spawn_watched(move || {
                        bind_prover_lane(k, Role::Prove);
                        let mut items = items;
                        let mut drain = drain;
                        // Not attached until the feed drains: while chunks can still arrive this
                        // lane's job is riscv alone, and a chunk queued behind a convert on its
                        // own card is exactly what splitting the lanes was for.
                        let mut ready = crossbeam::channel::never();
                        let mut combine_ready = crossbeam::channel::never();
                        let mut prefix_pieces = prefix_src;
                        let mut items_open = true;
                        let mut ready_open = false;
                        let mut combine_ready_open = false;
                        let mut prefix_open = true;
                        while items_open || ready_open || combine_ready_open || prefix_open {
                            // Nothing pushes to this slot, so it can only be idle for want of
                            // input, never blocked on capacity. Each arm's own `Busy` span splits
                            // this one.
                            let _i = spans::idle(WorkKind::Unattributed);
                            // A piece of the tree's prefix goes ahead of whatever else waits, a
                            // chunk included: `select!` would toss a coin between them.
                            if let Ok(piece) = prefix_pieces.try_recv() {
                                run_prefix_piece(piece, k, &prefix_failed);
                                continue;
                            }
                            // Recursion only while no chunk is waiting. `select!` picks at random
                            // among ready arms, and when the feed drains there are still up to
                            // `prover_count` chunks on the lane -- the head of the tail's critical
                            // path, which must not lose a coin toss to a convert. Not
                            // `select_biased!`, which would also put convert ahead of combine, and
                            // that is a preference nobody has measured.
                            //
                            // The queue is shared by every card, so the chunk this saw may be
                            // taken by another lane; the retry is what stops that from parking
                            // this one on a queue that can never refill -- no chunk can arrive
                            // after the feed is drained, so it would sit out the whole tail.
                            let (rdy, comb, retry) = if items.is_empty() {
                                (
                                    ready.clone(),
                                    combine_ready.clone(),
                                    crossbeam::channel::never(),
                                )
                            } else {
                                (
                                    crossbeam::channel::never(),
                                    crossbeam::channel::never(),
                                    crossbeam::channel::after(Duration::from_millis(20)),
                                )
                            };
                            crossbeam::channel::select! {
                                recv(prefix_pieces) -> m => match m {
                                    Ok(piece) => run_prefix_piece(piece, k, &prefix_failed),
                                    Err(_) => {
                                        prefix_open = false;
                                        prefix_pieces = crossbeam::channel::never();
                                    }
                                },
                                recv(items) -> m => match m {
                                    // `items` and the handles travel together: the arm below
                                    // detaches the one as it drops the other, so a chunk cannot
                                    // arrive once they are gone.
                                    Ok(ProverItem::Riscv { chunk_idx }) => riscv
                                        .as_ref()
                                        .expect("a chunk arrived after the riscv handles went")
                                        .prove(chunk_idx, &worker_id, lane_depth(&items)),
                                    Err(_) => {
                                        items_open = false;
                                        items = crossbeam::channel::never();
                                        drain = crossbeam::channel::never();
                                        riscv = None;
                                    }
                                },
                                // Fires on close, the only thing that ever happens to it: the feed
                                // is finished, so start serving this card's recursion work.
                                // `items` stays attached -- chunks can still be on it when this
                                // arrives, so nothing may depend on the signal being exact.
                                recv(drain) -> _ => {
                                    drain = crossbeam::channel::never();
                                    ready = ready_src.clone();
                                    combine_ready = combine_src.clone();
                                    ready_open = true;
                                    combine_ready_open = true;
                                    info!("[{worker_id}] riscv feed drained: serving recursion");
                                },
                                recv(rdy) -> m => match m {
                                    Ok((chunk_idx, work)) => {
                                        #[cfg(feature = "cuda")]
                                        rec.prove_convert(chunk_idx, work, &worker_id);
                                        #[cfg(not(feature = "cuda"))]
                                        {
                                            let _ = chunk_idx;
                                            match work {}
                                        }
                                    }
                                    Err(_) => {
                                        ready_open = false;
                                        ready = crossbeam::channel::never();
                                    }
                                },
                                recv(comb) -> m => match m {
                                    Ok(work) => {
                                        #[cfg(feature = "cuda")]
                                        rec.prove_combine(work, &worker_id);
                                        #[cfg(not(feature = "cuda"))]
                                        {
                                            match work {}
                                        }
                                    }
                                    Err(_) => {
                                        combine_ready_open = false;
                                        combine_ready = crossbeam::channel::never();
                                    }
                                },
                                // Re-sample the queue; see above.
                                recv(retry) -> _ => {}
                            }
                        }
                    })
                    .expect("spawn mle-prover"),
            );
        }

        #[cfg(feature = "cuda")]
        let rec = Arc::clone(&card_rec);
        let convert_ready_rx = convert_ready_rxs[k].clone();
        let combine_ready_rx = combine_ready_rxs[k].clone();
        let prefix_failed = Arc::clone(&guest_failed);
        // The recursion lane by default; under `MLE_RECURSION_LANE=0` this is the card's ONLY
        // prover lane, and then it is the one that gets the riscv handles and the queue, making
        // its `select!` the pre-split three-armed loop exactly. One conditional for all of it, so
        // no two of these can disagree about which shape this lane is.
        //
        // The lane that does NOT serve riscv gets `never()` rather than a second clone of the real
        // receiver: a live receiver parked on a lane that never takes from it stops the
        // dispatcher's `send` from ever erroring, so if the riscv-serving lanes died it would
        // block on a full queue and the final join would hang.
        let (mut riscv, rec_items, rec_prefix, role, worker_id, spawn_err) = if rec_lane {
            (
                None,
                crossbeam::channel::never(),
                crossbeam::channel::never(),
                Role::ProveRecursion,
                format!("{}-mle-prover-rec-{k}", get_worker_label()),
                "spawn mle-prover-rec",
            )
        } else {
            (
                Some(riscv_lane()),
                items_rx.clone(),
                prefix_pieces_rx.clone(),
                Role::Prove,
                format!("{}-mle-prover-{k}", get_worker_label()),
                "spawn mle-prover",
            )
        };
        // What ends the run if this lane panics is the process-wide panic hook in
        // `bin/mle_single_node.rs`: it prints and exits, so the first panic is also the last line.
        //
        // The hook is load-bearing rather than a nicety, because the topology would report this
        // death in the wrong voice. This lane holds the only receivers for its card's convert and
        // combine ready lanes, so while prepares remain the next one routed to that card dies on
        // `.expect("prover hung up")` -- a preparer's panic, one stage downstream of the prover
        // that actually failed -- and once they are done the run instead hangs on the join with no
        // message at all. The hook is what keeps the real cause first in the log.
        workers.push(
            thread::Builder::new()
                .name(worker_id.clone())
                .spawn_watched(move || {
                    bind_prover_lane(k, role);
                    let mut items = rec_items;
                    let mut prefix_pieces = rec_prefix;
                    let mut ready = convert_ready_rx;
                    let mut combine_ready = combine_ready_rx;
                    // Live only when this thread is the one serving riscv; otherwise `items` never
                    // fires and the flag would keep the loop from ever ending. The two travel
                    // together -- `riscv` is `Some` for exactly the lane that took the queue.
                    let mut items_open = riscv.is_some();
                    let mut ready_open = true;
                    let mut combine_ready_open = true;
                    // The prefix's pieces go to the lane that serves riscv, like the chunks.
                    let mut prefix_open = riscv.is_some();
                    while items_open || ready_open || combine_ready_open || prefix_open {
                        // Nothing pushes to this slot, so it can only be idle for want of input,
                        // never blocked on capacity. Each arm's own `Busy` span splits this one.
                        let _i = spans::idle(WorkKind::Unattributed);
                        if let Ok(piece) = prefix_pieces.try_recv() {
                            run_prefix_piece(piece, k, &prefix_failed);
                            continue;
                        }
                        crossbeam::channel::select! {
                            recv(prefix_pieces) -> m => match m {
                                Ok(piece) => run_prefix_piece(piece, k, &prefix_failed),
                                Err(_) => {
                                    prefix_open = false;
                                    prefix_pieces = crossbeam::channel::never();
                                }
                            },
                            recv(items) -> m => match m {
                                Ok(ProverItem::Riscv { chunk_idx }) => riscv
                                    .as_ref()
                                    .expect("riscv work on a lane that does not serve riscv")
                                    .prove(chunk_idx, &worker_id, lane_depth(&items)),
                                Err(_) => {
                                    items_open = false;
                                    items = crossbeam::channel::never();
                                    // The scheduler is drained: no further riscv proofs can exist,
                                    // so release our convert feed and let that chain drain to a
                                    // close -- the ready lanes below are what we keep serving.
                                    riscv = None;
                                }
                            },
                            recv(ready) -> m => match m {
                                Ok((chunk_idx, work)) => {
                                    #[cfg(feature = "cuda")]
                                    rec.prove_convert(chunk_idx, work, &worker_id);
                                    #[cfg(not(feature = "cuda"))]
                                    {
                                        let _ = chunk_idx;
                                        match work {}
                                    }
                                }
                                Err(_) => {
                                    ready_open = false;
                                    ready = crossbeam::channel::never();
                                }
                            },
                            recv(combine_ready) -> m => match m {
                                Ok(work) => {
                                    #[cfg(feature = "cuda")]
                                    rec.prove_combine(work, &worker_id);
                                    #[cfg(not(feature = "cuda"))]
                                    {
                                        match work {}
                                    }
                                }
                                Err(_) => {
                                    combine_ready_open = false;
                                    combine_ready = crossbeam::channel::never();
                                }
                            },
                        }
                    }
                })
                .expect(spawn_err),
        );
    }
    // The provers hold their own clones; drop the originals so the convert chain can drain.
    // Same for the shared riscv queue, and there it is load-bearing rather than tidy: keeping a
    // receiver alive here leaves the channel connected after every riscv-serving lane has died, so
    // the dispatcher's blocking `send` waits forever on a full queue instead of erroring out. The
    // dispatcher is joined first, so that turns an all-lanes-dead panic into a silent hang.
    drop(items_rx);
    // And for the prefix's pieces: with every lane gone, the prefix stage's `send` errors.
    drop(prefix_pieces_rx);
    drop(convert_tx);
    drop(convert_ready_rxs);
    // Same for the combine chain: the dispatcher holds the live task sender (it drops it on
    // `Complete`), and the provers hold the live ready receivers.
    #[cfg(feature = "cuda")]
    drop(combine_task_tx);
    drop(combine_ready_rxs);

    let (emulate_wall, emulated_cycles, committed, guest_failure) = join_stage(
        emulate_handle,
        "emulate thread",
        embedded_run,
        &store,
        &guest_failed,
    )
    .unwrap_or_default();
    vram_probe("emulate_joined", iteration.unwrap_or(0), prover_count);
    let (chunk_count, prepare_wall) = join_stage(
        preparer_handle,
        "preparer thread",
        embedded_run,
        &store,
        &guest_failed,
    )
    .unwrap_or_default();
    // A refusal stops the emulation, so it outranks the failure that stop reports.
    let guest_failure = refused_shape
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .take()
        .map(GuestFailure::CatchAllShape)
        .or_else(|| {
            over_global_row_count
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
                .map(GuestFailure::TooManyGlobalRows)
        })
        .or(guest_failure);
    vram_probe("after_preparer", iteration.unwrap_or(0), prover_count);
    info!(
        "MLE emulate done in {:.3}s, prepare in {:.3}s ({chunk_count} chunk(s))",
        emulate_wall.as_secs_f64(),
        prepare_wall.as_secs_f64(),
    );
    let deferred_stats = (
        deferred.peak.load(Ordering::Relaxed),
        Duration::from_micros(deferred.parked_us.load(Ordering::Relaxed)),
    );
    *LAST_DEFERRED.lock().unwrap_or_else(|e| e.into_inner()) = deferred_stats;
    info!(
        "MLE deferred records: at most {} waiting (bound {:?}), the emulation parked {:.3}s on them",
        deferred_stats.0,
        deferred.bound,
        deferred_stats.1.as_secs_f64(),
    );

    // A stopped run: the guest failed, or (embedded) a pipeline thread panicked. The scheduler is
    // aborted, so every stage drains and exits; the joins below wait for them all, the checks on a
    // finished run are skipped, and the run is drained at the end instead of accepted.
    let stopped = |guest_failure: &Option<GuestFailure>| {
        guest_failure.is_some() || (embedded_run && watch::failed())
    };
    let join = |h: thread::JoinHandle<()>, what| {
        join_stage(h, what, embedded_run, &store, &guest_failed);
    };

    // Nothing to prove (degenerate empty program): the scheduler never completes with zero
    // chunks, so return without joining the workers — process exit reaps them.
    if chunk_count == 0 && !stopped(&guest_failure) {
        info!("MLE single-node: no chunks emulated; nothing to prove");
        // The lanes and the prefix stage are still there: stop them, as a drained run does. The
        // stage itself takes a chain over no chunk for a block without a second phase
        // (`GlobalChain::whole`), whether or not it sees the abort first.
        crate::common::mle_scheduler_singleton::mle_abort_run();
        // The cycle count is real -- the emulator did run -- but there is no root. A caller that
        // has to report this block upstream must report it as unproved, and `root: None` is what
        // says so; handing back a default outcome here would also claim zero cycles.
        return BlockOutcome {
            cycles: emulated_cycles,
            committed,
            ..Default::default()
        };
    }

    // A single chunk: `ProofTree` only pairs ADJACENT proofs, so a lone proof never pairs. With
    // the global LogUp's prefix the scheduler does give a lone chunk a root (the prefix joined
    // with it), but no run has been taken through that path, and without the guard a tree that
    // never collapsed would leave the workers polling forever — silently, because the sync
    // `acquire_task` returns `WaitForMore` rather than registering a waiter. Guard explicitly.
    //
    // Unreachable in practice: memory init/finalize events are deferred out of every CPU chunk
    // into their own record, so any real program emulates to >= 2 chunks. Kept because the failure
    // mode is a silent hang.
    assert!(
        stopped(&guest_failure) || !with_combine || chunk_count >= 2,
        "--step combine needs >= 2 chunks, got {chunk_count} \
         (a lone proof has no adjacent neighbour, so the tree never collapses)"
    );

    for h in workers {
        join(h, "worker thread");
    }
    vram_probe("after_workers", iteration.unwrap_or(0), prover_count);
    // Every proof exists: each lane only exits once its own feeds are closed, so joining the
    // workers drains riscv, convert and combine alike.
    let prove_wall = t_prove.elapsed();

    // The prefix stage took the chunks' Global tables for the second phase. Without a tree (no
    // combine step) nothing proves it, and the tables are dropped here.
    #[cfg(feature = "cuda")]
    if let Some(stage) = tree_prefix {
        join(stage, "global LogUp prefix stage");
    }
    #[cfg(feature = "cuda")]
    if let Some(peer) = peer_chunks {
        peer_chunks_done.store(true, Ordering::SeqCst);
        join(peer, "global LogUp chain peer thread");
    }
    for prover in &provers {
        prover.discard_chunk_tables();
    }

    // The pre-build pool is speculative and unjoined by the channel alone — its `tx` lives in the
    // riscv lanes' hooks — so it is stopped here, before the resident machines serve another block.
    #[cfg(feature = "cuda")]
    if let Some(pb) = convert_prebuild.as_ref() {
        pb.shutdown();
    }

    // Convert stage drain: the workers' exits dropped the last `convert_tx` senders, so the
    // preparer/prover pools run dry and exit; joining them means every convert proof is done.
    #[cfg(feature = "cuda")]
    for h in convert_stage {
        join(h, "convert stage thread");
    }
    #[cfg(feature = "cuda")]
    if !converts.is_empty() && !stopped(&guest_failure) {
        let done = convert_done.load(Ordering::SeqCst);
        // Single-node proves every chunk it emulated, so convert count == chunk count. Under
        // two-machine each side emulates the WHOLE block but proves only its share, so
        // the equality is the wrong invariant there — the secondary emulated 8 and converted 4, and
        // this assert fired on an otherwise correct run. What still holds on both is that every
        // chunk this machine proved got converted.
        if is_mle_secondary() || mle_two_machine_requested() {
            assert!(
                done <= chunk_count,
                "convert proofs ({done}) exceed the {chunk_count} chunks emulated"
            );
        } else {
            assert_eq!(
                done, chunk_count,
                "convert proofs ({done}) != riscv chunks ({chunk_count})"
            );
        }
        let convert_total = Duration::from_nanos(convert_prove_nanos.load(Ordering::SeqCst));
        let convert_note = if verify {
            "proved + verified"
        } else {
            "proved (verify skipped; set MLE_VERIFY=1 to enable)"
        };
        info!(
            "MLE convert complete: all {done} convert proof(s) {convert_note} ✓ | sum(convert)={:.3}s avg/chunk={:.3}s",
            convert_total.as_secs_f64(),
            convert_total.as_secs_f64() / (done.max(1) as f64),
        );
    }

    vram_probe("after_convert_report", iteration.unwrap_or(0), prover_count);
    // Combine preparer drain: the dispatcher's exit dropped the last task sender, so the pool
    // runs dry and exits; joining it propagates any preparer panic. An arity-2 reduction of N
    // leaves has exactly N-1 internal nodes, so the count check doubles as an engagement check —
    // a dead ready lane could not have produced them.
    #[cfg(feature = "cuda")]
    for h in combine_stage {
        join(h, "combine preparer thread");
    }
    #[cfg(feature = "cuda")]
    if !combines.is_empty() && !stopped(&guest_failure) {
        let nodes = combine_count.load(Ordering::SeqCst);
        // A binary tree over N chunks has N-1 internal nodes, and single-node proves all of them.
        // Under two-machine the tree is one tree but its nodes are split across the machines --
        // measured 4 + 3 = 7 for an 8-chunk block -- so the per-machine count is a share, not the
        // total. Asserting equality locally failed on BOTH sides of a run whose tree was in fact
        // complete. The whole-run count is checked where it can be: the scheduler only reports the
        // run complete once its proof tree is (`is_proof_tree_complete`).
        // The chunks' tree has `chunk_count - 1` nodes, and the root joins it with the prefix.
        if mle_two_machine_requested() {
            assert!(
                nodes <= chunk_count,
                "combine nodes proved ({nodes}) exceeds the {chunk_count} a {chunk_count}-chunk \
                 tree has with its root"
            );
        } else {
            assert_eq!(
                nodes, chunk_count,
                "combine nodes proved ({nodes}) != chunks - 1 for the chunks' tree, plus the root"
            );
        }
    }

    // Every stage has joined. Drop what the run prepared and the cross-chunk sums it accumulated,
    // so the resident machines and the history slots serve the next block as if this one never ran.
    if stopped(&guest_failure) {
        // A root keygen started on the final node before the run stopped is CPU work; joined so
        // that nothing of this run outlives it.
        #[cfg(feature = "cuda")]
        if let Some(keygen) = early_root.as_ref().and_then(EarlyRootKeygen::take) {
            let _ = keygen.join();
        }
        store.clear();
        for prover in &provers {
            prover.discard_chunk_tables();
        }
        let stage_failure = watch::failure_message().filter(|_| embedded_run);
        match (&guest_failure, &stage_failure) {
            (Some(failure), _) => info!("MLE run drained after the guest failed: {failure}"),
            (None, Some(message)) => info!("MLE run drained after a stage failed: {message}"),
            (None, None) => {}
        }
        return BlockOutcome {
            cycles: emulated_cycles,
            committed,
            guest_failure,
            stage_failure,
            ..Default::default()
        };
    }

    vram_probe("after_combine_check", iteration.unwrap_or(0), prover_count);
    // Window ends here: every proof exists and every stage has joined. Root acceptance below is CPU
    // work on a lane-less thread, so leaving it inside made the window outlast every lane and read as
    // device idleness.
    let e2e_wall = t_e2e.elapsed();
    // Starts where the window ended, so the two meet exactly and leave no unattributed sliver.
    #[cfg(feature = "cuda")]
    let t_accept = Instant::now();
    // Set at the end of the acceptance block; stays zero when there is none to do.
    #[cfg_attr(not(feature = "cuda"), allow(unused_mut))]
    let mut root_accept = Duration::ZERO;
    // Filled in the acceptance block below, i.e. only once the root has passed host-side
    // acceptance. A root this process has not itself verified must never reach a submission.
    #[cfg_attr(not(feature = "cuda"), allow(unused_mut))]
    let mut root_export: Option<RootProofExport> = None;
    // Likewise for the compress proof: filled only once the compress proof has passed host-side
    // acceptance and the standalone apex.
    #[cfg_attr(not(feature = "cuda"), allow(unused_mut))]
    let mut compress_export: Option<CompressProofExport> = None;

    // Combine stage: the tree collapsed (that is what let the workers exit), so the root is in the
    // slot. Acceptance runs on the CPU `CombineMachine` — deliberately, so the four-step host-side
    // check (honest-vk substitution, `flag_complete`, the exe anchor, PV-digest recompute) exists
    // in exactly one place instead of being transcribed onto the GPU machine. `register_shape`
    // first: `verify` checks against a VK this machine keygen'd itself, never the supplied one, so
    // the root's shape has to exist here (its documented CONTRACT). Rebuilding the root program
    // from the child layouts also catches a GPU-side program built with the wrong parameters —
    // a mismatch shows up as no matching complete shape.
    // The secondary never holds the root: `try_acquire_combine_task` refuses the final combine to
    // any non-leader worker, so the root is proved AND accepted on the primary by construction.
    // Without this guard the secondary would die on the `expect` below at the end of an otherwise
    // successful run — its slot is empty by design, not by failure.
    #[cfg(feature = "cuda")]
    if !combines.is_empty() && is_mle_secondary() {
        info!("secondary: run complete; the root is proved and accepted on the primary");
    }
    #[cfg(feature = "cuda")]
    if !combines.is_empty() && !is_mle_secondary() {
        let root = root_slot
            .lock()
            .expect("root slot mutex poisoned")
            .take()
            .expect("scheduler reported complete but no final combine node was recorded");
        // Each convert leaf wrote its chunk's share and the tree added them up, so the root
        // carries the count the chunks were counted at, the other machine's among them.
        if let Some(global_row_count) = &global_row_count {
            let counted = global_row_count.counted.load(Ordering::SeqCst);
            assert_eq!(
                pico_vm::mle::machine::global_logup_nodes::global_row_count_of(&root.proof),
                Some(counted),
                "the root's real-row count is not the one the block's chunks were counted at"
            );
            info!(
                "MLE global LogUp: the block's real-row count is {counted}; a block may reach {}",
                global_row_count.limit
            );
        }
        let nodes = combine_count.load(Ordering::SeqCst);
        let combine_total = Duration::from_nanos(combine_nanos.load(Ordering::SeqCst));

        // With a compress stage and `MLE_VERIFY` off, the root is an intermediate proof like the
        // nodes under it and is left to the compress proof: the compress circuit verifies the root
        // (in whitelist mode re-checking the root key's membership), and the compress acceptance
        // below checks the public values the root passed on. Skipping the root's CPU keygen and
        // verify here lets compress start right after the tree. What dev mode gives up: a parent
        // circuit takes its child's key as witnessed, so nothing then checks the root against an
        // honestly keygen'd key, the check that catches a GPU root program built with the wrong
        // parameters; `MLE_VERIFY=1` keeps it.
        let accept_root = verify || compress.is_none();
        let t_verify = Instant::now();
        if accept_root {
            let early = early_root.as_ref().and_then(EarlyRootKeygen::take);
            let keygen_here = early.is_none();
            let mut cpu_combine = match early {
                // A keygen that panicked panics here, as it would have inside acceptance.
                Some(handle) => match handle.join() {
                    Ok(machine) => machine,
                    Err(panic) => std::panic::resume_unwind(panic),
                },
                None => acceptance_machine(
                    riscv_vm_vk
                        .clone()
                        .expect("combine implies convert, which builds the exe identity"),
                    vk_map.as_ref(),
                ),
            };
            let waited = t_verify.elapsed();
            if keygen_here {
                info!("MLE root keygen: start (in acceptance)");
            }
            let shapes_before = cpu_combine.num_distinct_shapes();
            cpu_combine
                .register_shape(&root.child_layouts, /* is_complete = */ true)
                .unwrap_or_else(|e| panic!("{e}"));
            if keygen_here {
                info!(
                    "MLE root keygen: done in {:.3}s (in acceptance)",
                    (t_verify.elapsed() - waited).as_secs_f64()
                );
            }
            // `verify` takes the honest key from any complete shape the machine holds; an early
            // machine keygen'd from other layouts than the root's would show up here as a second one.
            assert_eq!(
                cpu_combine.num_distinct_shapes(),
                1,
                "root acceptance's machine holds a shape besides this root's"
            );
            let how = match (keygen_here, &early_root) {
                (false, _) => format!(
                    "keygen'd under the root's prove, {:.3}s waited for it",
                    waited.as_secs_f64()
                ),
                (true, None) => "keygen'd here (MLE_ROOT_EARLY_KEYGEN=0)".to_string(),
                (true, Some(_)) => "keygen'd here: no early keygen was started".to_string(),
            };
            info!(
                "MLE root acceptance: root-shape keygens={} in acceptance | {how}",
                cpu_combine.num_distinct_shapes() - shapes_before,
            );
            cpu_combine
                .verify(&root.proof)
                .expect("combine ROOT proof failed host-side acceptance");
            // Whitelist mode: the standalone apex re-accepts the root from artifacts only, against
            // the deployment's pinned root (`MLE_VK_ROOT`, else the artifact's own).
            if let Some(apex) = &apex {
                apex.verify(&root.proof)
                    .expect("standalone apex verify failed");
                info!("standalone apex verify ✓");
            }
        }
        // Asserted before the success line so a miscount cannot be preceded by a ✓.
        //
        // Per-machine under two-machine, for the same reason as the count above: the tree is one
        // tree but its nodes are shared out, so this machine proving fewer than `chunk_count - 1`
        // is the expected case, not a miscount. The root is the whole tree's root regardless —
        // that is what its acceptance checks, here or, when it is left to the compress proof, in
        // the compress circuit.
        // The chunks' tree has `chunk_count - 1` nodes, and the root joins it with the prefix.
        if mle_two_machine_requested() {
            assert!(
                nodes <= chunk_count,
                "combine nodes proved ({nodes}) exceeds the {chunk_count} a {chunk_count}-leaf \
                 tree has with its root"
            );
        } else {
            assert_eq!(
                nodes,
                chunk_count,
                "the chunks' tree over {chunk_count} leaves has {} nodes and the root joins it \
                 with the prefix, but {nodes} were proved",
                chunk_count - 1
            );
        }
        let root_note = if accept_root {
            "root proved + verified ✓"
        } else {
            "root proved (acceptance left to the compress proof; set MLE_VERIFY=1 to run it here)"
        };
        info!(
            "MLE combine complete: {nodes} node(s) (n expected for {chunk_count} chunks: n-1 and \
             the root's join with the prefix), \
             {root_note} | sum(combine)={:.3}s | verify={:.3}s",
            combine_total.as_secs_f64(),
            t_verify.elapsed().as_secs_f64(),
        );
        // What this run actually produced, in wire bytes, attributed per protocol part. Shared
        // with the CPU e2e example so the field list exists in one place; the number is
        // shape-dependent, so the CPU example's fib figure does not stand in for this one.
        pico_vm::mle::machine::recursion::log_proof_size("MLE combine root", &root.proof.0);

        // Package the root for whoever has to verify it elsewhere. Built here rather than at the
        // end of the function because `root` is moved-from by then, and built only on this side of
        // `verify` above so that what we hand out is what we ourselves accepted. A root left to the
        // compress proof was not accepted here, so it is not exported; nothing is lost, as its two
        // consumers, ethproofs and `pico-prover`'s GPU entry (`embed`), run the combine step (the
        // ethproofs launcher refuses any other step).
        // Whitelist mode ships the root's vk with the proof (see `RootProofExport::root_vk`).
        if accept_root {
            let root_vk = vk_map
                .as_ref()
                .map(|_| bincode::serialize(&*root.proof.1))
                .transpose();
            match (
                pico_vm::mle::machine::recursion::proof_wire_bytes(&root.proof.0),
                root_vk,
            ) {
                (Ok(bytes), Ok(root_vk)) => {
                    root_export = Some(RootProofExport {
                        proof: bytes,
                        child_layouts: root.child_layouts.clone(),
                        riscv_vk_digest: riscv_vm_vk
                            .as_ref()
                            .expect("combine implies convert, which builds the exe identity")
                            .digest_hex(),
                        root_vk,
                    });
                }
                // A run that has already produced a verified root must not die because the export
                // failed; the caller sees `root: None` and reports the block as unproved.
                (Err(e), _) => {
                    tracing::warn!("MLE combine root: wire encode failed, not exported: {e:?}")
                }
                (_, Err(e)) => {
                    tracing::warn!("MLE combine root: vk encode failed, not exported: {e:?}")
                }
            }
        }

        // Shape summary: the sentinel for tree-shape jitter. The tree shape is a function of the
        // order convert proofs arrive in, and it decides which `(child layouts, is_complete)`
        // combinations occur — hence how many (expensive) keygens the run pays. That swing hides
        // inside the end-to-end figure, so it needs its own line. Counts and format both come
        // from `ShapeStats` so they cannot drift from what the machine actually recorded. One
        // line per card — each machine records only the nodes it proved.
        // Differenced against the block-start baseline, not read raw: the machines are resident, so
        // the raw figures are cumulative over every block this process has proved while `nodes` is
        // this block's alone. See `shape_baseline`.
        let mut shape_nodes = 0usize;
        let (mut blk_keygens, mut blk_hits, mut blk_evictions) = (0usize, 0usize, 0usize);
        for (card, machine) in combines.iter().enumerate() {
            let shapes = machine.shape_stats();
            let (base_k, base_h, base_e) = shape_baseline[card];
            let (dk, dh, de) = (
                shapes.keygens - base_k,
                shapes.hits - base_h,
                shapes.evictions - base_e,
            );
            shape_nodes += dk + dh;
            blk_keygens += dk;
            blk_hits += dh;
            blk_evictions += de;
            info!(
                target: "bench",
                "[bench] MLE combine shapes (card {card}): this block keygens={dk} hits={dh} \
                 evictions={de} | resident total {shapes}"
            );
        }
        info!(
            target: "bench",
            "[bench] MLE combine shapes: block keygens={blk_keygens} hits={blk_hits} evictions={blk_evictions}"
        );
        assert_eq!(
            shape_nodes,
            nodes + prefix_reduction_nodes.load(Ordering::SeqCst),
            "every node, the tree's and the prefix stage's own, either keygens a shape or hits \
             a cached one"
        );
        // The whole block, not just `verify`: when the root is accepted here, the root shape's CPU
        // keygen inside `register_shape`, the slot take and the two summary lines are on the same
        // thread and outside the window just as much. `t_verify` stays what the `verify=` field has
        // always meant.
        root_accept = t_accept.elapsed();

        // `--step compress`: re-prove the root at the compress preset on card 0 (the main thread's
        // card; every lane has joined), then accept the compress proof on the CPU machine, which
        // keygens the layout's key itself rather than trusting the prover's, and in whitelist mode
        // on the standalone apex. It is the final proof, so it is accepted whatever `MLE_VERIFY`
        // says. Reported on its own line, outside `e2e=` and `root-accept=`: the headline's fields
        // are parsed by position. `e2e-compress=` runs from the start of `e2e=` to the compress
        // proof: `e2e=`, then `root-accept=`, then the compress prove, without its acceptance.
        if let Some((gpu_compress, cpu_compress)) = &compress {
            let t_compress = Instant::now();
            let proved = gpu_compress
                .prove(&root.proof)
                .expect("compress prove failed");
            let e2e_compress = t_e2e.elapsed();
            let t_compress_verify = Instant::now();
            let mut cpu_compress = cpu_compress
                .lock()
                .expect("compress machine mutex poisoned");
            cpu_compress
                .preregister(&proved.root_layout)
                .unwrap_or_else(|e| panic!("{e}"));
            cpu_compress
                .verify(&proved.proof)
                .expect("compress proof failed host-side acceptance");
            // Whitelist mode: the standalone apex. `CompressMachine::verify` leaves the compress
            // key's membership to it (the whitelist's last leaf). A member key is a
            // whitelisted compress circuit, which re-checks the root's key under the whitelist root
            // `vk_root`; the apex then pins `vk_root` to the trusted root.
            if let Some(apex) = &apex {
                apex.verify_compress(&proved.proof)
                    .expect("standalone apex verify of the compress proof failed");
                info!("standalone apex verify (compress) ✓");
                // Exported only here: in whitelist mode, and once both acceptances above have
                // passed. Without a whitelist nothing outside this process could verify it.
                match compress_wire_bytes(&proved.proof) {
                    Ok(bytes) => {
                        compress_export = Some(CompressProofExport {
                            proof: bytes,
                            riscv_vk_digest: riscv_vm_vk
                                .as_ref()
                                .expect("compress implies convert, which builds the exe identity")
                                .digest_hex(),
                        });
                    }
                    // As for the root: a proof that verified must not take the process down
                    // because its export failed; the caller sees `compress: None`.
                    Err(e) => {
                        tracing::warn!("MLE compress: wire encode failed, not exported: {e}")
                    }
                }
            }
            info!(
                target: "bench",
                "MLE compress: proved + verified ✓ | total={:.3}s | keygen={:.3}s setup={:.3}s \
                 tracegen={:.3}s prove={:.3}s | verify={:.3}s | e2e-compress={:.3}s",
                t_compress.elapsed().as_secs_f64(),
                proved.keygen_ms as f64 / 1000.0,
                proved.setup_ms as f64 / 1000.0,
                proved.tracegen_ms as f64 / 1000.0,
                proved.prove_ms as f64 / 1000.0,
                t_compress_verify.elapsed().as_secs_f64(),
                e2e_compress.as_secs_f64(),
            );
            pico_vm::mle::machine::recursion::log_proof_size("MLE compress", &proved.proof.0);
        }
    }

    // --- Benchmark report (throughput + end-to-end). ---
    let n = prove_count.load(Ordering::SeqCst);
    let sum_prove = Duration::from_nanos(prove_nanos.load(Ordering::SeqCst));
    let avg = sum_prove.as_secs_f64() / (n.max(1) as f64);
    let total = t_total.elapsed();
    let verified_note = if verify {
        "proved + per-chunk verified"
    } else {
        "proved (per-chunk verify skipped; set MLE_VERIFY=1 to enable)"
    };
    // With a tree the root asserts that the global LogUp's sum is zero, and the root (or the
    // compress proof over it) was accepted above; without one nothing of this run checks the
    // chunks against each other, and a two-machine secondary's tree has its root on the
    // primary. The bench scripts count this line's last clause (`bench-arm.sh`, `sweep-csv.py`).
    let cross_chunk = if !with_combine || is_mle_secondary() {
        ""
    } else if verify || !with_compress || vk_on {
        "; cross-chunk global LogUp sum == 0 ✓"
    } else {
        // Dev mode with a compress stage and `MLE_VERIFY` off: the root was not held to an
        // honestly keygen'd key (`accept_root`), so the statement rests on the root program
        // this run built, as verified by the compress proof.
        "; cross-chunk global LogUp sum == 0 ✓ (asserted by the root this run built, under the \
         compress proof; MLE_VERIFY=1 holds the root to its key)"
    };
    info!("MLE single-node: all {n} chunk(s) {verified_note}{cross_chunk}");
    info!(
        // `e2e` excludes setup and root acceptance; `total` is the whole process. Keep each variable
        // named for the field it prints — the pair these replaced denoted each other's meaning.
        // `bench-scripts/sweep-csv.py` matches this line whole, so a field added or moved here
        // empties every timing column it extracts — on rows that still read rc=0.
        "MLE bench: chunks={n} prover_count={prover_count} lanes={lanes_per_card} | sum(prove)={:.3}s avg/chunk={:.3}s | prove(wall)={:.3}s | keygen={:.3}s | emulate={:.3}s cycles={emulated_cycles} prepare={:.3}s | e2e={:.3}s | root-accept={:.3}s | total={:.3}s",
        sum_prove.as_secs_f64(),
        avg,
        prove_wall.as_secs_f64(),
        keygen_wall.as_secs_f64(),
        emulate_wall.as_secs_f64(),
        prepare_wall.as_secs_f64(),
        e2e_wall.as_secs_f64(),
        root_accept.as_secs_f64(),
        total.as_secs_f64(),
    );
    // Where that window went, lane by lane — on its own lines, since the headline's field names are
    // what the harness extracts. The combine keygen total rides along to be cross-checked.
    #[cfg(feature = "cuda")]
    let combine_keygen_ms = (!combines.is_empty()).then(|| {
        combines
            .iter()
            .map(|m| m.shape_stats().keygen_total_ms)
            .sum::<u128>()
    });
    #[cfg(not(feature = "cuda"))]
    let combine_keygen_ms: Option<u128> = None;
    report_spans(e2e_wall, combine_keygen_ms, iteration);

    // Its own line rather than a field on the headline, whose field names benchmarks parse.
    // Absent in single-node: printing `0 MiB` there would invite comparing it against a
    // two-machine run's real figure as though the two measured the same thing.
    if let Some(line) = crate::common::transfer_stats::summary_line() {
        info!(target: "bench", "{line}");
    }
    vram_probe("exit", iteration.unwrap_or(0), prover_count);
    if let Some(slots) = take_occupancy() {
        info!(
            target: "bench",
            "[record-slots] this run: at most {} of {} history slots held at once, {} of {} takes \
             waited, {:.3}s in all | memory pool: {} memories made so far, pool size {}",
            slots.max_in_use,
            slots.slots,
            slots.blocked_takes,
            slots.takes,
            slots.blocked.as_secs_f64(),
            memories_made(),
            memory_pool_size(),
        );
    }

    BlockOutcome {
        cycles: emulated_cycles,
        e2e_wall,
        root_accept,
        root: root_export,
        compress: compress_export,
        committed,
        guest_failure: None,
        stage_failure: None,
    }
}

/// The strip's label column, shared with the report layer via the strip's own header line so the two
/// cannot drift apart.
const STRIP_LABEL_WIDTH: usize = 14;

/// Emit the span-derived report, and the raw spans when `MLE_SPANS` names a path.
///
/// `window` is what every share is taken against — the headline's `e2e=`, which excludes setup.
/// `combine_keygen_ms` is the combine machines' own figure, cross-checked below against the spans'.
/// `iteration` names the `MLE_REPEAT` pass in the exported CSV's file name, and is `None` for a
/// single run, which keeps writing exactly the path it was given.
fn report_spans(window: Duration, combine_keygen_ms: Option<u128>, iteration: Option<usize>) {
    use pico_vm::mle::spans::report as rep;

    let recorded = spans::snapshot();
    if recorded.is_empty() {
        return; // nothing bound a lane: a CPU build, or a path that never reached the pipeline
    }
    let window_us = window.as_micros() as u64;

    // Validated before anything is derived from it. Every figure below is cross-lane, so a single
    // lane whose spans overlap leaves all of them untrustworthy rather than merely incomplete —
    // publishing the survivors would mean publishing plausible wrong numbers.
    let gaps = match spans::validate(&recorded) {
        Ok(g) => g,
        Err(v) => {
            tracing::warn!(
                "MLE spans: lane invariant violated ({v:?}) — per-lane figures withheld for this run"
            );
            return;
        }
    };

    let roles = rep::by_role(&recorded);
    for s in &roles {
        let occ = s
            .occ()
            .map(|o| format!("{:.1}%", o * 100.0))
            .unwrap_or_else(|| "n/a".into());
        // `idle` includes `wait`; the two are printed together because they are one quantity and its
        // contended part, and separating them into unrelated fields invites adding them up.
        info!(
            target: "bench",
            // `lane_time` is `occ`'s denominator and is not derivable from the other fields; it also
            // makes the lane's gap readable as `lane_time - busy - idle`.
            "MLE lane: {}x{} busy={:.3}s idle={:.3}s (wait={:.3}s) wall={:.3}s lane_time={:.3}s occ={occ}",
            s.role.as_str(),
            s.lanes,
            s.busy_us as f64 / 1e6,
            s.idle_us as f64 / 1e6,
            s.wait_us as f64 / 1e6,
            s.wall_us as f64 / 1e6,
            s.lane_time_us as f64 / 1e6,
        );
        if s.busy_by_work.len() > 1 {
            // The recursion lane, the emulate workers, and any preparer that took a keygen miss:
            // a pool taking several kinds of work in turn, where the split is the only way to see
            // one kind crowding out another (prove-convert against prove-combine; a batch's replay
            // against the recover before it; a keygen against the prepare it blocked).
            let parts: Vec<String> = s
                .busy_by_work
                .iter()
                .map(|(k, v)| format!("{k}={:.3}s", *v as f64 / 1e6))
                .collect();
            info!(target: "bench", "MLE lane: {} busy split: {}", s.role.as_str(), parts.join(" "));
        }
    }

    let gpu = rep::gpu_lane_figures(&recorded, window_us);
    let buckets: Vec<String> = (0..gpu.buckets.len())
        .map(|k| format!("k{k}={:.1}%", gpu.share(k) * 100.0))
        .collect();
    // Named for what it measures: lanes, not hardware. A lane counts as working while its thread is
    // inside GPU-related work, which is not the same as the device having kernels in flight.
    info!(
        target: "bench",
        "MLE gpu-lanes: dead={:.3}s ({:.1}% of window) concurrency {}",
        gpu.dead_us() as f64 / 1e6,
        gpu.share(0) * 100.0,
        buckets.join(" "),
    );

    // A fixed cell duration rather than window/N, so two runs' strips share a scale without either
    // having to know the other's window: identical cells mean columns correspond, and the shorter
    // run simply produces fewer of them, which is the difference made visible.
    let cell_ms = std::env::var("MLE_STRIP_CELL_MS")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(350)
        .max(1);
    let cell_us = cell_ms * 1000;
    // Rounded up, so the last cell exists even when it is only partly inside the window; a strip that
    // stopped short would understate exactly the tail this is meant to show.
    let cells = window_us.div_ceil(cell_us).max(1) as usize;
    // `label_width` is stated rather than left implicit: the report layer blanks the label column of
    // the second arm's rows to pair them up, and it should read the width from here instead of both
    // sides hardcoding the same number and drifting apart.
    info!(
        target: "bench",
        "MLE strip: 1 cell = {cell_ms} ms, {cells} cells, window {:.3}s, label_width={} · {}",
        window_us as f64 / 1e6,
        STRIP_LABEL_WIDTH,
        rep::LEGEND,
    );
    info!(
        target: "bench",
        "MLE strip: a cell spans about one prove, so the strip shows occupancy and the mix of work \
         over time — not individual proves, and not a change of a few percent"
    );
    for row in rep::strip(&recorded, cell_us, cells, window_us) {
        let occ = row
            .occ
            .map(|o| format!("{:>3.0}%", o * 100.0))
            .unwrap_or_else(|| "    ".into());
        info!(
            target: "bench",
            "MLE strip: {:<width$}{occ} {}",
            row.label,
            row.cells,
            width = STRIP_LABEL_WIDTH,
        );
    }

    // Two independent measurements of the combine keygen total: the keygen spans on the lanes
    // that ask a combine machine for a key, and what the combine machines report for themselves.
    // They should agree; a mismatch means a missed close or a keygen call site nobody bracketed,
    // and it has no other symptom. The lanes are the combine preparers, and the riscv prover
    // lanes where they reduce the global LogUp's nodes: the only keygen those lanes record as a
    // keygen span (a node machine's own keys are made there too, inside the node's piece).
    if let Some(reported_ms) = combine_keygen_ms {
        let from_spans_ms = (rep::keygen_us_on(&recorded, spans::Role::CombinePreparer)
            + rep::keygen_us_on(&recorded, spans::Role::Prove)) as f64
            / 1000.0;
        // The two clocks start one statement apart, so exact equality is not the claim. 5 % or 10 ms,
        // whichever is larger, is far below any real discrepancy and far above the framing cost.
        let tol = (reported_ms as f64 * 0.05).max(10.0);
        if (from_spans_ms - reported_ms as f64).abs() > tol {
            tracing::warn!(
                "MLE spans: combine keygen disagrees — {:.3}s from spans against {:.3}s reported by \
                 the machine; a keygen call site is unbracketed or a span was left open",
                from_spans_ms / 1000.0,
                reported_ms as f64 / 1000.0,
            );
        } else {
            info!(
                target: "bench",
                "MLE spans: combine keygen cross-check ok ({:.3}s spans vs {:.3}s reported)",
                from_spans_ms / 1000.0,
                reported_ms as f64 / 1000.0,
            );
        }
    }

    // Unaccounted time inside a lane's life means a blocking call nobody bracketed. Small totals are
    // the loop overhead between one span closing and the next opening.
    for (lane, gap, frac) in gaps.significant(&rep::lane_lifetimes(&recorded), 0.05) {
        tracing::warn!(
            "MLE spans: lane {lane} has {:.3}s ({:.1}%) of unbracketed time — a blocking call is \
             missing instrumentation",
            gap as f64 / 1e6,
            frac * 100.0,
        );
    }

    if let Ok(path) = std::env::var("MLE_SPANS") {
        let path = match iteration {
            Some(n) => spans::csv_path_for_iteration(&path, n),
            None => path,
        };
        match spans::export_csv(&path, &recorded) {
            Ok(_) => info!("MLE spans: {} span(s) written to {path}", recorded.len()),
            Err(e) => tracing::warn!("MLE spans: could not write {path}: {e}"),
        }
    }
}
