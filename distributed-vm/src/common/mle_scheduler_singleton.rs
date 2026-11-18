//! MLE's global scheduler singleton.
//!
//! Beside [`super::scheduler_singleton`]'s, not replacing it. `GlobalScheduler<P>` is payload-
//! generic and so are the gRPC services, but a `static` cannot be generic
//! without a type-keyed registry — so the singleton is the one layer that genuinely needs a second
//! instance. FRI's is at `MetaProof<KoalaBearPoseidon2>`; this one is at MLE's [`ProofWithVk`],
//! which is what cross-machine transfer carries (combine verifies *convert*
//! proofs, and riscv proofs never enter the scheduler).
//!
//! Why MLE needs to be here at all: its dispatcher used to hold a private `Arc<GlobalScheduler<_>>`,
//! so the scheduler a gRPC server would serve and the one MLE actually scheduled against were two
//! different objects, and a secondary connecting in would find no work.

use crate::{
    common::{
        global_logup_exchange::{ChainNews, ChunkTableReport},
        global_scheduler::{AcquireResult, CombineTask, GlobalScheduler, SchedulerTask},
        machine_role::{get_runtime_mode, RuntimeMode},
        scheduler_service::{ClientAcquireResult, ExchangeError, SchedulerClientWrapper},
    },
    gateway::handler::proof_tree::IndexedProof,
};
use once_cell::sync::Lazy;
use pico_vm::mle::machine::convert::ProofWithVk;
use std::sync::{Arc, OnceLock};

/// MLE's scheduler payload: a convert proof with the vk it verifies under.
pub type MleSchedulerProof = ProofWithVk;

static MLE_SCHEDULER: Lazy<Arc<GlobalScheduler<MleSchedulerProof>>> =
    Lazy::new(|| Arc::new(GlobalScheduler::new()));

/// The MLE scheduler instance. Same object for the dispatcher and for anything a gRPC server hands
/// out, which is the whole point.
pub fn get_mle_scheduler() -> Arc<GlobalScheduler<MleSchedulerProof>> {
    Arc::clone(&MLE_SCHEDULER)
}

/// Client for an MLE secondary to reach the primary's scheduler.
static MLE_SCHEDULER_CLIENT: OnceLock<Arc<SchedulerClientWrapper<MleSchedulerProof>>> =
    OnceLock::new();

pub fn get_mle_scheduler_client() -> Option<Arc<SchedulerClientWrapper<MleSchedulerProof>>> {
    MLE_SCHEDULER_CLIENT.get().map(Arc::clone)
}

/// Connect the MLE secondary's scheduler client.
pub async fn init_mle_scheduler_client(addr: &str) -> anyhow::Result<()> {
    let client = SchedulerClientWrapper::<MleSchedulerProof>::connect(addr).await?;
    MLE_SCHEDULER_CLIENT
        .set(Arc::new(client))
        .map_err(|_| anyhow::anyhow!("MLE scheduler client already initialised"))?;
    Ok(())
}

/// Runtime handle the secondary's blocking callers use to drive the gRPC client. MLE's pipeline
/// threads are plain OS threads, not tasks, so every remote call has to `block_on` something.
static MLE_TOKIO_HANDLE: OnceLock<tokio::runtime::Handle> = OnceLock::new();

pub fn set_mle_tokio_handle(handle: tokio::runtime::Handle) {
    let _ = MLE_TOKIO_HANDLE.set(handle);
}

pub fn is_mle_secondary() -> bool {
    matches!(get_runtime_mode(), RuntimeMode::TwoMachineSecondary)
}

/// The secondary's client and runtime, or a panic naming which half is missing. Both are set during
/// launch, so absence is a wiring bug rather than a race.
fn remote_client() -> Arc<SchedulerClientWrapper<MleSchedulerProof>> {
    get_mle_scheduler_client()
        .expect("MLE secondary has no scheduler client (init_mle_scheduler_client not called)")
}

/// Client plus a runtime handle, for the **synchronous** façade calls only.
///
/// Never reach for this inside an `async fn`. Those are already being driven by the dispatcher's
/// `block_on`, and blocking again within them panics with "Cannot start a runtime from within a
/// runtime" — which is exactly how the first two-machine run died. The async path awaits the
/// client directly instead.
fn remote() -> (
    Arc<SchedulerClientWrapper<MleSchedulerProof>>,
    tokio::runtime::Handle,
) {
    let client = remote_client();
    let handle = MLE_TOKIO_HANDLE
        .get()
        .cloned()
        .expect("MLE secondary has no tokio handle (set_mle_tokio_handle not called)");
    (client, handle)
}

// === Routing façade ===
//
// The pipeline calls these instead of touching a scheduler directly, so the local/remote split
// lives in one place rather than at every call site. Single-node and the primary run against the
// local singleton; the secondary goes over gRPC to the primary's.

/// Register a chunk discovered by emulation. **Primary only.**
///
/// The scheduler's chunk registry is global but the prepared-chunk store is per-process, and
/// registering is what makes a chunk acquirable. Both processes run a full emulator at
/// their own pace, so a secondary that registered would announce chunks the PRIMARY has not traced
/// yet — the primary's dispatcher would then acquire one and find its local store empty. That is
/// not hypothetical: it is how the first working two-machine run died, as
/// `prepared chunk missing for acquired task`.
///
/// De-duplication does not save this. `GlobalScheduler::register_chunk` does dedupe, so the second
/// registration is a no-op — but the FIRST one can still be the remote machine's, arriving before
/// the local emulator has produced the chunk. The invariant that matters is "registered implies
/// locally available", and only the machine that owns the run can uphold it.
///
/// So the primary alone registers, which is what the RPC's own comment has always said
/// ("Primary registers chunk during emulation (only called by Primary's emulator)") and mirrors
/// `mle_finalize_emulation` below. The secondary still emulates everything; it simply does not
/// announce. It receives its share through role partitioning of what the primary registered.
pub fn mle_register_chunk(chunk_idx: usize) {
    if !is_mle_secondary() {
        get_mle_scheduler().register_chunk(chunk_idx);
    }
}

/// [`mle_register_chunk`] with the chunk's estimated proving cost, for cost-ordered dispatch.
pub fn mle_register_chunk_with_cost(chunk_idx: usize, cost: u64) {
    if !is_mle_secondary() {
        get_mle_scheduler().register_chunk_with_cost(chunk_idx, cost);
    }
}

/// Emulation finished on THIS machine.
///
/// Local-only by design, and not forwarded: the flag means "no more chunks are coming", which is a
/// statement about the whole run. The secondary saying it would latch completion on the primary
/// while the primary's own emulator was still producing chunks. The primary owns the run, so the
/// primary owns the flag.
pub fn mle_finalize_emulation() {
    if !is_mle_secondary() {
        get_mle_scheduler().finalize_emulation();
    }
}

/// Ends the current block without a result, so its lanes drain and exit (see
/// `GlobalScheduler::abort`).
pub fn mle_abort_run() {
    get_mle_scheduler().abort();
}

/// Declare that this block's tree has a prefix (`GlobalScheduler::expect_prefix`): the global
/// LogUp's nodes, proved outside the chunk queue. The primary owns the tree.
pub fn mle_expect_prefix() {
    if !is_mle_secondary() {
        get_mle_scheduler().expect_prefix();
    }
}

/// Hand in the proof over the tree's prefix (`GlobalScheduler::report_prefix`).
pub fn mle_report_prefix(proof: MleSchedulerProof) {
    get_mle_scheduler().report_prefix(proof);
}

/// Report a finished convert proof into the proof tree.
pub fn mle_report_proof(proof: IndexedProof<MleSchedulerProof>, worker_id: &str) {
    if is_mle_secondary() {
        let (client, handle) = remote();
        let worker_id = worker_id.to_string();
        handle.block_on(async move {
            // `keep_local = false`: the primary owns the tree and needs the proof itself to pair it.
            if let Err(e) = client.report_proof(&worker_id, proof, false).await {
                tracing::error!("secondary failed to report proof: {e}");
            }
        });
    } else {
        get_mle_scheduler().report_proof(proof, worker_id);
    }
}

// === The global LogUp across the two machines (see `global_logup_exchange`) ===
//
// The secondary's side of the three messages. The primary's pipeline reads and fills the
// exchange directly: it is in the same process as the service.

/// How often a report to the primary is sent before it is given up, and the pause between two
/// sends. A report that is lost leaves the block's chain or its tree short for good, so a call
/// that fails on the transport is worth sending again.
const REPORT_ATTEMPTS: usize = 3;
const REPORT_PAUSE: std::time::Duration = std::time::Duration::from_secs(1);

/// Sends a report to the primary, again when the call fails. A refusal ends this machine's run
/// of the block: the primary is on another one.
async fn deliver<Fut>(what: &str, send: impl Fn() -> Fut)
where
    Fut: std::future::Future<Output = Result<(), ExchangeError>>,
{
    for attempt in 1..=REPORT_ATTEMPTS {
        match send().await {
            Ok(()) => return,
            Err(ExchangeError::OtherBlock(why)) => {
                tracing::error!("the primary refused {what}: {why}; this block's run is stopped");
                mle_abort_run();
                return;
            }
            Err(ExchangeError::Failed(why)) if attempt < REPORT_ATTEMPTS => {
                tracing::warn!("secondary failed to report {what} (attempt {attempt}): {why}");
                tokio::time::sleep(REPORT_PAUSE).await;
            }
            Err(ExchangeError::Failed(why)) => {
                tracing::error!("secondary failed to report {what}: {why}");
            }
        }
    }
}

/// Report the Global table commitment of a chunk this machine traced, with the chunk's share
/// of the block's real-row count. **Secondary only.** Does not wait for the primary: the caller
/// is a prover lane in the middle of the chunk's proof.
pub fn mle_report_chunk_table(report: ChunkTableReport) {
    let (client, handle) = remote();
    let block = get_mle_scheduler().get_block_num();
    handle.spawn(async move {
        let what = format!("chunk {}'s Global table commitment", report.chunk_idx);
        deliver(&what, || client.report_chunk_table(block, report.clone())).await;
    });
}

/// The commitments the primary holds from chunk `from_chunk` on, and the block's chunk count
/// once the primary knows it. **Secondary only.** Returns within the primary's poll time, with
/// nothing if nothing came.
pub fn mle_await_chunk_tables(from_chunk: usize) -> Result<ChainNews, ExchangeError> {
    let (client, handle) = remote();
    let block = get_mle_scheduler().get_block_num();
    handle.block_on(async move { client.await_chunk_tables(block, from_chunk).await })
}

/// Hand the primary the node over the group of `chunks` chunks from `first_chunk` on.
/// **Secondary only.**
pub fn mle_report_group_node(first_chunk: usize, chunks: usize, node: &MleSchedulerProof) {
    let (client, handle) = remote();
    let block = get_mle_scheduler().get_block_num();
    handle.block_on(async move {
        let what = format!(
            "the node over chunks {first_chunk}..{}",
            first_chunk + chunks
        );
        deliver(&what, || {
            client.report_group_node(block, first_chunk, chunks, node)
        })
        .await;
    });
}

/// Terminal report for the riscv-only / convert-only steps, which have no proof tree.
///
/// Local-only: those steps have no two-machine shape (the scheduler completes by count, and the
/// count belongs to whoever owns the run), and `--step combine` is what two-machine exists for.
pub fn mle_report_chunk_terminal(chunk_idx: usize) {
    if !is_mle_secondary() {
        get_mle_scheduler().report_chunk_terminal(chunk_idx);
    }
}

/// **Call once per `run_pipeline` iteration, before registering any chunk.**
///
/// The dispatcher used to build a fresh `GlobalScheduler` per run, so nothing had to be cleared.
/// A singleton outlives the run, and `MLE_REPEAT` calls `run_pipeline` N times in one process — so
/// without this, iteration 2 would inherit iteration 1's proof tree and completion state. That is
/// precisely the knob steady-state measurements use, so getting it wrong would corrupt
/// the measurements rather than fail loudly.
pub fn reset_mle_scheduler() {
    MLE_SCHEDULER.reset();
}

/// What the MLE dispatcher gets back. Mirrors `UnifiedAcquireResult` but carries MLE's payload, and
/// keeps `Combine` as the whole `CombineTask` rather than flattening it to two children — the
/// combine preparer consumes the task, so flattening here would only force it to be rebuilt.
pub enum MleAcquireResult {
    ChunkProof { chunk_idx: usize },
    Combine(CombineTask<MleSchedulerProof>),
    WaitForMore,
    Complete,
}

/// Acquire through the mode switch instead of off a private `Arc`, so the same call serves
/// single-node and (once MLE has a two-machine launch shape) a two-machine secondary.
///
/// `SingleNode` and `TwoMachinePrimary` are the local path and behave exactly as the previous
/// direct `acquire_task_async` did — single-node is unchanged.
/// Returns the task **and the chunks the scheduler already considers proven**.
///
/// The second half is not bookkeeping — it is what keeps a two-machine run alive. Each machine
/// emulates the whole block and stores every chunk's prepared record, but only proves its share,
/// and a record's slot goes back only when a worker finishes its chunk and drops the record. So the
/// records for chunks the OTHER machine proved are never dropped: the slots run out, the take
/// waits, emulation stalls, registration stops with it, and both machines sit idle until the
/// scheduler's 300s "system is broken" timeout. Measured on reth-239: stalled at 61 of 122 chunks
/// against `MLE_HISTORY_SLOTS=64`.
///
/// FRI avoids this by feeding the same list to `record_store::send_proven_chunks` on every acquire.
/// MLE keeps its prepared chunks in its own store, so the caller does the eviction; the list is
/// returned rather than acted on here so this stays a scheduling function.
pub async fn mle_acquire_task_unified_async(
    worker_id: &str,
    _block_num: u64,
) -> (MleAcquireResult, Vec<usize>) {
    match get_runtime_mode() {
        RuntimeMode::SingleNode | RuntimeMode::TwoMachinePrimary => {
            let scheduler = get_mle_scheduler();
            let acquired = match scheduler.acquire_task_async(worker_id).await {
                AcquireResult::Task(SchedulerTask::ChunkProof { chunk_idx }) => {
                    MleAcquireResult::ChunkProof { chunk_idx }
                }
                AcquireResult::Task(SchedulerTask::Combine(task)) => {
                    MleAcquireResult::Combine(task)
                }
                AcquireResult::WaitForMore => MleAcquireResult::WaitForMore,
                AcquireResult::Complete => MleAcquireResult::Complete,
            };
            (acquired, scheduler.get_proven_chunks())
        }
        RuntimeMode::TwoMachineSecondary => {
            // Awaited rather than `block_on`'d: this fn is async and the dispatcher already drives
            // it with `block_on`, so blocking again here panics with "Cannot start a runtime from
            // within a runtime". Only the sync façade calls need a handle.
            remote_client()
                .acquire_task(worker_id, _block_num)
                .await
                .map(|r| match r {
                    ClientAcquireResult::ChunkProof {
                        chunk_idx,
                        proven_chunks,
                    } => (MleAcquireResult::ChunkProof { chunk_idx }, proven_chunks),
                    ClientAcquireResult::Combine {
                        left,
                        right,
                        proven_chunks,
                        ..
                    } => (
                        match (left, right) {
                            (Some(left), Some(right)) => MleAcquireResult::Combine(CombineTask {
                                left,
                                right,
                                // Server-side affinity only; a task acquired over the wire is already
                                // this worker's.
                                preferred_worker: None,
                            }),
                            // `data_omitted`: the server sent ranges without payloads, expecting the
                            // caller to fetch them. MLE has no fetch path, so treat it as "nothing to
                            // do now" and poll again rather than fabricating an empty combine.
                            _ => MleAcquireResult::WaitForMore,
                        },
                        proven_chunks,
                    ),
                    ClientAcquireResult::WaitForMore => (MleAcquireResult::WaitForMore, Vec::new()),
                    ClientAcquireResult::Complete => (MleAcquireResult::Complete, Vec::new()),
                })
                .unwrap_or_else(|e| {
                    // A transport error is not "no work": returning Complete would retire the
                    // worker for the rest of the run. Back off and let the caller retry.
                    tracing::error!("secondary acquire failed: {e}");
                    (MleAcquireResult::WaitForMore, Vec::new())
                })
        }
    }
}
