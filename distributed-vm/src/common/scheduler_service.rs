//! Scheduler gRPC Service Implementation
//!
//! Server-side implementation of the global scheduler gRPC service.
//! Runs on Primary machine, handles task distribution to all workers.

use crate::{
    common::global_scheduler::{AcquireResult, CombineTask, GlobalScheduler, SchedulerTask},
    gateway::handler::proof_tree::IndexedProof,
    scheduler_server::{Scheduler, SchedulerServer},
    AcquireTaskRequest, AcquireTaskResponse, CheckCompleteResponse, ChunkProofTask,
    CombineProofTask, CompleteTask, RegisterChunkRequest, ReportGcsDigestRequest,
    ReportProofRequest, ReportProofResponse, WaitForNextBlockInputResponse, WaitTask,
};
use anyhow::Result;
use once_cell::sync::Lazy;
use serde::{de::DeserializeOwned, Serialize};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use tonic::{Request, Response, Status};
use tracing::{error, info};

/// What the scheduler services carry. `GlobalScheduler<P>` has always been payload-generic
/// (`global_scheduler.rs:82`); only these transport layers were pinned to `MetaProof<SC>`, which is
/// why MLE's `ProofWithVk` could not be served by them. Named as one trait alias rather than
/// repeated as a four-line `where` on every item.
pub trait SchedulerPayload: Clone + Send + Sync + Serialize + DeserializeOwned + 'static {}
impl<T: Clone + Send + Sync + Serialize + DeserializeOwned + 'static> SchedulerPayload for T {}

/// Compile-time guard that these services are genuinely payload-generic, rather than `MetaProof`
/// with extra steps: instantiating them at a payload that is not a `MetaProof` must type-check.
/// The MLE scheduler server depends on exactly this, so it is asserted in the library — CI lints
/// `--lib`, while the
/// test jobs are currently configured to skip.
#[allow(dead_code)]
fn _assert_scheduler_service_is_payload_generic() {
    #[derive(Clone, Serialize, serde::Deserialize)]
    struct NotAMetaProof(Vec<u8>);

    let _: SchedulerServer<SchedulerService<NotAMetaProof>> =
        create_scheduler_server(Arc::new(GlobalScheduler::<NotAMetaProof>::new()));
}

// === Block Input Watch Channel (for ethproofs two-machine stdin forwarding) ===

/// Watch channel for notifying Secondary when new block input is stored.
/// Sender is held globally; receiver is cloned per `wait_for_next_block_input` call.
// allow: domain-complex signature — tuple reflects prover data-flow structure
#[allow(clippy::type_complexity)]
static BLOCK_INPUT_WATCH: Lazy<(
    tokio::sync::watch::Sender<Option<(u64, Vec<u8>)>>,
    tokio::sync::watch::Receiver<Option<(u64, Vec<u8>)>>,
)> = Lazy::new(|| tokio::sync::watch::channel(None));

/// Tracks the last block number successfully returned by `wait_for_next_block_input`.
/// Prevents the race condition where Primary stores block input *before* Secondary's
/// gRPC call arrives, which would cause `borrow_and_update()` to skip the data.
static LAST_SERVED_BLOCK: AtomicU64 = AtomicU64::new(0);

/// Store block input bytes (called by Primary's ethproofs scheduler when RSP sends input).
/// Notifies any waiting `WaitForNextBlockInput` RPCs via the watch channel.
pub fn store_block_input(block_number: u64, input_data: Vec<u8>) {
    let len = input_data.len();
    info!(
        "[BlockInputStore] Stored input for block {} ({} bytes), notifying watchers",
        block_number, len
    );
    // Notify any waiting Secondary via watch channel
    let _ = BLOCK_INPUT_WATCH.0.send(Some((block_number, input_data)));
}

/// Global scheduler service for gRPC
// The bound is on the struct because the field demands it: `GlobalScheduler<P>` is declared
// `P: Clone + Send + Sync` (`global_scheduler.rs:82`).
pub struct SchedulerService<P: SchedulerPayload> {
    scheduler: Arc<GlobalScheduler<P>>,
}

impl<P: SchedulerPayload> SchedulerService<P> {
    pub fn new(scheduler: Arc<GlobalScheduler<P>>) -> Self {
        Self { scheduler }
    }

    /// Serialize a combine task for gRPC transmission
    #[allow(dead_code)]
    // retained for upcoming gRPC CombineTask distribution path
    // allow: tonic RPC contract requires Result<_, Status>; boxing here would
    // force every caller to unbox before propagating into the handler signature.
    #[allow(clippy::result_large_err)]
    fn serialize_combine_task(&self, task: &CombineTask<P>) -> Result<CombineProofTask, Status> {
        let left_data = bincode::serialize(&*task.left.inner)
            .map_err(|e| Status::internal(format!("Failed to serialize left proof: {}", e)))?;
        let right_data = bincode::serialize(&*task.right.inner)
            .map_err(|e| Status::internal(format!("Failed to serialize right proof: {}", e)))?;

        Ok(CombineProofTask {
            left_proof_data: left_data,
            left_start: task.left.start_chunk as u64,
            left_end: task.left.end_chunk as u64,
            right_proof_data: right_data,
            right_start: task.right.start_chunk as u64,
            right_end: task.right.end_chunk as u64,
        })
    }
}

#[tonic::async_trait]
impl<P: SchedulerPayload> Scheduler for SchedulerService<P> {
    async fn acquire_task(
        &self,
        request: Request<AcquireTaskRequest>,
    ) -> Result<Response<AcquireTaskResponse>, Status> {
        let req = request.into_inner();
        let worker_id = &req.worker_id;
        let block_num = req.block_num;

        // First contact from the peer machine. A worker only polls once its own pipeline is up, so
        // this is the earliest honest "my half is ready" signal, and it needs no new RPC.
        // `mle::wait_for_peer_ready` blocks the primary's pipeline on it — see there for why.
        if !worker_id.contains(&crate::common::machine_role::get_worker_label()) {
            crate::common::machine_role::note_peer_worker_ready();
        }

        // Check if this block is already complete (for Secondary querying after Primary reset)
        if block_num > 0 && self.scheduler.is_complete_for_block(block_num) {
            info!(
                "Scheduler: block {} already complete, returning Complete to worker {}",
                block_num, worker_id
            );
            return Ok(Response::new(AcquireTaskResponse {
                task: Some(crate::acquire_task_response::Task::CompleteTask(
                    CompleteTask {},
                )),
                proven_chunks: vec![],
            }));
        }

        // Check if worker is requesting a future block (Primary hasn't reset/started it yet)
        // TODO: cross blocks
        let current_block = self.scheduler.get_block_num();
        if block_num != current_block {
            info!(
                "Scheduler: worker {} requested future block {} (current: {}), returning Wait",
                worker_id, block_num, current_block
            );
            return Ok(Response::new(AcquireTaskResponse {
                task: Some(crate::acquire_task_response::Task::WaitTask(WaitTask {})),
                proven_chunks: vec![],
            }));
        }

        // Check completion first
        if self.scheduler.is_complete() {
            return Ok(Response::new(AcquireTaskResponse {
                task: Some(crate::acquire_task_response::Task::CompleteTask(
                    CompleteTask {},
                )),
                proven_chunks: vec![],
            }));
        }

        // Use async acquire with long-polling - blocks until task is available (up to 300s)
        let result = self.scheduler.acquire_task_async(worker_id).await;

        let proven_chunks: Vec<u64> = self
            .scheduler
            .get_proven_chunks()
            .into_iter()
            .map(|c| c as u64)
            .collect();

        let response = match result {
            AcquireResult::Task(task) => match task {
                SchedulerTask::ChunkProof { chunk_idx } => AcquireTaskResponse {
                    task: Some(crate::acquire_task_response::Task::ChunkTask(
                        ChunkProofTask {
                            chunk_idx: chunk_idx as u64,
                        },
                    )),
                    proven_chunks: proven_chunks.clone(),
                },
                SchedulerTask::Combine(combine) => {
                    // Always send data to Secondary
                    let (left_data, right_data) = (
                        bincode::serialize(&combine.left.inner).map_err(|e| {
                            Status::internal(format!("Failed to serialize left proof: {}", e))
                        })?,
                        bincode::serialize(&combine.right.inner).map_err(|e| {
                            Status::internal(format!("Failed to serialize right proof: {}", e))
                        })?,
                    );

                    crate::common::transfer_stats::record_out(
                        left_data.len() + right_data.len(),
                        2,
                    );
                    let combine_task = crate::CombineProofTask {
                        left_proof_data: left_data,
                        left_start: combine.left.start_chunk as u64,
                        left_end: combine.left.end_chunk as u64,
                        right_proof_data: right_data,
                        right_start: combine.right.start_chunk as u64,
                        right_end: combine.right.end_chunk as u64,
                    };
                    AcquireTaskResponse {
                        task: Some(crate::acquire_task_response::Task::CombineTask(
                            combine_task,
                        )),
                        proven_chunks: proven_chunks.clone(),
                    }
                }
            },
            AcquireResult::Complete => AcquireTaskResponse {
                task: Some(crate::acquire_task_response::Task::CompleteTask(
                    CompleteTask {},
                )),
                proven_chunks,
            },
            // AcquireResult::WaitForMore => AcquireTaskResponse {
            //     task: Some(crate::acquire_task_response::Task::WaitTask(WaitTask {})),
            // },
            AcquireResult::WaitForMore => {
                panic!("should not happen, Secondary get WaitForMore")
            }
        };
        Ok(Response::new(response))
    }

    async fn report_proof(
        &self,
        request: Request<ReportProofRequest>,
    ) -> Result<Response<ReportProofResponse>, Status> {
        let req = request.into_inner();
        let worker_id = &req.worker_id;

        // Deserialize the proof
        // Server side of the same accounting, so the primary's log answers the bytes question too
        // rather than being blank because it never uses the client.
        crate::common::transfer_stats::record_in(req.proof_data.len(), 1);
        let proof: P = bincode::deserialize(&req.proof_data)
            .map_err(|e| Status::invalid_argument(format!("Failed to deserialize proof: {}", e)))?;

        let indexed_proof =
            IndexedProof::new(proof, req.start_chunk as usize, req.end_chunk as usize);

        // Report to scheduler - it hands a new combine task to a waiter or queues it internally
        let combine_task = self.scheduler.report_proof(indexed_proof, worker_id);

        if let Some(task) = combine_task {
            // GlobalScheduler::report_proof has already handed the task to a waiting worker, or
            // queued it if none was waiting (`dispatch_or_enqueue`).
            // Just log for observability
            if req.keep_local {
                tracing::info!(
                    "Worker {} reported proof, combine task generated (PREFERRED): [{}, {}]+[{}, {}]",
                    worker_id,
                    task.left.start_chunk, task.left.end_chunk,
                    task.right.start_chunk, task.right.end_chunk
                );
            } else {
                tracing::info!(
                    "Worker {} reported proof, combine task generated: [{}, {}]+[{}, {}]",
                    worker_id,
                    task.left.start_chunk,
                    task.left.end_chunk,
                    task.right.start_chunk,
                    task.right.end_chunk
                );
            }
        }

        let response = ReportProofResponse {};

        Ok(Response::new(response))
    }

    async fn register_chunk(
        &self,
        request: Request<RegisterChunkRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        self.scheduler.register_chunk(req.chunk_idx as usize);
        Ok(Response::new(()))
    }

    async fn finalize_emulation(&self, _request: Request<()>) -> Result<Response<()>, Status> {
        self.scheduler.finalize_emulation();
        Ok(Response::new(()))
    }

    async fn check_complete(
        &self,
        _request: Request<()>,
    ) -> Result<Response<CheckCompleteResponse>, Status> {
        let completed = self.scheduler.is_complete();
        let final_proof_data = if completed {
            if let Some(proof) = self.scheduler.final_proof() {
                bincode::serialize(&*proof).ok()
            } else {
                None
            }
        } else {
            None
        };

        Ok(Response::new(CheckCompleteResponse {
            completed,
            final_proof_data: final_proof_data.unwrap_or_default(),
            completed_block: self.scheduler.get_last_completed_block(),
        }))
    }

    /// Receive a machine's partial cross-chunk GCS digest and park it for the pipeline to reduce.
    ///
    /// The service does not interpret the bytes: only the caller knows the field type, and decoding
    /// it here would restate that layout in a second place.
    async fn report_gcs_digest(
        &self,
        request: Request<ReportGcsDigestRequest>,
    ) -> Result<Response<()>, Status> {
        let req = request.into_inner();
        crate::common::transfer_stats::record_in(req.digest.len(), 0);
        crate::common::gcs_digest::push_remote_digest(req.worker_id, req.digest);
        Ok(Response::new(()))
    }

    async fn wait_for_next_block_input(
        &self,
        _request: Request<()>,
    ) -> Result<Response<WaitForNextBlockInputResponse>, Status> {
        let mut rx = BLOCK_INPUT_WATCH.1.clone();

        loop {
            // Check current value: if it's a block we haven't served yet, return immediately.
            // This handles the race where Primary called store_block_input() BEFORE this
            // gRPC request arrived (borrow_and_update would otherwise skip it).
            {
                let current = rx.borrow_and_update();
                if let Some((block_number, ref input_data)) = *current {
                    let last = LAST_SERVED_BLOCK.load(Ordering::Acquire);
                    if block_number != last {
                        LAST_SERVED_BLOCK.store(block_number, Ordering::Release);
                        info!(
                            "[SchedulerService] WaitForNextBlockInput: returning block {} ({} bytes) [immediate]",
                            block_number,
                            input_data.len()
                        );
                        return Ok(Response::new(WaitForNextBlockInputResponse {
                            block_number,
                            input_data: input_data.clone(),
                        }));
                    }
                }
            }

            // Current value is old (already served); wait for the next store_block_input().
            rx.changed()
                .await
                .map_err(|_| Status::internal("Block input watch channel closed"))?;
        }
    }
}

/// Create the Scheduler gRPC server
pub fn create_scheduler_server<P: SchedulerPayload>(
    scheduler: Arc<GlobalScheduler<P>>,
) -> SchedulerServer<SchedulerService<P>> {
    SchedulerServer::new(SchedulerService::new(scheduler))
}

// === Client wrapper for workers ===

use crate::scheduler_client::SchedulerClient;
use tonic::transport::Channel;

/// Client wrapper for workers to interact with the scheduler
pub struct SchedulerClientWrapper<P> {
    client: SchedulerClient<Channel>,
    _phantom: std::marker::PhantomData<P>,
}

impl<P: SchedulerPayload> SchedulerClientWrapper<P> {
    /// Connect to the scheduler on Primary machine
    pub async fn connect(addr: &str) -> Result<Self> {
        info!("Connecting to scheduler at {}", addr);
        let endpoint = tonic::transport::Endpoint::from_shared(addr.to_string())?
            .tcp_keepalive(Some(std::time::Duration::from_secs(60)))
            .http2_keep_alive_interval(std::time::Duration::from_secs(30))
            .keep_alive_timeout(std::time::Duration::from_secs(20))
            .timeout(std::time::Duration::from_secs(360)); // > 300s long-polling timeout
        let channel = endpoint.connect().await?;
        let client = SchedulerClient::new(channel).max_decoding_message_size(256 * 1024 * 1024); // 256MB limit to prevent h2 protocol errors

        Ok(Self {
            client,
            _phantom: std::marker::PhantomData,
        })
    }

    /// Acquire a task from the scheduler
    /// Note: Uses &self and clones the tonic client internally to allow concurrent calls
    pub async fn acquire_task(
        &self,
        worker_id: &str,
        block_num: u64,
    ) -> Result<ClientAcquireResult<P>> {
        let request = AcquireTaskRequest {
            worker_id: worker_id.to_string(),
            block_num,
        };

        // Clone the client to allow concurrent calls without holding a lock
        let mut client = self.client.clone();
        let response = client.acquire_task(Request::new(request)).await?;
        let response = response.into_inner();

        match response.task {
            Some(crate::acquire_task_response::Task::ChunkTask(t)) => {
                let proven_chunks: Vec<usize> =
                    response.proven_chunks.iter().map(|&c| c as usize).collect();
                Ok(ClientAcquireResult::ChunkProof {
                    chunk_idx: t.chunk_idx as usize,
                    proven_chunks,
                })
            }
            Some(crate::acquire_task_response::Task::CombineTask(t)) => {
                // Inbound is counted separately: this machine sends convert proofs UP and receives
                // combine children back DOWN, and those are not the same size.
                crate::common::transfer_stats::record_in(
                    t.left_proof_data.len() + t.right_proof_data.len(),
                    usize::from(!t.left_proof_data.is_empty())
                        + usize::from(!t.right_proof_data.is_empty()),
                );
                let left_proof: Option<P> =
                    if t.left_proof_data.is_empty() {
                        None
                    } else {
                        Some(bincode::deserialize(&t.left_proof_data).map_err(|e| {
                            anyhow::anyhow!("Failed to deserialize left proof: {}", e)
                        })?)
                    };
                let right_proof: Option<P> =
                    if t.right_proof_data.is_empty() {
                        None
                    } else {
                        Some(bincode::deserialize(&t.right_proof_data).map_err(|e| {
                            anyhow::anyhow!("Failed to deserialize right proof: {}", e)
                        })?)
                    };

                let proven_chunks: Vec<usize> =
                    response.proven_chunks.iter().map(|&c| c as usize).collect();
                Ok(ClientAcquireResult::Combine {
                    left: left_proof
                        .map(|p| IndexedProof::new(p, t.left_start as usize, t.left_end as usize)),
                    right: right_proof.map(|p| {
                        IndexedProof::new(p, t.right_start as usize, t.right_end as usize)
                    }),
                    left_range: (t.left_start as usize, t.left_end as usize),
                    right_range: (t.right_start as usize, t.right_end as usize),
                    proven_chunks,
                })
            }
            // TODO: WaitTask should not happen
            Some(crate::acquire_task_response::Task::WaitTask(_)) => {
                Ok(ClientAcquireResult::WaitForMore)
            }
            Some(crate::acquire_task_response::Task::CompleteTask(_)) => {
                Ok(ClientAcquireResult::Complete)
            }
            None => {
                error!("Empty task response from scheduler");
                Ok(ClientAcquireResult::WaitForMore)
            }
        }
    }

    /// Async acquire task using long-polling - blocks until task is available
    /// This is the preferred method for the new async scheduler architecture
    /// The server uses long-polling, so this will block for up to 300s
    pub async fn acquire_task_async(
        &self,
        worker_id: &str,
        block_num: u64,
    ) -> Result<ClientAcquireResult<P>> {
        // Use block_num = 0 for async acquire (no block-specific checks)
        self.acquire_task(worker_id, block_num).await
    }

    /// Register a chunk with the scheduler
    /// Note: Uses &self and clones the tonic client internally to allow concurrent calls
    pub async fn register_chunk(&self, chunk_idx: usize) -> Result<()> {
        let request = RegisterChunkRequest {
            chunk_idx: chunk_idx as u64,
        };
        // Clone the client to allow concurrent calls
        let mut client = self.client.clone();
        let _ = client.register_chunk(Request::new(request)).await?;
        Ok(())
    }

    /// Send this machine's partial cross-chunk GCS digest to the primary.
    pub async fn report_gcs_digest(&self, worker_id: &str, digest: Vec<u8>) -> Result<()> {
        crate::common::transfer_stats::record_out(digest.len(), 0);
        let request = ReportGcsDigestRequest {
            digest,
            worker_id: worker_id.to_string(),
        };
        let mut client = self.client.clone();
        let _ = client.report_gcs_digest(Request::new(request)).await?;
        Ok(())
    }

    /// Report a proof to the scheduler
    /// Note: Uses &self and clones the tonic client internally to allow concurrent calls
    pub async fn report_proof(
        &self,
        worker_id: &str,
        proof: IndexedProof<P>,
        keep_local: bool,
    ) -> Result<()> {
        let proof_data = bincode::serialize(&*proof.inner)?;
        // Counted at the serialisation boundary -- the only place MLE moves a payload between
        // machines. Bytes-per-block are recorded because a run over loopback says nothing
        // about what a real link would cost.
        crate::common::transfer_stats::record_out(proof_data.len(), 1);
        let request = ReportProofRequest {
            worker_id: worker_id.to_string(),
            start_chunk: proof.start_chunk as u64,
            end_chunk: proof.end_chunk as u64,
            proof_data,
            keep_local,
        };

        // Clone the client to allow concurrent calls
        let mut client = self.client.clone();
        let _response = client.report_proof(Request::new(request)).await?;
        Ok(())
    }

    /// Check if all work is complete
    /// Note: Uses &self and clones the tonic client internally to allow concurrent calls
    pub async fn check_complete(&self) -> Result<(bool, Option<P>)> {
        // Clone the client to allow concurrent calls
        let mut client = self.client.clone();
        let response = client.check_complete(Request::new(())).await?;
        let response = response.into_inner();

        let proof = if response.completed && !response.final_proof_data.is_empty() {
            Some(bincode::deserialize(&response.final_proof_data)?)
        } else {
            None
        };

        Ok((response.completed, proof))
    }

    /// Wait for the next block input from Primary (blocking, zero-delay).
    /// Returns (block_number, stdin_bytes) as soon as Primary stores input.
    pub async fn wait_for_next_block_input(&self) -> Result<(u64, Vec<u8>)> {
        let mut client = self.client.clone();
        let response = client.wait_for_next_block_input(Request::new(())).await?;
        let resp = response.into_inner();
        Ok((resp.block_number, resp.input_data))
    }
}

/// Result type for client task acquisition
pub enum ClientAcquireResult<P> {
    ChunkProof {
        chunk_idx: usize,
        proven_chunks: Vec<usize>,
    },
    Combine {
        left: Option<IndexedProof<P>>,
        right: Option<IndexedProof<P>>,
        // Metadata to lookup if proofs are missing (used when data_omitted)
        left_range: (usize, usize),
        right_range: (usize, usize),
        proven_chunks: Vec<usize>,
    },
    WaitForMore,
    Complete,
}
