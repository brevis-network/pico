//! The `PicoProver` gRPC service RSP drives blocks through.
//!
//! Port, message size and compression all match what RSP's client sets, because RSP is not going to
//! change for us: `process_client` connects with zstd both ways and a 600 MB limit, and its
//! endpoint is whatever `WITNESS_GETAWAY_ENDPOINT` names -- 50051 by convention.

use crate::{
    common::{auth::AuthConfig, program::ProgramInput},
    io::stdins::build_stdin,
    mle::ethproofs::{store::ProvingResultStore, BlockRequest, MleEthProofsConfig},
    pico_prover_server::{PicoProver, PicoProverServer},
    ErrCode, ErrMsg, GetProveResultRequest, GetProveResultResponse, ProvingRequest,
    ProvingResponse,
};
use crossbeam::channel::Sender;
use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Instant,
};
use tonic::{
    codec::CompressionEncoding, service::interceptor::InterceptedService, Response, Status,
};
use tracing::{error, info, warn};

/// One block in flight at a time.
///
/// The pipeline owns every card, the memory pools and the scheduler singleton, so a second block
/// entering while one is proving would not run beside it -- it would corrupt it. Held from the
/// moment a request is accepted until the driver has STORED the result, so there is no window in
/// which RSP could be told "ready for the next block" before the previous one is answerable.
static REQUEST_SLOT_ACTIVE: AtomicBool = AtomicBool::new(false);

/// Called by the driver once a block's result is in the store.
pub fn release_request_slot() {
    REQUEST_SLOT_ACTIVE.store(false, Ordering::SeqCst);
}

struct ProverService {
    jobs: Sender<BlockRequest>,
    results: Arc<ProvingResultStore>,
}

#[tonic::async_trait]
impl PicoProver for ProverService {
    async fn check_health(&self, _request: tonic::Request<()>) -> Result<Response<()>, Status> {
        Ok(Response::new(()))
    }

    async fn request_prover(
        &self,
        request: tonic::Request<ProvingRequest>,
    ) -> Result<Response<ProvingResponse>, Status> {
        let request = request.into_inner();
        let block = request.block_number;

        // The reported `proving_duration` starts HERE, not where the pipeline starts. This is the
        // only boundary a verifier can hold us to: everything after it -- decoding the witness,
        // per-block keygen, emulation, proving, host-side root acceptance -- is work we do because
        // RSP asked, and excluding any of it would report a number nobody outside could reproduce.
        let received_at = Instant::now();

        if REQUEST_SLOT_ACTIVE
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            // ⚠️ RSP does not read this field (`process_client` discards the response), so from its
            // side a rejection is indistinguishable from acceptance and it will poll for a proof
            // that was never started. Logged loudly here because our log is the only place it
            // shows up. At the production cadence -- one block per ~20 minutes -- this should
            // never fire; if it does, proving is running longer than the block interval.
            warn!("rejecting block {block}: another block is still in flight");
            return Ok(Response::new(ProvingResponse {
                err: Some(ErrMsg {
                    code: ErrCode::Internal as i32,
                    msg: format!("another block is in flight; rejected block {block}"),
                }),
            }));
        }

        let input = ProgramInput::from(request);
        let stdin = match build_stdin(&input) {
            Ok((_block, stdin)) => stdin,
            Err(e) => {
                // Validate before committing the slot to a block we cannot prove: a malformed
                // witness should cost one rejected request, not a wedged prover.
                release_request_slot();
                error!("block {block}: could not build stdin from the request: {e:?}");
                return Ok(Response::new(ProvingResponse {
                    err: Some(ErrMsg {
                        code: ErrCode::Internal as i32,
                        msg: format!("block {block}: malformed input: {e}"),
                    }),
                }));
            }
        };

        if let Err(e) = self.jobs.send(BlockRequest {
            block,
            received_at,
            stdin,
        }) {
            release_request_slot();
            error!("block {block}: the prover loop is gone: {e}");
            return Ok(Response::new(ProvingResponse {
                err: Some(ErrMsg {
                    code: ErrCode::Internal as i32,
                    msg: format!("block {block}: prover loop unavailable"),
                }),
            }));
        }

        info!("accepted block {block}");
        Ok(Response::new(ProvingResponse::default()))
    }

    async fn get_prove_result(
        &self,
        request: tonic::Request<GetProveResultRequest>,
    ) -> Result<Response<GetProveResultResponse>, Status> {
        let block = request.into_inner().block_number;
        // Idempotent read -- see the store's module docs for why this is not a `take`.
        let proof_info = self.results.get(block);
        Ok(Response::new(GetProveResultResponse {
            proof_info,
            ..Default::default()
        }))
    }
}

/// Bind the service and start serving on `runtime`.
///
/// Binding happens here rather than inside the spawned task on purpose: `serve()` reports a bind
/// failure as an opaque "transport error", which reads exactly like a mid-run transport fault. Held
/// separately, the real cause -- address in use, permission, bad address -- is named at the point
/// it happens, and the process refuses to start rather than looking healthy while answering
/// nothing.
pub fn serve(
    cfg: &MleEthProofsConfig,
    jobs: Sender<BlockRequest>,
    results: Arc<ProvingResultStore>,
    runtime: &tokio::runtime::Runtime,
) {
    let addr = cfg.grpc_addr;
    let max_msg = cfg.max_grpc_msg_size;
    let interceptor = cfg.server_auth_interceptor();

    let listener = runtime.block_on(async move {
        tokio::net::TcpListener::bind(addr)
            .await
            .unwrap_or_else(|e| {
                panic!(
                "could not bind the PicoProver port {addr}: {e}. Another prover (a FRI ethproofs \
                 node, or a previous run) may hold it -- set GRPC_ADDR to move."
            )
            })
    });
    info!("PicoProver gRPC listening on {addr} (max message {max_msg} bytes, zstd on)");

    runtime.spawn(async move {
        let service = InterceptedService::new(
            PicoProverServer::new(ProverService { jobs, results })
                .max_encoding_message_size(max_msg)
                .max_decoding_message_size(max_msg)
                .accept_compressed(CompressionEncoding::Zstd)
                .send_compressed(CompressionEncoding::Zstd),
            interceptor,
        );
        let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
        if let Err(e) = tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_incoming(incoming)
            .await
        {
            error!("PicoProver gRPC server stopped: {e} ({e:?})");
        }
    });
}
