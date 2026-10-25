//! EthProofs entry point for the MLE/WHIR single-node prover.
//!
//! RSP owns the block selection and the submission to ethproofs; this process owns exactly one
//! thing -- turning a witness into a verified combine root -- and exposes it over the
//! `PicoProver` gRPC service RSP already speaks. Nothing here talks HTTP to ethproofs, and nothing
//! here decides which block to prove.
//!
//! Shape:
//!
//! ```text
//!   RSP --RequestProver(block, witness)--> [server] --BlockRequest--> [this thread's loop]
//!                                                                          |
//!                                                                     mle::run_step
//!                                                                          |
//!   RSP <--GetProveResult(block)-------- [store] <----ProofInfo------------+
//! ```
//!
//! The loop runs on the calling thread and the gRPC service on a small tokio runtime beside it,
//! because the pipeline is blocking, spawns its own OS threads, and must not share a runtime with
//! anything that could starve it.

pub mod server;
pub mod store;
pub mod vk_bundle;

use crate::{
    common::auth::{AuthConfig, AuthMethod},
    impl_auth_config,
    mle::{config::MleSingleNodeConfig, BlockJob},
};
use clap::Parser;
use pico_vm::{compiler::riscv::program::Program, emulator::stdin::EmulatorStdin};
use std::{net::SocketAddr, sync::Arc, time::Instant};
use store::ProvingResultStore;
use tracing::{info, warn};

/// CLI / env config for the ethproofs MLE prover.
///
/// Everything about HOW a block is proved is [`MleSingleNodeConfig`], unchanged, so an operating
/// point tuned with `single_node_mle.sh` transfers here verbatim. Only the service surface is new.
#[derive(Parser, Debug, Clone)]
#[clap(about = "EthProofs single-node MLE/WHIR prover (KoalaBear)")]
pub struct MleEthProofsConfig {
    #[clap(flatten)]
    pub node: MleSingleNodeConfig,

    /// Where RSP connects (its `WITNESS_GETAWAY_ENDPOINT`). 50051 by convention, which is what the
    /// FRI ethproofs node used -- keeping it means RSP needs no change to point here.
    #[clap(long, env = "GRPC_ADDR", default_value = "0.0.0.0:50051")]
    pub grpc_addr: SocketAddr,

    /// `none` (the default, and what RSP sends) or `bearer`.
    #[clap(long, env = "AUTH_METHOD", default_value = "none", value_enum)]
    pub auth_method: AuthMethod,

    #[clap(long, env = "BEARER_TOKEN", requires = "auth_method")]
    pub bearer_token: Option<String>,

    /// Matches the 600 MB RSP's own client sets on both directions; a smaller value here would
    /// reject the witnesses it sends rather than negotiate down.
    #[clap(long, env = "MAX_GRPC_MSG_SIZE", default_value = "629145600")]
    pub max_grpc_msg_size: usize,
}

impl_auth_config!(MleEthProofsConfig);

/// One accepted block, handed from the gRPC service to the proving loop.
pub struct BlockRequest {
    pub block: u64,
    /// When `RequestProver` was received -- the start of the reported `proving_duration`.
    pub received_at: Instant,
    pub stdin: EmulatorStdin<Program, Vec<u8>>,
}

/// How many tokio workers the service gets.
///
/// Deliberately tiny. `new_multi_thread()` defaults to one worker per core (240 on these boxes),
/// and this process also runs an emulator and rayon's core-sized pool; an active runtime that size
/// measurably wrecks both through crossbeam-epoch reclamation, which scales with the number of
/// registered participants. The service awaits a channel send and a map lookup -- it is not CPU
/// work. (Same reasoning, same default, as the two-machine runtime.)
fn runtime_threads() -> usize {
    std::env::var("MLE_RT_THREADS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|&n| n >= 1)
        .unwrap_or(2)
}

/// Which block the prewarm run proves.
///
/// 188 is the alias for 18884864, the smallest reth fixture committed to the tree -- a real
/// mainnet block, small enough (30 transactions, 10 chunks) that warming up costs seconds rather
/// than a full production block's worth.
fn prewarm_block() -> u32 {
    std::env::var("MLE_ETHPROOFS_PREWARM_BLOCK")
        .ok()
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(188)
}

fn prewarm_enabled() -> bool {
    !matches!(
        std::env::var("MLE_ETHPROOFS_PREWARM").as_deref(),
        Ok("0") | Ok("false") | Ok("no")
    )
}

/// Prove one local fixture BEFORE the gRPC port opens.
///
/// The process's one-time setup -- program compile, per-card keygen, nvrtc JIT, pinned pools --
/// happens lazily on the first block proved, and `proving_duration` is measured from the gRPC
/// boundary because that is the only window a verifier can hold us to. Without this, the first
/// block after every restart reports that setup as though it were proving time: measured at
/// 66.6 s reported against 5.2 s of actual work.
///
/// That is not a one-off curiosity. With `Restart=always` in front of this process, every restart
/// donates one block far above the ten-second line -- on a leaderboard whose headline metric is
/// the FRACTION of blocks under ten seconds, and at one block per twelve seconds a restart during
/// a bad hour can cost several. Paying the cost here moves it outside every measured window
/// instead of hiding it inside the first one.
///
/// Ordering matters as much as the warming: this runs before `server::serve`, so the port does not
/// exist until the prover is hot. RSP's unit waits on that port, which makes the two agree without
/// either side knowing about the other.
///
/// A failure here is FATAL on purpose. It doubles as a startup self-test, and a prover that cannot
/// prove the fixture it ships with will not prove RSP's blocks either -- better to find out now
/// than to accept a block and fail holding it, which from RSP's side is an unanswerable poll.
fn prewarm(cfg: &MleEthProofsConfig) {
    let block = prewarm_block();
    let started = Instant::now();
    info!("prewarm: proving fixture block selector {block} before opening the port");

    let mut warm = cfg.node.clone();
    warm.n = block;
    let outcome = crate::mle::run_step(&warm, None, None);

    assert!(
        outcome.root.is_some(),
        "prewarm proved no root for fixture {block}; refusing to serve. \
         Check MLE_ELF/MLE_ETHPROOFS_PREWARM_BLOCK, or set MLE_ETHPROOFS_PREWARM=0 to skip \
         (and accept that the first real block will report this setup as proving time)."
    );

    info!(
        "prewarm done in {:.3}s ({} cycle(s)); resident state is hot, the next block pays none of it",
        started.elapsed().as_secs_f64(),
        outcome.cycles,
    );
}

/// Serve blocks until the channel closes (i.e. forever, in production).
pub fn run(cfg: &MleEthProofsConfig) {
    if let Err(e) = cfg.validate_auth() {
        panic!("invalid auth configuration: {e}");
    }

    let results = Arc::new(ProvingResultStore::new());

    // Capacity one, and the single-flight gate in front of it: a second block can only be sitting
    // here if the gate let it through, which it does not. The bound is a tripwire, not a queue.
    let (job_tx, job_rx) = crossbeam::channel::bounded::<BlockRequest>(1);

    // Leaked on purpose: the service must outlive every pipeline thread, and those threads are
    // plain OS threads with no scope tying them to this function. Dropping the runtime at the end
    // of `run` would take the server down while blocks are still in flight.
    let threads = runtime_threads();
    let runtime = Box::leak(Box::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(threads)
            .max_blocking_threads(threads)
            .enable_all()
            .thread_name("mle-ethproofs-rt")
            .build()
            .expect("building the ethproofs runtime failed"),
    ));
    info!("ethproofs runtime: {threads} worker thread(s)");

    // Before the port, not after: see `prewarm`.
    if prewarm_enabled() {
        prewarm(cfg);
    } else {
        warn!("prewarm disabled; the first block will report this process's setup as proving time");
    }

    server::serve(cfg, job_tx, Arc::clone(&results), runtime);
    info!(
        "EthProofs MLE prover ready on {} -- waiting for RSP (step={:?}, cards={})",
        cfg.grpc_addr, cfg.node.step, cfg.node.prover_count,
    );

    // The first block used to be an outlier here -- it paid the process's one-time setup inside
    // its own reported `proving_duration`. `prewarm` above now pays that before the port opens, so
    // every block RSP sends sees the resident state (see `Resident`) and reports only its own work.
    let mut proved = 0u64;
    let mut failed = 0u64;
    while let Ok(request) = job_rx.recv() {
        let block = request.block;
        let received_at = request.received_at;
        info!("block {block}: proving");

        let outcome = crate::mle::run_step(
            &cfg.node,
            None,
            Some(BlockJob {
                block,
                stdin: request.stdin,
            }),
        );

        // Read the clock before touching the store, so serialization is not counted, and after the
        // pipeline has fully finished -- `run_step` returns only once the root has been accepted.
        let proving = received_at.elapsed();

        match outcome.root {
            Some(root) => {
                if results.complete(block, outcome.cycles, proving, root) {
                    proved += 1;
                    info!(
                        "block {block}: proved in {:.3}s (e2e {:.3}s + root-accept {:.3}s + \
                         witness decode and setup) | {proved} proved, {failed} failed",
                        proving.as_secs_f64(),
                        outcome.e2e_wall.as_secs_f64(),
                        outcome.root_accept.as_secs_f64(),
                    );
                } else {
                    failed += 1;
                }
            }
            None => {
                // No root: `--step` stopped short of combine, the block emulated to nothing, or
                // the export failed. RSP keeps polling and gets no proof, which is the truthful
                // answer -- there is none.
                failed += 1;
                warn!(
                    "block {block}: finished WITHOUT a root proof after {:.3}s; \
                     nothing to answer GetProveResult with | {proved} proved, {failed} failed",
                    proving.as_secs_f64(),
                );
            }
        }

        // Only now: RSP may not be told we are free until the result it will ask for is in place.
        server::release_request_slot();
    }

    warn!("ethproofs job channel closed; the prover loop is exiting");
}
