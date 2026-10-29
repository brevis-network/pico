//! MLE two-machine bring-up: the MLE counterpart of FRI's two-machine launch.
//!
//! Deliberately thin. FRI's two-machine usecase is a node with a gateway, an orchestrator and a
//! PicoProver service; MLE's entry point is one self-contained pipeline, so all this has to do is
//! put the scheduler on the wire and hand the secondary a client for it. Everything else — role
//! partitioning, the proof tree, the root pin — already lives in `GlobalScheduler` and is shared
//! with FRI rather than duplicated.
//!
//! Ports match FRI's so one box can run both without a second convention to remember.

use crate::common::{
    machine_role::{get_machine_role, get_worker_label},
    mle_scheduler_singleton::{get_mle_scheduler, init_mle_scheduler_client, set_mle_tokio_handle},
    scheduler_service::create_scheduler_server,
};
use std::net::SocketAddr;
use tracing::{error, info};

fn env_port(key: &str, default: u16) -> u16 {
    std::env::var(key)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(default)
}

/// Start whichever half of the two-machine shape this process is, and block until it is usable.
///
/// Called before the pipeline runs. A no-op unless two-machine was explicitly requested, so the
/// single-node path does not gain a runtime, a port, or a failure mode.
///
/// The runtime is intentionally leaked: MLE's pipeline threads are plain OS threads that
/// `block_on` this handle from arbitrary points, and the scheduler server must outlive every one of
/// them. Dropping it at the end of a scope would take the server down mid-run.
pub fn init_mle_two_machine() {
    let role = get_machine_role();
    // Worker threads are CAPPED, and the cap is the point.
    //
    // `new_multi_thread()` defaults to one worker per core — 240 on these boxes. This process also
    // runs an 8-thread emulator and rayon's global pool (also core-sized), and an *active* 240-worker
    // runtime wrecks both: profiling the primary mid-emulation showed 31% of CPU in rayon's
    // work-stealing `bridge_producer_consumer::helper` and 26% in `crossbeam_epoch` reclamation
    // (`try_advance` + `with_handle`), against **5%** in `emulate_instruction`. Epoch reclamation
    // cost scales with the number of registered participants, so simply having that many active
    // threads in the process is the cost.
    //
    // The scheduler service is not CPU-bound — it awaits a oneshot per request and moves proofs —
    // so a handful of threads is ample. `MLE_RT_THREADS` overrides if a topology ever needs more.
    let rt_threads = env_port("MLE_RT_THREADS", 4).max(1) as usize;
    let runtime = Box::leak(Box::new(
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(rt_threads)
            .max_blocking_threads(rt_threads)
            .enable_all()
            .thread_name("mle-2m-rt")
            .build()
            .expect("building the MLE two-machine runtime failed"),
    ));
    info!("MLE two-machine runtime: {rt_threads} worker threads");
    set_mle_tokio_handle(runtime.handle().clone());

    if role.is_primary() {
        let port = env_port("GLOBAL_SCHEDULER_PORT", 50054);
        let addr: SocketAddr = format!("0.0.0.0:{port}")
            .parse()
            .expect("scheduler bind address");
        // Serves the SAME singleton the local pipeline schedules against — that identity is the
        // whole point, and the reason a secondary now finds work where it previously
        // found an empty scheduler nobody was filling.
        let server = create_scheduler_server(get_mle_scheduler());
        // Bind before announcing, and separately from serving: `serve()` reports a bind failure as
        // an opaque "transport error", which is indistinguishable from a mid-run transport fault
        // and cost a full debugging round. Binding here names the real cause (address in use,
        // permission, bad address) at the point it happens.
        let listener = runtime.block_on(async move {
            tokio::net::TcpListener::bind(addr)
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "MLE primary could not bind the scheduler port {addr}: {e}. \
                     Another process (a FRI two-machine primary, or a previous run) may hold it — \
                     set GLOBAL_SCHEDULER_PORT to move."
                    )
                })
        });
        info!("MLE scheduler gRPC server listening on {addr}");
        runtime.spawn(async move {
            let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
            if let Err(e) = tonic::transport::Server::builder()
                .add_service(server)
                .serve_with_incoming(incoming)
                .await
            {
                error!("MLE scheduler gRPC server stopped: {e} ({e:?})");
            }
        });
        info!(
            "MLE two-machine PRIMARY ready (worker_label={}, scheduler port {port})",
            get_worker_label()
        );
    } else {
        // The secondary binds no port at all — it only builds clients. So two processes on one
        // host have zero port conflicts, and `PRIMARY_IP=127.0.0.1` exercises real gRPC over
        // loopback rather than a shortcut.
        let ip = std::env::var("PRIMARY_IP").unwrap_or_else(|_| "127.0.0.1".to_string());
        let port = env_port("GLOBAL_SCHEDULER_PORT", 50054);
        let addr = format!("http://{ip}:{port}");
        // Retried, not one-shot. The two halves are launched independently and each builds before
        // it runs — and they contend on the cargo lock — so "primary started first" does not mean
        // "primary is listening first". A single attempt turned that race into a hard failure.
        // FRI's client does the same thing for the same reason.
        //
        // Blocking until connected is still deliberate: every later call assumes the client exists,
        // and a refusal is far cheaper to read here than as a panic from a pipeline thread mid-run.
        let attempts = env_port("MLE_CONNECT_ATTEMPTS", 600) as usize;
        runtime.block_on(async {
            for attempt in 1..=attempts {
                match init_mle_scheduler_client(&addr).await {
                    Ok(()) => return,
                    Err(e) => {
                        if attempt == attempts {
                            panic!(
                                "MLE secondary could not reach the primary at {addr} after \
                                 {attempts} attempts: {e}"
                            );
                        }
                        if attempt == 1 || attempt % 30 == 0 {
                            info!("waiting for the primary at {addr} (attempt {attempt}): {e}");
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            }
        });
        info!(
            "MLE two-machine SECONDARY ready (worker_label={}, primary at {addr})",
            get_worker_label()
        );
    }
}
