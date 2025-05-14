use super::WorkerEndpoint;
use crate::{
    common::auth::AuthConfig,
    coordinator_client::CoordinatorClient,
    messages::{
        combine::{CombineMsg, CombineResponse},
        gateway::GatewayMsg,
        riscv::{RiscvMsg, RiscvResponse},
    },
    worker::config::WorkerConfig,
    ProofResult,
};
use log::error;
use p3_commit::Pcs;
use pico_vm::configs::config::StarkGenericConfig;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tonic::{codec::CompressionEncoding, transport::Channel};
use tracing::info;

pub async fn new_channel(coordinator_addr: String) -> Channel {
    // TODO: consider adding max attempts to the config
    const MAX_ATTEMPTS: usize = 10;
    let mut attempts = 0;
    let delay = std::time::Duration::from_secs(1);

    loop {
        match Channel::from_shared(coordinator_addr.clone())
            .expect("Invalid coordinator address format")
            // TODO: check below configurations if extended
            // .concurrency_limit(128)
            // .initial_stream_window_size(Some(1024 * 1024 * 1024))
            // .initial_connection_window_size(Some(1024 * 1024 * 1024))
            .connect()
            .await
        {
            Ok(c) => break c,
            Err(e) if attempts < MAX_ATTEMPTS => {
                eprintln!(
                    "Retrying gRPC connection to coordinator (attempt {}): {}",
                    attempts + 1,
                    e
                );
                tokio::time::sleep(delay).await;
                attempts += 1;
            }
            Err(e) => panic!(
                "Failed to connect to coordinator after {} attempts: {}",
                MAX_ATTEMPTS, e
            ),
        }
    }
}

pub fn run<SC: StarkGenericConfig + 'static>(
    grpc_client_id: String,
    grpc_channel: Channel,
    endpoint: Arc<WorkerEndpoint<SC>>,
    cfg: &WorkerConfig,
    shutdown: CancellationToken,
) -> JoinHandle<()>
where
    <SC::Pcs as Pcs<
        <SC as StarkGenericConfig>::Challenge,
        <SC as StarkGenericConfig>::Challenger,
    >>::ProverData: Send,
    <SC as StarkGenericConfig>::Domain: Send,
{
    let max_grpc_msg_size = cfg.max_grpc_msg_size;
    let auth_interceptor = cfg.client_auth_interceptor();

    tokio::spawn(async move {
        let mut grpc_client = CoordinatorClient::with_interceptor(grpc_channel, auth_interceptor)
            .max_encoding_message_size(max_grpc_msg_size)
            .max_decoding_message_size(max_grpc_msg_size)
            .accept_compressed(CompressionEncoding::Zstd)
            .send_compressed(CompressionEncoding::Zstd);

        loop {
            tokio::select! {
                biased;

                _ = shutdown.cancelled() => break,
                maybe_msg = async { endpoint.recv() } => match maybe_msg {
                    Ok(msg) => match msg {
                        GatewayMsg::RequestTask => {
                            info!("[{grpc_client_id}] requesting new task");
                            loop {
                                match grpc_client.request_task(()).await {
                                    Ok(response) => {
                                        info!("[{grpc_client_id}] got new task");
                                        let new_msg: GatewayMsg<SC> = response.into_inner().into();
                                        endpoint.send(new_msg).unwrap();
                                        break;
                                    }
                                    Err(status) => {
                                        if status.code() == tonic::Code::Unauthenticated {
                                            error!("gRPC authentication failed: {}", status.message
                                                ());
                                            std::process::exit(1);
                                        } else {
                                            // TODO: handle no task, just sleep(1) then retry
                                            // error!("gRPC request failed: {}", status.message());
                                        }
                                    }
                                }

                                // TODO: may replace with grpc stream, but make it simple for now
                                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                            }
                        }
                        GatewayMsg::Riscv(RiscvMsg::Response(RiscvResponse { chunk_index, ..}), _, _, _)
                        | GatewayMsg::Combine(CombineMsg::Response(CombineResponse { chunk_index, .. }), _, _, _) => {
                            info!("[{grpc_client_id}] sending proved result: chunk-{chunk_index}");

                            let res: ProofResult = msg.into();
                            if let Err(status) = grpc_client.respond_result(res).await {
                                if status.code() == tonic::Code::Unauthenticated {
                                    error!("gRPC authentication failed: {}", status.message());
                                    std::process::exit(1);
                                } else {
                                    error!("gRPC response failed: {}", status.message());
                                }
                            }

                            info!("[{grpc_client_id}] finish sending proved result: chunk-{chunk_index}");
                        }
                        GatewayMsg::Exit => break,
                        _ => panic!("unsupported"),
                    }
                    Err(_) => {
                        error!("Failed to receive message from endpoint");
                        break;
                    }
                }
            }
        }
    })
}
