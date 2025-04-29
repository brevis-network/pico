use super::WorkerEndpoint;
use crate::{
    common::auth::AuthConfig, coordinator_client::CoordinatorClient, worker::config::WorkerConfig,
    ProofResult,
};
use log::error;
use p3_commit::Pcs;
use pico_vm::{
    configs::config::StarkGenericConfig,
    messages::{combine::CombineMsg, gateway::GatewayMsg, riscv::RiscvMsg},
};
use std::sync::Arc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tonic::transport::Channel;

pub fn run<SC: StarkGenericConfig + 'static>(
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
    let coordinator_addr = cfg.coordinator_grpc_addr.clone();
    let max_grpc_msg_size = cfg.max_grpc_msg_size;
    let auth_interceptor = cfg.client_auth_interceptor();

    tokio::spawn(async move {
        // TODO: consider adding max attempts to the config
        const MAX_ATTEMPTS: usize = 10;
        let mut attempts = 0;
        let delay = std::time::Duration::from_secs(1);

        let channel = loop {
            match Channel::from_shared(coordinator_addr.clone())
                .expect("Invalid coordinator address format")
                .connect()
                .await
            {
                Ok(c) => break c,
                Err(e) if attempts < MAX_ATTEMPTS => {
                    error!(
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
        };
        let mut client = CoordinatorClient::with_interceptor(channel, auth_interceptor)
            .max_encoding_message_size(max_grpc_msg_size)
            .max_decoding_message_size(max_grpc_msg_size);

        loop {
            tokio::select! {
                biased;

                _ = shutdown.cancelled() => break,
                maybe_msg = async { endpoint.recv() } => match maybe_msg {
                    Ok(msg) => match msg {
                        GatewayMsg::RequestTask => {
                            match client.request_task(()).await {
                                Ok(response) => {
                                    let new_msg: GatewayMsg<SC> = response.into_inner().into();
                                    endpoint.send(new_msg).unwrap();
                                }
                                Err(status) => {
                                    if status.code() == tonic::Code::Unauthenticated {
                                        error!("gRPC authentication failed: {}", status.message
                                            ());
                                        std::process::exit(1);
                                    } else {
                                        error!("gRPC request failed: {}", status.message());
                                    }
                                }
                            }
                        }
                        GatewayMsg::Riscv(RiscvMsg::Response(_), _, _)
                        | GatewayMsg::Combine(CombineMsg::Response(_), _, _) => {
                            let res: ProofResult = msg.into();
                            if let Err(status) = client.respond_result(res).await {
                                if status.code() == tonic::Code::Unauthenticated {
                                    error!("gRPC authentication failed: {}", status.message());
                                    std::process::exit(1);
                                } else {
                                    error!("gRPC response failed: {}", status.message());
                                }
                            }
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
