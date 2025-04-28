use crate::{coordinator_client::CoordinatorClient, ProofResult};
use p3_commit::Pcs;
use pico_vm::{
    configs::config::StarkGenericConfig,
    messages::{combine::CombineMsg, gateway::GatewayMsg, riscv::RiscvMsg},
};
use std::sync::Arc;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tonic::transport::Channel;

use super::WorkerEndpoint;

pub fn run<SC: StarkGenericConfig + 'static>(
    endpoint: Arc<WorkerEndpoint<SC>>,
    coordinator_addr: String,
    max_grpc_msg_size: usize,
    shutdown: CancellationToken,
) -> JoinHandle<()>
where
    <SC::Pcs as Pcs<
        <SC as StarkGenericConfig>::Challenge,
        <SC as StarkGenericConfig>::Challenger,
    >>::ProverData: Send,
    <SC as StarkGenericConfig>::Domain: Send,
{
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
        };
        let mut client = CoordinatorClient::new(channel)
            .max_encoding_message_size(max_grpc_msg_size)
            .max_decoding_message_size(max_grpc_msg_size);

        loop {
            tokio::select! {
                biased;

                _ = shutdown.cancelled() => break,
                maybe_msg = async { endpoint.recv() } => match maybe_msg {
                    Ok(msg) => match msg {
                        GatewayMsg::RequestTask => {
                            let res = client.request_task(()).await.unwrap();
                            let msg: GatewayMsg<SC> = res.into_inner().into();

                            endpoint.send(msg).unwrap();
                        }
                        GatewayMsg::Riscv(RiscvMsg::Response(_), _, _)
                        | GatewayMsg::Combine(CombineMsg::Response(_), _, _) => {
                            let res: ProofResult = msg.into();
                            client.respond_result(res).await.unwrap();
                        }
                        GatewayMsg::Exit => break,
                        _ => panic!("unsupported"),
                    }
                    Err(_) => {
                        eprintln!("Failed to receive message from endpoint");
                        break;
                    }
                }
            }
        }
    })
}
