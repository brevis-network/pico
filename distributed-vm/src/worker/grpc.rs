use crate::{coordinator_client::CoordinatorClient, worker::message::WorkerMsg, ProofResult};
use p3_commit::Pcs;
use pico_vm::{
    configs::config::StarkGenericConfig, messages::gateway::GatewayMsg,
    thread::channel::DuplexUnboundedEndpoint,
};
use std::sync::Arc;
use tokio::task::JoinHandle;
use tonic::transport::Channel;

pub fn run<SC: StarkGenericConfig + 'static>(
    endpoint: Arc<DuplexUnboundedEndpoint<WorkerMsg<SC>, WorkerMsg<SC>>>,
    coordinator_addr: String,
    max_grpc_msg_size: usize,
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

        while let Ok(msg) = endpoint.recv() {
            match msg {
                WorkerMsg::RequestTask => {
                    let res = client.request_task(()).await.unwrap();
                    let msg: GatewayMsg<SC> = res.into_inner().into();

                    endpoint.send(WorkerMsg::ProcessTask(msg)).unwrap();
                }
                WorkerMsg::RespondResult(msg) => {
                    let res: ProofResult = msg.into();
                    client.respond_result(res).await.unwrap();
                }
                WorkerMsg::Exit => break,
                _ => panic!("unsupported"),
            }
        }
    })
}
