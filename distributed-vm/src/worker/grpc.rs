use crate::{coordinator_client::CoordinatorClient, worker::message::WorkerMsg, ProofResult};
use p3_commit::Pcs;
use pico_vm::{
    configs::config::StarkGenericConfig, messages::gateway::GatewayMsg,
    thread::channel::DuplexUnboundedEndpoint,
};
use std::{net::SocketAddr, sync::Arc};
use tokio::task::JoinHandle;
use tonic::transport::Channel;

pub fn run<SC: StarkGenericConfig + 'static>(
    endpoint: Arc<DuplexUnboundedEndpoint<WorkerMsg<SC>, WorkerMsg<SC>>>,
    coordinator_addr: SocketAddr,
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
        let channel = Channel::from_shared(format!("http://{}", coordinator_addr))
            .expect("invalid coordinator address")
            .connect()
            .await
            .unwrap();
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
