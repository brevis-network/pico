use crate::{
    coordinator_client::CoordinatorClient, worker::message::WorkerMsg, RiscvResult,
    MAX_GRPC_MSG_SIZE,
};
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
) -> JoinHandle<()>
where
    <SC::Pcs as Pcs<
        <SC as StarkGenericConfig>::Challenge,
        <SC as StarkGenericConfig>::Challenger,
    >>::ProverData: Send,
{
    tokio::spawn(async move {
        let channel = Channel::from_static("http://[::1]:50051")
            .connect()
            .await
            .unwrap();
        let mut client = CoordinatorClient::new(channel)
            .max_encoding_message_size(MAX_GRPC_MSG_SIZE)
            .max_decoding_message_size(MAX_GRPC_MSG_SIZE);

        while let Ok(msg) = endpoint.recv() {
            match msg {
                WorkerMsg::RequestTask => {
                    let res = client.request_riscv(()).await.unwrap();
                    let msg: GatewayMsg<SC> = res.into_inner().into();

                    endpoint.send(WorkerMsg::ProcessTask(msg)).unwrap();
                }
                WorkerMsg::RespondResult(msg) => {
                    let res: RiscvResult = msg.into();
                    client.respond_riscv(res).await.unwrap();
                }
                WorkerMsg::Exit => break,
                _ => panic!("unsupported"),
            }
        }
    })
}
