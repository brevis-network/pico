use crate::{coordinator_client::CoordinatorClient, worker::message::WorkerMsg, RiscvResult};
use p3_commit::Pcs;
use pico_vm::{
    configs::config::StarkGenericConfig, messages::gateway::GatewayMsg,
    thread::channel::DuplexUnboundedEndpoint,
};
use std::sync::Arc;
use tokio::task::JoinHandle;

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
        let mut client = CoordinatorClient::connect("http://[::1]:50051")
            .await
            .unwrap();

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
