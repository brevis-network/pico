use crate::worker::message::WorkerMsg;
use pico_vm::{
    configs::stark_config::{BabyBearPoseidon2, KoalaBearPoseidon2},
    messages::{
        combine::{CombineMsg, CombineRequest},
        gateway::GatewayMsg,
    },
    thread::channel::DuplexUnboundedEndpoint,
};
use std::sync::Arc;
use tokio::task::JoinHandle;
use tracing::info;

pub fn run_bb(
    endpoint: Arc<
        DuplexUnboundedEndpoint<WorkerMsg<BabyBearPoseidon2>, WorkerMsg<BabyBearPoseidon2>>,
    >,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok(msg) = endpoint.recv() {
            match msg {
                WorkerMsg::ProcessTask(GatewayMsg::Combine(
                    CombineMsg::Request(CombineRequest {
                        chunk_index,
                        flag_complete,
                        proofs,
                    }),
                    task_id,
                    ip_addr,
                )) => {
                    // TODO: add combine logic
                    info!("recieve combine request: chunk_index = {}", chunk_index);
                }
                // ignore other task types
                WorkerMsg::ProcessTask(..) => (),
                WorkerMsg::Exit => break,
                _ => panic!("unsupported"),
            }
        }
    })
}

pub fn run_kb(
    endpoint: Arc<
        DuplexUnboundedEndpoint<WorkerMsg<KoalaBearPoseidon2>, WorkerMsg<KoalaBearPoseidon2>>,
    >,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok(msg) = endpoint.recv() {
            match msg {
                WorkerMsg::ProcessTask(GatewayMsg::Combine(
                    CombineMsg::Request(CombineRequest {
                        chunk_index,
                        flag_complete,
                        proofs,
                    }),
                    task_id,
                    ip_addr,
                )) => {
                    // TODO: add combine logic
                    info!("recieve combine request: chunk_index = {}", chunk_index);
                }
                // ignore other task types
                WorkerMsg::ProcessTask(..) => (),
                WorkerMsg::Exit => break,
                _ => panic!("unsupported"),
            }
        }
    })
}
