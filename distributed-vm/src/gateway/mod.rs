pub mod handler;
pub mod message;

use crossbeam::channel::{select, Receiver};
use handler::GatewayHandler;
use log::debug;
use p3_commit::Pcs;
use pico_vm::{
    configs::config::StarkGenericConfig,
    messages::{gateway::GatewayMsg, riscv::RiscvMsg},
    thread::channel::DuplexUnboundedEndpoint,
};
use std::sync::Arc;
use tokio::task::JoinHandle;

pub type GatewayEndpoint<SC> = DuplexUnboundedEndpoint<GatewayMsg<SC>, GatewayMsg<SC>>;

pub fn run<SC: Send + StarkGenericConfig + 'static>(
    emulator_receiver: Arc<Receiver<GatewayMsg<SC>>>,
    grpc_endpoint: Arc<GatewayEndpoint<SC>>,
) -> JoinHandle<()>
where
    <SC::Pcs as Pcs<
        <SC as StarkGenericConfig>::Challenge,
        <SC as StarkGenericConfig>::Challenger,
    >>::ProverData: Send,
{
    debug!("[coordinator] gateway init");

    let thread_handle = tokio::spawn(async move {
        let mut gateway_handler = GatewayHandler::default();

        loop {
            select! {
                recv(emulator_receiver) -> msg => {
                    let msg = msg.unwrap();
                    match msg {
                        GatewayMsg::Riscv(RiscvMsg::Request(..), _, _) => {
                            // save a none proof as placeholder to the chunk_index slot in proof tree
                            // TODO: avoid clone msg, and move msg into process for proof response
                            gateway_handler.process(msg.clone()).unwrap();
                            // send the task to grpc
                            grpc_endpoint.send(msg).unwrap();
                        }
                        GatewayMsg::EmulatorComplete => gateway_handler.process(msg.clone()).unwrap(),
                        _ => panic!("unsupported"),
                    }
                }
                recv(grpc_endpoint.receiver()) -> msg => {
                    let msg = msg.unwrap();
                    match msg {
                        GatewayMsg::Riscv(RiscvMsg::Response(..), _, _) => {
                            // save the generated proof to the chunk_index slot in proof tree
                            gateway_handler.process(msg).unwrap();
                        }
                        _ => panic!("unsupported"),
                    }
                }
            }
        }
    });

    debug!("[coordinator] gateway init end");

    thread_handle
}
