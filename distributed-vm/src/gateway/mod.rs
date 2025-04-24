pub mod handler;
pub mod message;

use crossbeam::channel::{select, Receiver};
use handler::GatewayHandler;
use log::debug;
use p3_commit::Pcs;
use pico_vm::{
    configs::config::StarkGenericConfig,
    messages::{combine::CombineMsg, gateway::GatewayMsg, riscv::RiscvMsg},
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
    <SC as StarkGenericConfig>::Domain: Send,
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
                            let no_task = gateway_handler.process(msg.clone()).unwrap();
                            assert!(no_task.is_none());
                            // send the task to grpc
                            grpc_endpoint.send(msg).unwrap();
                        }
                        GatewayMsg::EmulatorComplete => {
                            let no_task = gateway_handler.process(msg.clone()).unwrap();
                            assert!(no_task.is_none());
                        }
                        _ => panic!("unsupported"),
                    }
                }
                recv(grpc_endpoint.receiver()) -> msg => {
                    let msg = msg.unwrap();
                    match msg {
                        GatewayMsg::Riscv(RiscvMsg::Response(..), _, _) | GatewayMsg::Combine(CombineMsg::Response(..), _, _) => {
                            // save the generated proof to the chunk_index slot in proof tree
                            if let Some(msg) = gateway_handler.process(msg).unwrap() {
                                // send the new combine task to grpc
                                grpc_endpoint.send(msg).unwrap();
                            }
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
