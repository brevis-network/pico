pub mod config;
pub mod grpc;
pub mod prover;

tonic::include_proto!("grpc");

use crate::messages::gateway::GatewayMsg;
use pico_vm::thread::channel::DuplexUnboundedEndpoint;

pub type WorkerEndpoint<SC> = DuplexUnboundedEndpoint<GatewayMsg<SC>, GatewayMsg<SC>>;
