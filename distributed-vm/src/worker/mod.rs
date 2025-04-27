pub mod config;
pub mod grpc;
pub mod prover;

tonic::include_proto!("grpc");

use pico_vm::{messages::gateway::GatewayMsg, thread::channel::DuplexUnboundedEndpoint};

pub type WorkerEndpoint<SC> = DuplexUnboundedEndpoint<GatewayMsg<SC>, GatewayMsg<SC>>;
