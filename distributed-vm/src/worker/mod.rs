pub mod config;
pub mod grpc;
pub mod message;
pub mod prover;

tonic::include_proto!("grpc");

use crate::worker::message::WorkerMsg;
use pico_vm::thread::channel::DuplexUnboundedEndpoint;

pub type WorkerEndpoint<SC> = DuplexUnboundedEndpoint<WorkerMsg<SC>, WorkerMsg<SC>>;
