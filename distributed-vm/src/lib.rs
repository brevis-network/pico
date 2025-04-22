#![feature(min_specialization)]

pub mod coordinator;
pub mod gateway;
pub mod worker;

tonic::include_proto!("grpc");

// 600MB
const MAX_GRPC_MSG_SIZE: usize = 600 * 1024 * 1024;
