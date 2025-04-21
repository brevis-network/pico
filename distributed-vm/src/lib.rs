#![feature(min_specialization)]

pub mod coordinator;
pub mod gateway;
pub mod worker;

tonic::include_proto!("grpc");

// 1 GB
const MAX_GRPC_MSG_SIZE: usize = 1024 * 1024 * 1024;
