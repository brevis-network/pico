#![feature(min_specialization)]

pub(crate) mod common;
pub mod coordinator;
pub mod gateway;
pub mod single_node;
pub mod worker;

tonic::include_proto!("grpc");
