#![feature(min_specialization)]

pub mod coordinator;
pub mod gateway;
pub mod worker;

tonic::include_proto!("grpc");
