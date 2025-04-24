pub mod combine;
pub mod config;
pub mod grpc;
pub mod message;
pub mod riscv;
// TODO: add covert and combine provers here

tonic::include_proto!("grpc");
