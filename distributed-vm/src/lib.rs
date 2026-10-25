#![feature(min_specialization)]
// `tonic::Status`, the error of every generated gRPC method below and of the auth interceptors, is
// larger than `result_large_err` allows, and generated code is not ours to box.
#![allow(clippy::result_large_err)]

#[cfg(feature = "aot-emulator")]
mod aot;
pub mod common;
pub mod gateway;
pub mod io;
pub mod mle;
pub mod timeline;

pub fn init_optional_aot() {
    #[cfg(feature = "aot-emulator")]
    aot::register();
}

tonic::include_proto!("grpc");
tonic::include_proto!("prover_server");
tonic::include_proto!("proving_network");
tonic::include_proto!("finalproof");
tonic::include_proto!("orchestrator");
tonic::include_proto!("proof");
tonic::include_proto!("aggregator");
tonic::include_proto!("subblock");
tonic::include_proto!("proof_transfer");
tonic::include_proto!("scheduler");
