#![feature(min_specialization)]
// `tonic::Status`, the error of every generated gRPC method below and of the auth interceptors, is
// larger than `result_large_err` allows, and generated code is not ours to box.
#![allow(clippy::result_large_err)]

/// `--version` of the prover binaries: the crate version and the backend it was built for.
pub const VERSION: &str = if cfg!(feature = "cuda") {
    concat!(env!("CARGO_PKG_VERSION"), " [cuda]")
} else {
    concat!(env!("CARGO_PKG_VERSION"), " [cpu]")
};

/// Logs the build's backend and, in a `cuda` build, exits unless a CUDA device is visible.
pub fn announce_backend() {
    tracing::info!("pico {VERSION}");
    #[cfg(feature = "cuda")]
    pico_vm::cuda_adaptor::require_cuda_device();
}

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
