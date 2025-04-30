use crate::{
    common::{
        auth::{AuthConfig, AuthMethod},
        parse::{parse_field, parse_program},
    },
    impl_auth_config,
};
use clap::Parser;
use pico_perf::common::{bench_field::BenchField, bench_program::BenchProgram};

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
pub struct WorkerConfig {
    #[clap(
        long,
        env = "FIELD",
        default_value = "kb",
        value_parser = parse_field,
        help = "Field identifier"
    )]
    pub field: BenchField,

    // TODO: change default to reth-17106222
    #[clap(
        long,
        env = "PROGRAM",
        default_value = "fibonacci-300kn",
        value_parser = parse_program,
        help = "Program name"
    )]
    pub program: BenchProgram,

    #[clap(
        long,
        env = "MAX_GRPC_MSG_SIZE",
        default_value = "629145600",
        help = "Max gRPC message size (bytes)"
    )]
    pub max_grpc_msg_size: usize,

    #[clap(
        long,
        env = "COORDINATOR_GRPC_ADDR",
        default_value = "http://[::1]:50051",
        help = "gRPC address of the coordinator server to connect to"
    )]
    pub coordinator_grpc_addr: String,

    #[clap(
        long,
        env = "WORKER_NAME",
        default_value = "default-worker",
        help = "Worker name"
    )]
    pub worker_name: String,

    #[clap(
        long,
        env = "PROVER_COUNT",
        default_value = "1",
        help = "Prover count to start"
    )]
    pub prover_count: usize,

    #[clap(
        long,
        env = "AUTH_METHOD",
        default_value = "none",
        value_enum,
        help = "Authentication method (none, bearer)"
    )]
    pub auth_method: AuthMethod,

    #[clap(
        long,
        env = "BEARER_TOKEN",
        requires = "auth_method",
        help = "Bearer token (required if auth_method=bearer)"
    )]
    pub bearer_token: Option<String>,
}

impl_auth_config!(WorkerConfig);

impl WorkerConfig {
    pub fn validate(&self) -> Result<(), String> {
        self.validate_auth()
    }
}
