use crate::{
    common::{
        auth::{AuthConfig, AuthMethod},
        parse::{parse_field, parse_program},
    },
    impl_auth_config,
};
use clap::Parser;
use pico_perf::common::{bench_field::BenchField, bench_program::BenchProgram};
use std::net::SocketAddr;

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
pub struct CoordinatorConfig {
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
        env = "GRPC_ADDR",
        default_value = "[::1]:50051",
        help = "gRPC listen address"
    )]
    pub grpc_addr: SocketAddr,

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

impl_auth_config!(CoordinatorConfig);

impl CoordinatorConfig {
    pub fn validate(&self) -> Result<(), String> {
        self.validate_auth()
    }
}
