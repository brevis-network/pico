use crate::common::parse::{parse_field, parse_program};
use clap::Parser;
use pico_perf::common::{bench_field::BenchField, bench_program::BenchProgram};

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
pub struct SingleNodeConfig {
    #[clap(
        long,
        env = "FIELD",
        default_value = "kb",
        value_parser = parse_field,
        help = "Field identifier"
    )]
    pub field: BenchField,

    // program could be reth-17106222
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
        env = "PROVER_COUNT",
        default_value = "1",
        help = "Prover count to start"
    )]
    pub prover_count: usize,
}
