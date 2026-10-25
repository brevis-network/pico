use anyhow::Result;
use clap::{Parser, ValueEnum};
use distributed_vm::{
    common::{parse::parse_program, BlockNum},
    pico_prover_client::PicoProverClient,
    GetProveResultRequest, ProvingRequest, ProvingType,
};
use dotenvy::dotenv;
use log::debug;
use pico_perf::common::bench_program::{load_input, BenchProgram};
use pico_vm::machine::logger::setup_logger;
use std::sync::Arc;
use tonic::codec::CompressionEncoding;
use tracing::info;

#[derive(Clone, Debug, ValueEnum)]
enum Command {
    Request,
    GetResult,
}

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Config {
    #[clap(long, default_value = "request", help = "Command")]
    pub cmd: Command,

    #[clap(
        long,
        env = "BLOCK_NUMBER",
        default_value = "17106222",
        help = "Block number"
    )]
    pub block_number: BlockNum,

    #[clap(
        long,
        env = "PROGRAM",
        default_value = "reth-17106222",
        value_parser = parse_program,
        help = "Program name"
    )]
    pub program: BenchProgram,

    #[clap(
        long,
        env = "GRPC_ADDR",
        default_value = "http://[::1]:50052",
        help = "gRPC address"
    )]
    pub grpc_addr: String,

    #[clap(
        long,
        env = "MAX_GRPC_MSG_SIZE",
        default_value = "629145600",
        help = "Max gRPC message size (bytes)"
    )]
    pub max_grpc_msg_size: usize,
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_logger();

    dotenv().ok();

    let cfg = Arc::new(Config::parse());
    debug!("starting with config: {:?}", cfg);

    let mut client = PicoProverClient::connect(cfg.grpc_addr.clone())
        .await?
        .max_encoding_message_size(cfg.max_grpc_msg_size)
        .max_decoding_message_size(cfg.max_grpc_msg_size)
        .accept_compressed(CompressionEncoding::Zstd)
        .send_compressed(CompressionEncoding::Zstd);

    match cfg.cmd {
        Command::Request => {
            let block_number = cfg.block_number;
            let proving_type = ProvingType::Cpu as i32;
            let input_buffer = cfg.program.input.map(|input| load_input(input).unwrap());
            let req = ProvingRequest {
                block_number,
                proving_type,
                input_buffer,
            };
            let res = client.request_prover(req).await?;
            info!("Request command response: {res:?}");
        }
        Command::GetResult => {
            let block_number = cfg.block_number;
            let req = GetProveResultRequest { block_number };
            let res = client.get_prove_result(req).await?;
            info!("GetResult command response: {res:?}");
        }
    };

    Ok(())
}
