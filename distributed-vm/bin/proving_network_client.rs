use anyhow::Result;
use clap::{Parser, ValueEnum};
use distributed_vm::{proving_network_client::ProvingNetworkClient, ProveTaskRequest};
use dotenvy::dotenv;
use log::debug;
use pico_vm::machine::logger::setup_logger;
use std::{fs, sync::Arc};
use tonic::codec::CompressionEncoding;
use tracing::info;

#[derive(Clone, Debug, ValueEnum)]
enum Command {
    ProveTask,
}

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Config {
    #[clap(long, default_value = "prove-task", help = "Command")]
    pub cmd: Command,

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

    let mut client = ProvingNetworkClient::connect(cfg.grpc_addr.clone())
        .await?
        .max_encoding_message_size(cfg.max_grpc_msg_size)
        .max_decoding_message_size(cfg.max_grpc_msg_size)
        .accept_compressed(CompressionEncoding::Zstd)
        .send_compressed(CompressionEncoding::Zstd);

    match cfg.cmd {
        Command::ProveTask => {
            let inputs = ["./perf/bench_data/primus.bin"]
                .iter()
                .map(|file_path| fs::read_to_string(file_path).unwrap())
                .collect();
            let req = ProveTaskRequest { inputs };
            let res = client.prove_task(req).await?;
            info!("RequestTask command response: {res:?}");
        }
    };

    Ok(())
}
