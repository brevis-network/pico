use anyhow::Result;
use clap::Parser;
use distributed_vm::worker::{config::WorkerConfig, grpc, message::WorkerMsg, riscv};
use log::debug;
use pico_perf::common::{bench_field::BenchField, bench_program::PROGRAMS};
use pico_vm::{
    configs::stark_config::{bb_poseidon2::BabyBearPoseidon2, kb_poseidon2::KoalaBearPoseidon2},
    machine::logger::setup_logger,
    thread::channel::DuplexUnboundedChannel,
};
use std::{str::FromStr, sync::Arc};
use tokio::signal::ctrl_c;

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about=None)]
struct Args {
    #[clap(long, default_value = "kb")]
    field: String,

    // #[clap(long, default_value = "reth-17106222")]
    #[clap(long, default_value = "fibonacci-300kn")]
    program: String,
}

impl From<Args> for WorkerConfig {
    fn from(args: Args) -> Self {
        let field = BenchField::from_str(&args.field).unwrap();
        let program = *PROGRAMS.iter().find(|p| p.name == args.program).unwrap();

        Self { field, program }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_logger();

    let cfg = Arc::new(WorkerConfig::from(Args::parse()));
    let field = cfg.field;

    let (grpc, riscv) = match field {
        BenchField::BabyBear => {
            let channel = DuplexUnboundedChannel::default();
            channel.endpoint2().send(WorkerMsg::RequestTask).unwrap();

            let grpc = grpc::run(channel.endpoint1());
            let riscv = riscv::run(
                BabyBearPoseidon2::default(),
                cfg.program,
                channel.endpoint2(),
            );

            // wait for CTRL + C then close the channels to exit
            debug!("waiting for stop");
            ctrl_c().await.unwrap();

            channel.endpoint1().send(WorkerMsg::Exit).unwrap();
            channel.endpoint2().send(WorkerMsg::Exit).unwrap();

            (grpc, riscv)
        }
        BenchField::KoalaBear => {
            let channel = DuplexUnboundedChannel::default();
            channel.endpoint2().send(WorkerMsg::RequestTask).unwrap();

            let grpc = grpc::run(channel.endpoint1());
            let riscv = riscv::run(
                KoalaBearPoseidon2::default(),
                cfg.program,
                channel.endpoint2(),
            );

            // wait for CTRL + C then close the channels to exit
            debug!("waiting for stop");
            ctrl_c().await.unwrap();

            channel.endpoint1().send(WorkerMsg::Exit).unwrap();
            channel.endpoint2().send(WorkerMsg::Exit).unwrap();

            (grpc, riscv)
        }
    };

    let _ = tokio::join!(grpc, riscv);

    Ok(())
}
