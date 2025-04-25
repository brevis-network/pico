use anyhow::Result;
use clap::Parser;
use distributed_vm::worker::{
    config::WorkerConfig,
    grpc,
    message::WorkerMsg,
    prover::{Prover, ProverRunner},
};
use dotenvy::dotenv;
use futures::future::join_all;
use log::debug;
use pico_perf::common::bench_field::BenchField;
use pico_vm::{
    configs::stark_config::{BabyBearPoseidon2, KoalaBearPoseidon2},
    machine::logger::setup_logger,
    thread::channel::DuplexUnboundedChannel,
};
use std::sync::Arc;
use tokio::signal::ctrl_c;

#[tokio::main]
async fn main() -> Result<()> {
    setup_logger();

    dotenv().ok();

    let cfg = Arc::new(WorkerConfig::parse());
    debug!("starting with config: {:?}", cfg);

    let handles = match cfg.field {
        BenchField::BabyBear => {
            let channel = DuplexUnboundedChannel::default();
            channel.endpoint2().send(WorkerMsg::RequestTask)?;

            let grpc = grpc::run(
                channel.endpoint1(),
                cfg.coordinator_grpc_addr.clone(),
                cfg.max_grpc_msg_size,
            );
            let prover = Prover::<BabyBearPoseidon2>::new(cfg.program, channel.endpoint2());
            let prover = prover.run();

            // wait for CTRL + C then close the channels to exit
            debug!("waiting for stop");
            ctrl_c().await?;

            channel.endpoint1().send(WorkerMsg::Exit)?;
            channel.endpoint2().send(WorkerMsg::Exit)?;

            [grpc, prover]
        }
        BenchField::KoalaBear => {
            let channel = DuplexUnboundedChannel::default();
            channel.endpoint2().send(WorkerMsg::RequestTask)?;

            let grpc = grpc::run(
                channel.endpoint1(),
                cfg.coordinator_grpc_addr.clone(),
                cfg.max_grpc_msg_size,
            );
            let prover = Prover::<KoalaBearPoseidon2>::new(cfg.program, channel.endpoint2());
            let prover = prover.run();

            // wait for CTRL + C then close the channels to exit
            debug!("waiting for stop");
            ctrl_c().await?;

            channel.endpoint1().send(WorkerMsg::Exit)?;
            channel.endpoint2().send(WorkerMsg::Exit)?;

            [grpc, prover]
        }
    };

    join_all(handles).await;

    Ok(())
}
