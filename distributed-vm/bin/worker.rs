use anyhow::Result;
use clap::Parser;
use distributed_vm::worker::{
    config::WorkerConfig,
    grpc,
    prover::{Prover, ProverRunner},
};
use dotenvy::dotenv;
use log::debug;
use pico_perf::common::bench_field::BenchField;
use pico_vm::{
    configs::stark_config::{BabyBearPoseidon2, KoalaBearPoseidon2},
    machine::logger::setup_logger,
    thread::channel::DuplexUnboundedChannel,
};
use std::{process, sync::Arc};
use tokio::signal::ctrl_c;
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> Result<()> {
    setup_logger();

    dotenv().ok();

    let cfg = Arc::new(WorkerConfig::parse());
    cfg.validate().expect("invalid config");
    debug!("starting with config: {:?}", cfg);

    let shutdown = CancellationToken::new();

    let grpc_conn = grpc::new_channel(cfg.coordinator_grpc_addr.clone()).await;

    match cfg.field {
        BenchField::BabyBear => {
            (0..cfg.prover_count).enumerate().for_each(|(i, _)| {
                let channel = DuplexUnboundedChannel::default();

                // start grpc
                let grpc_client_id = format!("{}-grpc-{}", cfg.worker_name, i);
                grpc::run(
                    grpc_client_id,
                    grpc_conn.clone(),
                    channel.endpoint1(),
                    &cfg,
                    shutdown.clone(),
                );

                // start prover
                let prover_id = format!("{}-prover-{}", cfg.worker_name, i);
                let prover =
                    Prover::<BabyBearPoseidon2>::new(prover_id, cfg.program, channel.endpoint2());
                prover.run();
            });
        }
        BenchField::KoalaBear => {
            (0..cfg.prover_count).enumerate().for_each(|(i, _)| {
                let channel = DuplexUnboundedChannel::default();

                // start grpc
                let grpc_client_id = format!("{}-grpc-{}", cfg.worker_name, i);
                grpc::run(
                    grpc_client_id,
                    grpc_conn.clone(),
                    channel.endpoint1(),
                    &cfg,
                    shutdown.clone(),
                );

                // start prover
                let prover_id = format!("{}-prover-{}", cfg.worker_name, i);
                let prover =
                    Prover::<KoalaBearPoseidon2>::new(prover_id, cfg.program, channel.endpoint2());
                prover.run();
            });
        }
    };

    debug!("waiting for stop");
    ctrl_c().await?;
    debug!("Ctrl+C received; shutting down worker");
    shutdown.cancel();
    process::exit(0);
}
