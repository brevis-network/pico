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
    messages::gateway::GatewayMsg,
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
    debug!("starting with config: {:?}", cfg);

    let shutdown = CancellationToken::new();

    match cfg.field {
        BenchField::BabyBear => {
            let channel = DuplexUnboundedChannel::default();
            channel.endpoint2().send(GatewayMsg::RequestTask)?;

            grpc::run(
                channel.endpoint1(),
                cfg.coordinator_grpc_addr.clone(),
                cfg.max_grpc_msg_size,
                shutdown.clone(),
            );

            // start provers
            (0..cfg.prover_count).enumerate().for_each(|(i, _)| {
                let prover_id = format!("{}-prover-{}", cfg.worker_name, i);
                let worker_endpoint = channel.endpoint2().clone_inner();
                let prover =
                    Prover::<BabyBearPoseidon2>::new(prover_id, cfg.program, worker_endpoint);
                prover.run();
            });
        }
        BenchField::KoalaBear => {
            let channel = DuplexUnboundedChannel::default();
            channel.endpoint2().send(GatewayMsg::RequestTask)?;

            grpc::run(
                channel.endpoint1(),
                cfg.coordinator_grpc_addr.clone(),
                cfg.max_grpc_msg_size,
                shutdown.clone(),
            );

            // start provers
            (0..cfg.prover_count).enumerate().for_each(|(i, _)| {
                let prover_id = format!("{}-prover-{}", cfg.worker_name, i);
                let worker_endpoint = channel.endpoint2().clone_inner();
                let prover =
                    Prover::<KoalaBearPoseidon2>::new(prover_id, cfg.program, worker_endpoint);
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
