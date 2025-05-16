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
    cuda_adaptor::{
        chips_analyzer::{initial_chips_2, initial_chips_load},
        resource_pool::{
            mem_pool::{create_ctx, get_global_mem_pool},
            stream_pool::{create_stream, get_global_stream_pool},
        },
    },
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

    initial_chips_2();
    initial_chips_load();

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

                create_ctx(i);
                let sync_pool = get_global_mem_pool(i);
                let mem_pool = &sync_pool.0;

                create_stream(i);
                let sync_stream = get_global_stream_pool(i);
                let stream = &sync_stream.0;

                // start prover
                let prover_id = format!("prover-{}", i);
                // let prover =
                //     Prover::<BabyBearPoseidon2>::new(prover_id, cfg.program, channel.endpoint2());
                // prover.run();
                let (prover, pk_gm) = Prover::<BabyBearPoseidon2>::new_cuda(
                    prover_id,
                    cfg.program,
                    channel.endpoint2(),
                    stream,
                    mem_pool,
                    i,
                );
                prover.run_cuda(pk_gm, stream, mem_pool, i);
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

                create_ctx(i);
                let sync_pool = get_global_mem_pool(i);
                let mem_pool = &sync_pool.0;

                create_stream(i);
                let sync_stream = get_global_stream_pool(i);
                let stream = &sync_stream.0;

                // start prover
                let prover_id = format!("prover-{}", i);
                // let prover =
                //     Prover::<KoalaBearPoseidon2>::new(prover_id, cfg.program, channel.endpoint2());
                // prover.run();
                let (prover, pk_gm) = Prover::<KoalaBearPoseidon2>::new_cuda(
                    prover_id,
                    cfg.program,
                    channel.endpoint2(),
                    stream,
                    mem_pool,
                    i,
                );
                prover.run_cuda(pk_gm, stream, mem_pool, i);
            });
        }
    };

    debug!("waiting for stop");
    ctrl_c().await?;
    debug!("Ctrl+C received; shutting down worker");
    shutdown.cancel();
    process::exit(0);
}
