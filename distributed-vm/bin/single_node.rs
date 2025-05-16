use anyhow::Result;
use clap::Parser;
use distributed_vm::{
    coordinator::emulator,
    gateway,
    messages::{emulator::EmulatorMsg, gateway::GatewayMsg},
    single_node::config::SingleNodeConfig,
    timeline::{InMemStore, Stage, Timeline, TimelineStore, COORD_TL_ID},
    worker::prover::{Prover, ProverRunner},
};
use dotenvy::dotenv;
use futures::future::join_all;
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
    iter::{current_num_threads, ThreadPoolBuilder},
    machine::logger::setup_logger,
    thread::channel::{DuplexUnboundedChannel, SingleUnboundedChannel},
};
use std::sync::Arc;
use tokio::signal::ctrl_c;

#[tokio::main]
async fn main() -> Result<()> {
    initial_chips_2();
    initial_chips_load();

    ThreadPoolBuilder::new()
        .num_threads(num_cpus::get())
        .build_global()
        .expect("Failed to build global Rayon thread pool");

    println!("Initialized Rayon with {} threads", current_num_threads());

    let timeline_store = Arc::new(InMemStore::default());

    let coord_tl = Timeline::new(COORD_TL_ID, COORD_TL_ID);
    timeline_store.insert_active(COORD_TL_ID, coord_tl);
    setup_logger();

    dotenv().ok();

    let cfg = Arc::new(SingleNodeConfig::parse());
    debug!("starting with config: {:?}", cfg);

    // emulator channel for starting the proving process
    let start_channel = SingleUnboundedChannel::default();
    start_channel.send(EmulatorMsg::Start)?;

    let handles = match cfg.field {
        BenchField::BabyBear => {
            let emulator_gateway_channel = SingleUnboundedChannel::default();
            let gateway_worker_channel = DuplexUnboundedChannel::default();

            // start gateway
            let gateway = gateway::run(
                true,
                timeline_store.clone(),
                emulator_gateway_channel.receiver(),
                gateway_worker_channel.endpoint1(),
            );

            // start provers
            let mut provers: Vec<_> = (0..cfg.prover_count)
                .enumerate()
                .map(|(i, _)| {
                    create_ctx(i);
                    let sync_pool = get_global_mem_pool(i);
                    let mem_pool = &sync_pool.0;

                    create_stream(i);
                    let sync_stream = get_global_stream_pool(i);
                    let stream = &sync_stream.0;

                    let prover_id = format!("prover-{i}");
                    let worker_endpoint = gateway_worker_channel.endpoint2().clone_inner();
                    // let prover =
                    //     Prover::<BabyBearPoseidon2>::new(prover_id, cfg.program, worker_endpoint);
                    let (prover, pk_gm) = Prover::<BabyBearPoseidon2>::new_cuda(
                        prover_id,
                        cfg.program,
                        worker_endpoint,
                        stream,
                        mem_pool,
                        i,
                    );
                    prover.run()
                })
                .collect();

            let mut coord_tl = timeline_store.remove_active(&COORD_TL_ID).unwrap();
            coord_tl.mark(Stage::CoordinatorStarted);
            timeline_store.insert_active(COORD_TL_ID, coord_tl);

            // start emulator
            let emulator = emulator::run::<BabyBearPoseidon2>(
                cfg.program,
                start_channel.receiver(),
                emulator_gateway_channel.sender(),
            );

            // wait for CTRL + C then close the channels to exit
            debug!("waiting for stop");
            ctrl_c().await?;

            emulator_gateway_channel.send(GatewayMsg::Exit)?;
            gateway_worker_channel.endpoint1().send(GatewayMsg::Exit)?;
            gateway_worker_channel.endpoint2().send(GatewayMsg::Exit)?;

            provers.extend([emulator, gateway]);
            provers
        }
        BenchField::KoalaBear => {
            let emulator_gateway_channel = SingleUnboundedChannel::default();
            let gateway_worker_channel = DuplexUnboundedChannel::default();

            // start gateway
            let gateway = gateway::run(
                true,
                timeline_store.clone(),
                emulator_gateway_channel.receiver(),
                gateway_worker_channel.endpoint1(),
            );

            // start provers
            let mut provers: Vec<_> = (0..cfg.prover_count)
                .enumerate()
                .map(|(i, _)| {
                    create_ctx(i);
                    let sync_pool = get_global_mem_pool(i);
                    let mem_pool = &sync_pool.0;

                    create_stream(i);
                    let sync_stream = get_global_stream_pool(i);
                    let stream = &sync_stream.0;

                    let prover_id = format!("prover-{i}");
                    let worker_endpoint = gateway_worker_channel.endpoint2().clone_inner();

                    // let prover =
                    //     Prover::<KoalaBearPoseidon2>::new(prover_id, cfg.program, worker_endpoint);
                    // prover.run()

                    let (prover, pk_gm) = Prover::<KoalaBearPoseidon2>::new_cuda(
                        prover_id,
                        cfg.program,
                        worker_endpoint,
                        stream,
                        mem_pool,
                        i,
                    );
                    prover.run_cuda(pk_gm, stream, mem_pool, i)
                })
                .collect();

            let mut coord_tl = timeline_store.remove_active(&COORD_TL_ID).unwrap();
            coord_tl.mark(Stage::CoordinatorStarted);
            timeline_store.insert_active(COORD_TL_ID, coord_tl);

            // start emulator
            let emulator = emulator::run::<KoalaBearPoseidon2>(
                cfg.program,
                start_channel.receiver(),
                emulator_gateway_channel.sender(),
            );

            // wait for CTRL + C then close the channels to exit
            debug!("waiting for stop");
            ctrl_c().await?;

            emulator_gateway_channel.send(GatewayMsg::Exit)?;
            gateway_worker_channel.endpoint1().send(GatewayMsg::Exit)?;
            gateway_worker_channel.endpoint2().send(GatewayMsg::Exit)?;

            provers.extend([emulator, gateway]);
            provers
        }
    };

    start_channel.send(EmulatorMsg::Stop)?;

    join_all(handles).await;

    Ok(())
}
