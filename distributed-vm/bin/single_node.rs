use anyhow::Result;
use clap::Parser;
use distributed_vm::{
    coordinator::emulator,
    gateway,
    single_node::config::SingleNodeConfig,
    worker::prover::{Prover, ProverRunner},
};
use dotenvy::dotenv;
use futures::future::join_all;
use log::debug;
use pico_perf::common::bench_field::BenchField;
use pico_vm::{
    configs::stark_config::{BabyBearPoseidon2, KoalaBearPoseidon2},
    machine::logger::setup_logger,
    messages::{emulator::EmulatorMsg, gateway::GatewayMsg},
    thread::channel::{DuplexUnboundedChannel, SingleUnboundedChannel},
};
use std::sync::Arc;
use tokio::signal::ctrl_c;

#[tokio::main]
async fn main() -> Result<()> {
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
            gateway_worker_channel
                .endpoint2()
                .send(GatewayMsg::RequestTask)?;

            let emulator = emulator::run::<BabyBearPoseidon2>(
                cfg.program,
                start_channel.receiver(),
                emulator_gateway_channel.sender(),
            );
            let gateway = gateway::run(
                emulator_gateway_channel.receiver(),
                gateway_worker_channel.endpoint1(),
            );
            let prover =
                Prover::<BabyBearPoseidon2>::new(cfg.program, gateway_worker_channel.endpoint2());
            let prover = prover.run();

            // wait for CTRL + C then close the channels to exit
            debug!("waiting for stop");
            ctrl_c().await?;

            emulator_gateway_channel.send(GatewayMsg::Exit)?;
            gateway_worker_channel.endpoint1().send(GatewayMsg::Exit)?;
            gateway_worker_channel.endpoint2().send(GatewayMsg::Exit)?;

            vec![emulator, gateway, prover]
        }
        BenchField::KoalaBear => {
            let emulator_gateway_channel = SingleUnboundedChannel::default();
            let gateway_worker_channel = DuplexUnboundedChannel::default();
            gateway_worker_channel
                .endpoint2()
                .send(GatewayMsg::RequestTask)?;

            let emulator = emulator::run::<KoalaBearPoseidon2>(
                cfg.program,
                start_channel.receiver(),
                emulator_gateway_channel.sender(),
            );
            let gateway = gateway::run(
                emulator_gateway_channel.receiver(),
                gateway_worker_channel.endpoint1(),
            );
            let prover =
                Prover::<KoalaBearPoseidon2>::new(cfg.program, gateway_worker_channel.endpoint2());
            let prover = prover.run();

            // wait for CTRL + C then close the channels to exit
            debug!("waiting for stop");
            ctrl_c().await?;

            emulator_gateway_channel.send(GatewayMsg::Exit)?;
            gateway_worker_channel.endpoint1().send(GatewayMsg::Exit)?;
            gateway_worker_channel.endpoint2().send(GatewayMsg::Exit)?;

            vec![emulator, gateway, prover]
        }
    };

    start_channel.send(EmulatorMsg::Stop)?;

    join_all(handles).await;

    Ok(())
}
