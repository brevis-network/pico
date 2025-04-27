use anyhow::Result;
use clap::Parser;
use distributed_vm::{
    coordinator::{config::CoordinatorConfig, emulator, grpc},
    gateway,
};
use dotenvy::dotenv;
use futures::future::join_all;
use log::debug;
use pico_perf::common::bench_field::BenchField;
use pico_vm::{
    configs::stark_config::{bb_poseidon2::BabyBearPoseidon2, KoalaBearPoseidon2},
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

    let cfg = Arc::new(CoordinatorConfig::parse());
    debug!("starting with config: {:?}", cfg);

    // emulator channel for starting the proving process
    let start_channel = SingleUnboundedChannel::default();
    // TODO: fix to trggier from a gprc call
    start_channel.send(EmulatorMsg::Start)?;

    let handles = match cfg.field {
        BenchField::BabyBear => {
            let emulator_gateway_channel = SingleUnboundedChannel::default();
            let gateway_grpc_channel = DuplexUnboundedChannel::default();

            let emulator = emulator::run::<BabyBearPoseidon2>(
                cfg.program,
                start_channel.receiver(),
                emulator_gateway_channel.sender(),
            );
            let gateway = gateway::run(
                false,
                emulator_gateway_channel.receiver(),
                gateway_grpc_channel.endpoint1(),
            );
            let grpc = grpc::run(gateway_grpc_channel.endpoint2(), cfg.grpc_addr);

            // wait for CTRL + C then close the channels to exit
            debug!("waiting for stop");
            ctrl_c().await?;

            emulator_gateway_channel.send(GatewayMsg::Exit)?;
            gateway_grpc_channel.endpoint1().send(GatewayMsg::Exit)?;
            gateway_grpc_channel.endpoint2().send(GatewayMsg::Exit)?;

            vec![emulator, gateway, grpc]
        }
        BenchField::KoalaBear => {
            let emulator_gateway_channel = SingleUnboundedChannel::default();
            let gateway_grpc_channel = DuplexUnboundedChannel::default();

            let emulator = emulator::run::<KoalaBearPoseidon2>(
                cfg.program,
                start_channel.receiver(),
                emulator_gateway_channel.sender(),
            );
            let gateway = gateway::run(
                false,
                emulator_gateway_channel.receiver(),
                gateway_grpc_channel.endpoint1(),
            );
            let grpc = grpc::run(gateway_grpc_channel.endpoint2(), cfg.grpc_addr);

            // wait for CTRL + C then close the channels to exit
            debug!("waiting for stop");
            ctrl_c().await?;

            emulator_gateway_channel.send(GatewayMsg::Exit)?;
            gateway_grpc_channel.endpoint1().send(GatewayMsg::Exit)?;
            gateway_grpc_channel.endpoint2().send(GatewayMsg::Exit)?;

            vec![emulator, gateway, grpc]
        }
    };

    start_channel.send(EmulatorMsg::Stop)?;

    join_all(handles).await;

    Ok(())
}
