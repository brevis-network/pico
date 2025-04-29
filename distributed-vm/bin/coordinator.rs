use anyhow::Result;
use clap::Parser;
use distributed_vm::{
    coordinator::{config::CoordinatorConfig, emulator, grpc},
    gateway,
};
use dotenvy::dotenv;
use log::debug;
use pico_perf::common::bench_field::BenchField;
use pico_vm::{
    configs::stark_config::{bb_poseidon2::BabyBearPoseidon2, KoalaBearPoseidon2},
    machine::logger::setup_logger,
    messages::emulator::EmulatorMsg,
    thread::channel::{DuplexUnboundedChannel, SingleUnboundedChannel},
};
use std::{process, sync::Arc};
use tokio::signal::ctrl_c;

#[tokio::main]
async fn main() -> Result<()> {
    setup_logger();

    dotenv().ok();

    let cfg = Arc::new(CoordinatorConfig::parse());
    cfg.validate().expect("invalid config");
    debug!("starting with config: {:?}", cfg);

    // emulator channel for starting the proving process
    let start_channel = SingleUnboundedChannel::default();
    // TODO: fix to trggier from a gprc call
    start_channel.send(EmulatorMsg::Start)?;

    match cfg.field {
        BenchField::BabyBear => {
            let emulator_gateway_channel = SingleUnboundedChannel::default();
            let gateway_grpc_channel = DuplexUnboundedChannel::default();

            emulator::run::<BabyBearPoseidon2>(
                cfg.program,
                start_channel.receiver(),
                emulator_gateway_channel.sender(),
            );
            gateway::run(
                false,
                emulator_gateway_channel.receiver(),
                gateway_grpc_channel.endpoint1(),
            );
            grpc::run(gateway_grpc_channel.endpoint2(), &cfg);
        }
        BenchField::KoalaBear => {
            let emulator_gateway_channel = SingleUnboundedChannel::default();
            let gateway_grpc_channel = DuplexUnboundedChannel::default();

            emulator::run::<KoalaBearPoseidon2>(
                cfg.program,
                start_channel.receiver(),
                emulator_gateway_channel.sender(),
            );
            gateway::run(
                false,
                emulator_gateway_channel.receiver(),
                gateway_grpc_channel.endpoint1(),
            );
            grpc::run(gateway_grpc_channel.endpoint2(), &cfg);
        }
    };

    debug!("waiting for stop");
    ctrl_c().await?;
    debug!("Ctrl+C received; shutting down coordinator");
    process::exit(0);
}
