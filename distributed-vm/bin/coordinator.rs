use anyhow::Result;
use clap::Parser;
use distributed_vm::coordinator::{config::CoordinatorConfig, emulator, grpc};
use log::debug;
use pico_perf::common::{bench_field::BenchField, bench_program::PROGRAMS};
use pico_vm::{
    configs::stark_config::bb_poseidon2::BabyBearPoseidon2,
    machine::logger::setup_logger,
    messages::{emulator::EmulatorMsg, gateway::GatewayMsg},
    thread::channel::{DuplexUnboundedChannel, SingleUnboundedChannel},
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

impl From<Args> for CoordinatorConfig {
    fn from(args: Args) -> Self {
        let field = BenchField::from_str(&args.field).unwrap();
        let program = *PROGRAMS.iter().find(|p| p.name == args.program).unwrap();

        Self { field, program }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    setup_logger();

    let cfg = Arc::new(CoordinatorConfig::from(Args::parse()));
    let field = cfg.field;

    // emulator channel for starting the proving process
    let emulator_channel = SingleUnboundedChannel::default();
    // TODO: fix to trggier from a gprc call
    emulator_channel.send(EmulatorMsg::Start).unwrap();

    let (emulator, grpc) = match field {
        BenchField::BabyBear => {
            let gateway_channel = DuplexUnboundedChannel::default();

            let emulator = emulator::run::<BabyBearPoseidon2>(
                cfg,
                emulator_channel.receiver(),
                gateway_channel.endpoint1(),
            );
            let grpc = grpc::run(gateway_channel.endpoint2());

            // wait for CTRL + C then close the channels to exit
            debug!("waiting for stop");
            ctrl_c().await.unwrap();

            gateway_channel.endpoint1().send(GatewayMsg::Exit).unwrap();
            gateway_channel.endpoint2().send(GatewayMsg::Exit).unwrap();

            (emulator, grpc)
        }
        BenchField::KoalaBear => {
            let gateway_channel = DuplexUnboundedChannel::default();

            let emulator = emulator::run(
                cfg,
                emulator_channel.receiver(),
                gateway_channel.endpoint1(),
            );
            let grpc = grpc::run(gateway_channel.endpoint2());

            // wait for CTRL + C then close the channels to exit
            debug!("waiting for stop");
            ctrl_c().await.unwrap();

            gateway_channel.endpoint1().send(GatewayMsg::Exit).unwrap();
            gateway_channel.endpoint2().send(GatewayMsg::Exit).unwrap();

            (emulator, grpc)
        }
    };

    emulator_channel.send(EmulatorMsg::Stop).unwrap();

    let _ = tokio::join!(emulator, grpc);

    Ok(())
}
