use anyhow::Result;
use clap::Parser;
use distributed_vm::{
    coordinator::{config::CoordinatorConfig, emulator},
    worker::riscv,
};
use log::debug;
use pico_perf::common::{bench_field::BenchField, bench_program::PROGRAMS};
use pico_vm::{
    configs::{
        config::StarkGenericConfig,
        stark_config::{bb_poseidon2::BabyBearPoseidon2, kb_poseidon2::KoalaBearPoseidon2},
    },
    machine::logger::setup_logger,
    messages::{emulator::EmulatorMsg, riscv::RiscvMsg},
    thread::channel::{DuplexUnboundedChannel, SingleUnboundedChannel},
};
use std::{str::FromStr, sync::Arc};
use tokio::signal::ctrl_c;

#[tokio::main]
async fn main() -> Result<()> {
    setup_logger();

    // gupeng
    todo!()
}
