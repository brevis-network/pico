//! EthProofs single-node MLE/WHIR prover (KoalaBear; GPU with `cuda`).
//!
//! Blocks arrive over gRPC from RSP; see `distributed_vm::mle::ethproofs`.

use clap::Parser;
use distributed_vm::mle::ethproofs::{self, MleEthProofsConfig};
use pico_vm::machine::logger::setup_logger;

fn main() {
    setup_logger();
    // A panicked worker thread would otherwise hang the run silently: the remaining stages block
    // on channels/barriers that the dead thread can no longer feed. Print the panic, then take the
    // whole process down so the failure is loud and immediate.
    //
    // It matters more here than in the benchmark entry point: a silently hung prover keeps its
    // gRPC port open and keeps answering `CheckHealth`, so from RSP's side -- and from any
    // liveness check that only probes the port -- a dead prover looks exactly like a busy one.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_hook(info);
        std::process::exit(101);
    }));
    // Register the AOT emulation factory when built with `aot-emulator` (no-op otherwise).
    distributed_vm::init_optional_aot();
    ethproofs::run(&MleEthProofsConfig::parse());
}
