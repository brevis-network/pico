//! Single-node MLE/WHIR prover (KoalaBear; GPU with `cuda`).

use clap::Parser;
use distributed_vm::mle::{self, config::MleSingleNodeConfig};
use pico_vm::machine::logger::setup_logger;

fn main() {
    setup_logger();
    // A panicked worker thread would otherwise hang the run silently: the remaining stages block
    // on channels/barriers that the dead thread can no longer feed. Print the panic, then take
    // the whole process down so the failure is loud and immediate.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_hook(info);
        std::process::exit(101);
    }));
    // Register the AOT emulation factory when built with `aot-emulator` (no-op otherwise).
    distributed_vm::init_optional_aot();
    let cfg = MleSingleNodeConfig::parse();

    // `MLE_REPEAT=N` proves the same block N times, sequentially, in one process. A single run only
    // measures the first block, which pays every process-wide one-shot cost (mem-pool high-water
    // mark, nvrtc JIT, event-buffer pool, background pool filler). Iteration 2+ is what a long-
    // running prover's steady state looks like -- compare the per-iteration "MLE bench:" lines.
    let repeat = std::env::var("MLE_REPEAT")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n >= 1)
        .unwrap_or(1);

    let repeating = repeat > 1;
    for i in 1..=repeat {
        if repeating {
            tracing::info!(target: "bench", "MLE repeat: iteration {i}/{repeat} starting");
        }
        mle::run(&cfg, repeating.then_some(i));
        if repeating {
            tracing::info!(target: "bench", "MLE repeat: iteration {i}/{repeat} done");
        }
    }
}
