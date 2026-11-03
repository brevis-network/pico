//! What the pipeline's instruments cost per call: one stage-ledger line with the facts a replay
//! writes, and one span that is recorded. Built without `stage-ledger`, as a shipped build is, the
//! calls compile to nothing. Built with it, run it with `MLE_LEDGER` and `MLE_SPANS` unset and
//! again with them set, then multiply by the calls a chunk makes (the lines per chunk in a run's
//! ledger, the spans per chunk in its CSV).
//!
//! A span shorter than a microsecond is not recorded, so each span here is held open for
//! `SPAN_US`, and the same loop holding nothing open is subtracted: `ROUNDS` interleaved pairs of
//! the two loops, and the median difference, since one pair's drift is as large as the cost off.
//! `spans_recorded` says how many reached the store: every one with `MLE_SPANS` set, none without.
//! One thread opens them, so the store's mutex is uncontended, as it is in a pipeline whose threads
//! open a few spans per chunk. A span opened inside another pushes twice, so count a CSV's rows,
//! not its guards.
//!
//! ```bash
//! cargo run --release -p pico-vm --example ledger_emit_cost
//! cargo run --release -p pico-vm --features stage-ledger --example ledger_emit_cost
//! MLE_LEDGER=/tmp/cost.jsonl MLE_SPANS=/tmp/cost.csv cargo run --release -p pico-vm --features stage-ledger --example ledger_emit_cost
//! ```
//!
//! Prints one `LEDGER_EMIT_COST` line.

use std::time::{Duration, Instant};

use pico_vm::mle::{
    ledger::{self, At},
    spans::{self, LaneId, Role, WorkKind},
};
use serde_json::json;

const CALLS: usize = 210_000;
const SPAN_US: u64 = 2;
const ROUNDS: usize = 7;
const SPAN_CALLS: usize = CALLS / ROUNDS;

fn hold(us: u64) {
    let until = Instant::now() + Duration::from_micros(us);
    while Instant::now() < until {}
}

fn ns_per_call(start: Instant, calls: usize) -> f64 {
    start.elapsed().as_nanos() as f64 / calls as f64
}

fn main() {
    let window = ledger::open_window(Instant::now(), "aot", "interpreter", 16);
    let lane = LaneId::new(Role::Emulate, 3);
    spans::bind_lane(lane);

    let start = Instant::now();
    for i in 0..CALLS {
        let t0 = Instant::now();
        let t1 = Instant::now();
        ledger::stage(
            "worker.replay",
            At::batch(i % 40, Some((0, 1))),
            lane,
            t0,
            t1,
            || {
                json!({
                    "tid": 3,
                    "cycles": 8_388_608,
                    "records": 1,
                    "events": {
                        "add_events": 1_833_269,
                        "cpu_local_memory_access": 72_881,
                    },
                    "record_bytes": 2_477_705_888u64,
                    "worker_kind": "interpreter",
                    "dispatches": null,
                    "fallback_insns": null,
                    "cycles_per_dispatch": null,
                })
            },
        );
    }
    let stage_ns = ns_per_call(start, CALLS);

    let mut span_ns: Vec<f64> = (0..ROUNDS)
        .map(|round| {
            let start = Instant::now();
            for _ in 0..SPAN_CALLS {
                hold(SPAN_US);
            }
            let bare_ns = ns_per_call(start, SPAN_CALLS);
            let start = Instant::now();
            for i in 0..SPAN_CALLS {
                let _guard = spans::busy(WorkKind::Emulate, Some((round * SPAN_CALLS + i) as u32));
                hold(SPAN_US);
            }
            ns_per_call(start, SPAN_CALLS) - bare_ns
        })
        .collect();
    span_ns.sort_by(f64::total_cmp);
    let recorded = spans::snapshot().len();

    drop(window);
    ledger::finish();
    println!(
        "LEDGER_EMIT_COST stage_ledger={} ledger={} spans={} calls={CALLS} \
         ns_per_stage={stage_ns:.1} ns_per_span={:.1} ns_per_span_min={:.1} ns_per_span_max={:.1} \
         rounds={ROUNDS} span_us={SPAN_US} spans_recorded={recorded}",
        cfg!(feature = "stage-ledger"),
        ledger::enabled(),
        std::env::var_os("MLE_SPANS").is_some(),
        span_ns[ROUNDS / 2],
        span_ns[0],
        span_ns[ROUNDS - 1],
    );
}
