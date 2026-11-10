//! Every serial check on the record-parity guests, on one emulation of each run.
//!
//! Each run of each guest in `GUESTS` is emulated once by the serial interpreter through the
//! history sink, and each record, as it comes, goes to every check that reads one:
//!
//! - `history`: the execution history against the program it ran;
//! - `header_rows`: the fill header's derived rows against the host's accessors, and on fib
//!   against its event streams;
//! - `counting` (`--features test-utils`): the history's counts and public values per chunk
//!   against the counting sink's, which a second emulation of the run takes, as it needs a sink of
//!   its own;
//! - `record_golden`: the record against `record_digests.txt`, and the syscalls the guests reach
//!   against `unreached_syscalls.txt`;
//! - `byte_scatter`: the byte chip's trace written lookup by lookup against the per-row scan;
//! - `trace_golden` (five guests): every chip's main trace against `trace_digests.txt`.
//!
//! No run's records are held, and none is cloned: a record of the BLS12-381 field or the SHA-256
//! guest runs to gigabytes. The checks that borrow a record run first. The record golden then
//! takes its precompile events out and puts them back, and sorts every local-memory window in
//! place, the chunk's and each precompile event's, which is the sort the trace golden's traces are
//! pinned after. The extra-record pass then consumes the record; the byte scatter reads the
//! augmented record and the trace golden consumes it. So each golden reads the record it read on
//! an emulation of its own, and a difference would show as a changed line.
//!
//! Each guest prints one line of the seconds its emulation and each check took, the extra-record
//! pass among them; the counting check's include the emulation it takes of its own.
//!
//! A test per guest, so the guests run in parallel and a name filter picks some; each guest's test
//! compares and rewrites its own lines of the golden files. What no one guest decides is in
//! `every_guest_together`: every syscall reached by some guest or listed, and every count the
//! counting sink takes taken by some guest. Each guest's checks run once per process, in whichever
//! test asks first, so that test waits on the guests' tests, or runs one that none has started.
//!
//! The variables in `RECORD_SHAPING_VARS` change where the deferred records split and how
//! precompile windows merge; the goldens are written with each at its default, so every test
//! removes them before anything emulates.
//!
//! To rewrite the files after an intended change:
//!   RECORD_DIGESTS_REWRITE=1 cargo test --release -p pico-vm --test serial_checks
//! rewrites `record_digests.txt`, and `unreached_syscalls.txt` once every guest has run;
//!   TRACE_DIGESTS_REWRITE=1 cargo test --release -p pico-vm --test serial_checks
//! rewrites `trace_digests.txt`.

use std::{
    any::Any,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::{Once, OnceLock},
    time::{Duration, Instant},
};

use pico_vm::{
    instances::chiptype::riscv_chiptype::RiscvChipType,
    mle::machine::riscv::{augment_record, Kb},
};

#[path = "common/chip_coverage.rs"]
mod chip_coverage;
#[path = "common/golden.rs"]
mod golden;
// Only the guests, their runs and the builders: the comparison in there is between two arms.
#[allow(dead_code)]
#[path = "common/record_parity.rs"]
mod record_parity;
// Not `history_records`: the stream reads the emulator's end state.
#[allow(dead_code)]
#[path = "common/trace_source.rs"]
mod trace_source;

#[path = "serial_checks/byte_scatter.rs"]
mod byte_scatter;
#[cfg(feature = "test-utils")]
#[path = "serial_checks/counting.rs"]
mod counting;
#[path = "serial_checks/header_rows.rs"]
mod header_rows;
#[path = "serial_checks/history.rs"]
mod history;
#[path = "serial_checks/record_golden.rs"]
mod record_golden;
#[path = "serial_checks/trace_golden.rs"]
mod trace_golden;

use record_parity::{program, Guest, GUESTS};
use trace_source::history_emulation;

/// Every variable the emulation reads that changes the records it emits. `PICO_GPU_MEM` picks
/// the deferred split thresholds.
const RECORD_SHAPING_VARS: [&str; 6] = [
    "DEFERRED_TAIL_MERGE",
    "MLE_PRECOMPILE_LOCAL_MEM_MERGE",
    "CHUNK_EVENT_LIMIT_SCALE",
    "CHUNK_EVENT_LIMITS_OFF",
    "CHUNK_COMMIT_TAIL_HOLD_OFF",
    "PICO_GPU_MEM",
];

/// Removes `RECORD_SHAPING_VARS`, once per process. Every test calls it first, so no emulation
/// reads them and no test reads the environment while they go.
fn before_any_emulation() {
    static REMOVED: Once = Once::new();
    REMOVED.call_once(|| {
        for var in RECORD_SHAPING_VARS {
            std::env::remove_var(var);
        }
    });
}

/// Wall time by stage of one guest's checks, the emulation first, the rest as each first ran.
struct Timings(Vec<(&'static str, Duration)>);

impl Timings {
    const EMULATION: &'static str = "emulation";

    fn new() -> Self {
        Self(vec![(Self::EMULATION, Duration::ZERO)])
    }

    fn add(&mut self, stage: &'static str, elapsed: Duration) {
        match self.0.iter_mut().find(|(name, _)| *name == stage) {
            Some((_, total)) => *total += elapsed,
            None => self.0.push((stage, elapsed)),
        }
    }

    /// `work`, its wall time added to `stage`'s.
    fn time<T>(&mut self, stage: &'static str, work: impl FnOnce() -> T) -> T {
        let started = Instant::now();
        let done = work();
        self.add(stage, started.elapsed());
        done
    }

    fn line(&self) -> String {
        self.0
            .iter()
            .map(|(stage, elapsed)| format!("{stage} {:.1}s", elapsed.as_secs_f64()))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

/// What the checks over every guest read of one guest's.
struct Summary {
    reached: record_golden::Reached,
    #[cfg(feature = "test-utils")]
    taken: counting::Taken,
}

/// Each guest's checks, by its index in `GUESTS`, once they have run in this process: the summary,
/// or the failure, which a test asking again fails on rather than running the guest again.
static CHECKED: [OnceLock<Result<Summary, String>>; GUESTS.len()] =
    [const { OnceLock::new() }; GUESTS.len()];

fn panic_message(panic: &(dyn Any + Send)) -> String {
    panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| {
            panic
                .downcast_ref::<&str>()
                .map(|message| message.to_string())
        })
        .unwrap_or_else(|| "a panic with no message".to_string())
}

/// The guest called `name`'s summary, its checks run first unless they have run in this process.
/// Panics if they failed.
fn checked(name: &str) -> &'static Summary {
    before_any_emulation();
    let index = GUESTS
        .iter()
        .position(|guest| guest.name == name)
        .unwrap_or_else(|| panic!("no guest {name}"));
    let outcome = CHECKED[index].get_or_init(|| {
        catch_unwind(AssertUnwindSafe(|| check_guest(&GUESTS[index])))
            .map_err(|panic| panic_message(&*panic))
    });
    match outcome {
        Ok(summary) => summary,
        Err(failure) => panic!("{name} failed its checks: {failure}"),
    }
}

/// Every run of `guest`, emulated once, each record handed to every check in the order the module
/// header gives. Panics listing every check's problems.
fn check_guest(guest: &Guest) -> Summary {
    let started = Instant::now();
    let mut timings = Timings::new();
    let name = guest.name;
    let chips = RiscvChipType::<Kb>::all_chips();
    let mut history = history::Check::default();
    let mut header_rows = header_rows::Check::new(name == "fib");
    #[cfg(feature = "test-utils")]
    let mut counting = counting::Check::default();
    let mut records = record_golden::Check::new(name);
    let mut bytes = byte_scatter::Check::default();
    let mut traces = trace_golden::Check::of(name);

    for (run_index, run) in guest.runs().into_iter().enumerate() {
        let program = program(guest.elf);
        let (label, bytes_label) = (
            format!("{name} @ {}", run.chunk_size),
            format!("{name} run {run_index}"),
        );
        let mut index = 0;
        let mut in_checks = Duration::ZERO;
        let emulating = Instant::now();
        let emulator =
            history_emulation(program.clone(), &run.stdin, run.chunk_size, |mut record| {
                let handed = Instant::now();
                let prefix = format!("{name}\t{}\t{index}", run.chunk_size);
                index += 1;
                timings.time("history", || history.record(&label, &record));
                timings.time("header rows", || header_rows.record(&label, &record));
                #[cfg(feature = "test-utils")]
                timings.time("counting", || counting.record(&record));
                if let Some(traces) = &mut traces {
                    timings.time("trace golden", || traces.history(&record));
                }
                timings.time("record golden", || {
                    records.record(run.chunk_size, &mut record)
                });
                let mut augmented =
                    timings.time("extra-record pass", || augment_record(&chips, record));
                timings.time("byte scatter", || {
                    bytes.record(&bytes_label, &mut augmented)
                });
                if let Some(traces) = &mut traces {
                    timings.time("trace golden", || traces.record(&chips, &prefix, augmented));
                }
                in_checks += handed.elapsed();
            });
        timings.add(
            Timings::EMULATION,
            emulating.elapsed().saturating_sub(in_checks),
        );
        timings.time("history", || history.end_run(&label));
        timings.time("record golden", || {
            records.end_run(run.chunk_size, &emulator)
        });
        // Its guest memory goes before the counting sink's emulation builds its own.
        drop(emulator);
        timings.time("byte scatter", || bytes.end_run(&bytes_label));
        #[cfg(feature = "test-utils")]
        timings.time("counting", || {
            counting.end_run(&label, program, &run.stdin, run.chunk_size)
        });
    }

    let mut problems = Vec::new();
    let mut keep = |check: &str, found: Vec<String>| {
        problems.extend(
            found
                .into_iter()
                .map(|problem| format!("{check}: {problem}")),
        );
    };
    keep("history", history.finish(name));
    keep("header rows", header_rows.finish());
    #[cfg(feature = "test-utils")]
    let (found, taken) = counting.finish();
    #[cfg(feature = "test-utils")]
    keep("counting sink", found);
    let (found, reached) = records.finish();
    keep("record golden", found);
    keep("byte scatter", bytes.finish());
    if let Some(traces) = traces {
        keep("trace golden", traces.finish());
    }
    println!(
        "{name}: {:.1}s in all: {}",
        started.elapsed().as_secs_f64(),
        timings.line()
    );
    for problem in &problems {
        println!("FAIL: {problem}");
    }
    assert!(
        problems.is_empty(),
        "{} problem(s):\n{}",
        problems.len(),
        problems.join("\n")
    );
    Summary {
        reached,
        #[cfg(feature = "test-utils")]
        taken,
    }
}

#[test]
fn fib() {
    checked("fib");
}

#[test]
fn ed25519() {
    checked("ed25519");
}

#[test]
fn poseidon2() {
    checked("poseidon2");
}

#[test]
fn aggregator() {
    checked("aggregator");
}

#[test]
fn bls12381_fp() {
    checked("bls12381-fp");
}

#[test]
fn sha2() {
    checked("sha2");
}

#[test]
fn sha3() {
    checked("sha3");
}

#[test]
fn tiny_keccak() {
    checked("tiny-keccak");
}

#[test]
fn k256() {
    checked("k256");
}

#[test]
fn bn254_fp() {
    checked("bn254-fp");
}

#[test]
fn bls12381_ws() {
    checked("bls12381-ws");
}

#[test]
fn bn254_ws() {
    checked("bn254-ws");
}

/// The checks no one guest decides, over every guest's summary: every syscall the emulator
/// implements is reached by some guest or listed as unreached, and every count the counting sink
/// takes is taken above zero by some guest.
#[test]
fn every_guest_together() {
    let summaries: Vec<(&str, &Summary)> = GUESTS
        .iter()
        .map(|guest| (guest.name, checked(guest.name)))
        .collect();
    record_golden::check_syscall_coverage(summaries.iter().map(|(_, summary)| &summary.reached));
    #[cfg(feature = "test-utils")]
    counting::check_every_count_taken(
        summaries
            .iter()
            .map(|(guest, summary)| (*guest, &summary.taken)),
    );
    #[cfg(not(feature = "test-utils"))]
    println!("the counting sink exists only with --features test-utils: not compared");
}

/// Each golden file holds its guests' lines in the order they run, the way a rewrite writes it:
/// each guest's test compares its own lines, and this the rest of the file.
#[test]
fn the_goldens_hold_each_guests_lines_in_turn() {
    before_any_emulation();
    record_golden::check_file_layout();
    trace_golden::check_file_layout();
}
