//! The snapshot pipeline (`emulate_with_pipeline`) and the one-interpreter path
//! (`emulate_with_opts`) must cut each chunk after the same step, under a leaf cap small enough to
//! cut nearly every chunk.
//!
//! The pipeline's snapshot thread and the serial path's tracing interpreter each decide cuts from
//! their own chunk-split counters. At `chunk_split::DEFAULT_LEAF_CAP` no record-parity guest
//! reaches the leaf arm of `should_split`, so `pipeline_record_parity` never compares the two leaf
//! estimates. The guests here are the field-arithmetic ones, which send the most syscalls per
//! instruction, to exercise the estimate's syscall term.
//!
//! `chunk_split::leaf_cap` reads `CHUNK_LEAF_CAP` once per process, so the cap needs its own test
//! binary.

use std::sync::{Mutex, Once, PoisonError};

use pico_vm::{
    emulator::{
        record::RecordBehavior,
        riscv::{chunk_split::leaf_cap, record::EmulationRecord},
    },
    mle::machine::riscv::{emulate_with_opts_streaming, emulate_with_pipeline_streaming},
};

// Only the guests and the run setup are used here.
#[allow(dead_code)]
#[path = "common/record_parity.rs"]
mod record_parity;
use record_parity::{opts, program, stdin, workers, GUESTS, WHOLE};

/// About 2.9 million leaves above a chunk's charge before its first step (3.4 million), so the leaf
/// arm closes each chunk after some thousands of instructions, long before `WHOLE`'s other limits.
const LEAF_CAP: u64 = 6 << 20;

/// Below this the leaf cap did not cut the run: `WHOLE`'s other limits alone give the field guests
/// 2 and 6 chunks.
const AT_LEAST_CHUNKS: usize = 16;

/// The pipeline takes its snapshot memory from one process-wide pool, so runs go one at a time.
static PIPELINE: Mutex<()> = Mutex::new(());

static SET_CAP: Once = Once::new();

fn set_leaf_cap() {
    SET_CAP.call_once(|| std::env::set_var("CHUNK_LEAF_CAP", LEAF_CAP.to_string()));
    assert_eq!(
        leaf_cap(),
        LEAF_CAP,
        "the leaf cap was read before this binary set it"
    );
}

/// `ends`: the first step's pc, the last step's next pc and clk; none for a chunk without steps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cut {
    chunk_index: usize,
    steps: usize,
    ends: Option<(u64, u64, u64)>,
}

impl Cut {
    fn of(record: &EmulationRecord) -> Self {
        let steps = record.cpu_steps();
        let ends = steps.len().checked_sub(1).map(|last| {
            let last = steps.get(last);
            (steps.get(0).pc, last.next_pc, last.clk)
        });
        Self {
            chunk_index: record.chunk_index(),
            steps: steps.len(),
            ends,
        }
    }
}

/// Runs `elf` down both paths; the pipeline's value comes first in every message.
fn check(label: &str, elf: &[u8], input: &[Vec<u8>]) {
    set_leaf_cap();
    let _one_at_a_time = PIPELINE.lock().unwrap_or_else(PoisonError::into_inner);
    let program = program(elf);
    let stdin = stdin(input);
    let opts = opts(WHOLE);

    let mut pipeline_cuts = Vec::new();
    let pipeline =
        emulate_with_pipeline_streaming(program.clone(), &stdin, opts, workers(), |record| {
            if record.is_cpu_chunk {
                pipeline_cuts.push(Cut::of(&record));
            }
        })
        .unwrap_or_else(|err| panic!("[{label}] emulate_with_pipeline: {err}"));
    let mut serial_cuts = Vec::new();
    let serial = emulate_with_opts_streaming(program, &stdin, opts, |record| {
        if record.is_cpu_chunk {
            serial_cuts.push(Cut::of(&record));
        }
    })
    .unwrap_or_else(|err| panic!("[{label}] emulate_with_opts: {err}"));

    println!(
        "[{label}] leaf cap {LEAF_CAP}: {} vs {} CPU chunk(s), {} vs {} chunk(s), {} vs {} \
         cycle(s)",
        pipeline_cuts.len(),
        serial_cuts.len(),
        pipeline.chunks,
        serial.chunks,
        pipeline.cycles,
        serial.cycles,
    );
    let mut problems = Vec::new();
    if pipeline.chunks != serial.chunks {
        problems.push(format!("chunks: {} vs {}", pipeline.chunks, serial.chunks));
    }
    if pipeline.cycles != serial.cycles {
        problems.push(format!("cycles: {} vs {}", pipeline.cycles, serial.cycles));
    }
    // A cut that moves moves every one after it, so the first is the one to read.
    let differing = (0..pipeline_cuts.len().max(serial_cuts.len()))
        .filter(|&i| pipeline_cuts.get(i) != serial_cuts.get(i))
        .collect::<Vec<_>>();
    if let Some(&first) = differing.first() {
        problems.push(format!(
            "CPU chunk {first} of {} is cut differently, {:?} vs {:?}, and {} CPU chunk(s) in all",
            pipeline_cuts.len(),
            pipeline_cuts.get(first),
            serial_cuts.get(first),
            differing.len()
        ));
    }
    if pipeline_cuts.len() < AT_LEAST_CHUNKS {
        problems.push(format!(
            "{} CPU chunk(s), short of the {AT_LEAST_CHUNKS} that show the leaf cap cut the run",
            pipeline_cuts.len()
        ));
    }
    for problem in &problems {
        println!("[{label}] FAIL: {problem}");
    }
    assert!(
        problems.is_empty(),
        "[{label}] the serial path cuts chunks where the pipeline does not, or the comparison is \
         vacuous; the pipeline's value first:\n{}",
        problems.join("\n")
    );
}

fn check_guest(name: &str) {
    let guest = GUESTS
        .iter()
        .find(|guest| guest.name == name)
        .unwrap_or_else(|| panic!("no guest {name}"));
    let run = guest.runs().into_iter().next().expect("a run");
    check(name, guest.elf, &run.stdin);
}

#[test]
fn bn254_fp() {
    check_guest("bn254-fp");
}

#[test]
fn bls12381_fp() {
    check_guest("bls12381-fp");
}

/// The smallest block input in `perf/bench_data/rv64/`.
#[test]
#[ignore = "minutes of emulation down each path; needs perf/bench_data/rv64/reth-elf"]
fn reth() {
    let data = concat!(env!("CARGO_MANIFEST_DIR"), "/../perf/bench_data/rv64/");
    let read = |file: &str| {
        std::fs::read(format!("{data}{file}")).unwrap_or_else(|e| panic!("{data}{file}: {e}"))
    };
    check(
        "reth-18884864",
        &read("reth-elf"),
        &[read("reth-18884864.bin")],
    );
}
