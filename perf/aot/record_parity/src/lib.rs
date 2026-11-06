//! The AOT snapshot thread against the interpreter's, record by record.
//!
//! `emulate_with_pipeline` runs one snapshot thread and replays its snapshots into the records on
//! interpreter workers. Run once with the interpreter on the snapshot thread and once with the code
//! generated into `aot-generated/`, under the same options and worker count, it must give the same
//! output: the workers are interpreters both times, so any difference is the AOT snapshot thread's.
//! `vm/tests/common/record_parity.rs`, compiled in here by path, holds the guests, their runs and
//! the comparison.
//!
//! A process holds one AOT program and every generated crate is named `pico-aot-dispatch`, so this
//! crate is built once per guest, against that guest's generated crates: `perf/aot/record_parity.sh`
//! generates, builds, runs and restores the committed stub, one guest at a time. The guest is the
//! one whose ELF digest the generated program carries. The bootstrap stub fails, and so does code
//! generated from an ELF not in [`GUESTS`].
//!
//! An AOT arm that interprets every block passes every comparison, so a run also fails unless the
//! AOT snapshot thread entered compiled blocks (`AotEmulatorCore::compiled_block_dispatches`).
//!
//! A second pass compares the AOT snapshot thread's own records, its sink on ([`emitting`]), and
//! reads per chunk how much of it compiled code ran. [`check_at_scale`] runs that pass on any
//! guest and input at a production chunk size (the `emitting_at_scale` binary), where the per-chunk
//! bounds apply.
//!
//! [`check_stub_code`] is the positive control for the AOT core's own records ([`emitting`]): the
//! bootstrap stub's code, registered under fib's digest, interprets every chunk, and its records
//! still have to be the interpreter's. It needs no generated code, so any build of this crate runs
//! it.
//!
//! A third pass runs the pipeline's replay workers as AOT cores on the program's recording blocks
//! (`ReplayWorkers::Aot`) against interpreter workers, both on the AOT snapshot thread and with the
//! same worker count, and compares the records the pipeline hands back. Records alone cannot show
//! which engine replayed a chunk, so the pass reads each chunk's `worker.replay` ledger line
//! ([`replay`]): the engine, the compiled blocks the worker entered, the instructions its fallback
//! ran, and those its recording bodies ran, which with the fallback's must cover the chunk.
//! [`check_stub_replay`] is that pass's control: the stub's code in the workers must read
//! all-fallback on every chunk and still give the interpreter workers' records.
//!
//! `AOT_PARITY_REPLAY`, if set, must be `aot`.
//!
//! `AOT_PARITY_WORKERS` sets the worker count; unset, it is four, or the core count if lower.

use std::{
    cell::Cell,
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicU64, Ordering},
        OnceLock,
    },
};

use pico_aot_runtime::{AotEmulatorCore, AotProgram};
use pico_vm::{
    emulator::{
        opts::{ReplayWorkers, SnapshotMainMode},
        riscv::record_digest::{field_digests, is_compared, FieldDigest},
    },
    mle::machine::riscv::{
        emulate_with_pipeline, emulate_with_pipeline_streaming, EmulationOutput,
    },
};
use sha2::{Digest, Sha256};

mod chain_diff;
pub mod emitting;
pub mod replay;

#[path = "../../../../vm/tests/common/record_parity.rs"]
mod record_parity;
use record_parity::{check_guest, Arm, Guest, GUESTS};

/// Refuses an `AOT_PARITY_REPLAY` other than `aot`.
fn check_replay_engine() {
    match std::env::var("AOT_PARITY_REPLAY").as_deref() {
        Err(_) | Ok("aot") => {}
        Ok("aot-recorder") => panic!(
            "AOT_PARITY_REPLAY=aot-recorder is refused: the AOT workers run the recording blocks \
             as aot; set AOT_PARITY_REPLAY=aot or leave it unset"
        ),
        Ok(other) => panic!("AOT_PARITY_REPLAY={other:?} is not aot"),
    }
}

fn workers() -> NonZeroUsize {
    match std::env::var("AOT_PARITY_WORKERS") {
        Ok(raw) => raw.trim().parse().unwrap_or_else(|_| {
            panic!("AOT_PARITY_WORKERS={raw:?} is not a positive worker count")
        }),
        Err(_) => record_parity::workers(),
    }
}

/// Compiled blocks the current AOT run has entered.
static DISPATCHES: AtomicU64 = AtomicU64::new(0);

/// The generated program, registered in its place: the same digest, stamp and code, reporting
/// after every batch how many compiled blocks its run has entered, and its recording entry point,
/// which only replay workers run; without one, the pipeline refuses AOT workers.
static COUNTED: AotProgram = {
    let counted = AotProgram::stamped(
        pico_aot_dispatch::AOT.elf_sha256(),
        pico_aot_dispatch::AOT.codegen_stamp(),
        run_counted,
    );
    match pico_aot_dispatch::AOT.record_entry() {
        Some(run_record) => counted.with_recorder(run_record),
        None => counted,
    }
};

fn run_counted(emu: &mut AotEmulatorCore) -> Result<(), String> {
    let result = emitting::run_emitting(emu, |emu| pico_aot_dispatch::AOT.run(emu));
    DISPATCHES.store(emu.compiled_block_dispatches(), Ordering::Relaxed);
    result
}

fn hex(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Compares the AOT snapshot thread with the interpreter's on every run of the guest
/// `aot-generated/` was generated from, first as it runs today, handing states to interpreter
/// workers, then with its sink on and its own records compared ([`emitting`]). Prints one line per
/// run and every problem found, and panics if there was any.
pub fn check_generated_guest() {
    println!(
        "recorder check: {}",
        if pico_aot_runtime::RECORDER_CHECK {
            "on, every direct row checked against the generic close"
        } else {
            "off"
        }
    );
    let generated = &pico_aot_dispatch::AOT;
    assert!(
        !generated.is_stub(),
        "aot-generated/ holds the bootstrap stub, which has no compiled code; \
         perf/aot/record_parity.sh generates a guest's crates and runs this test against them"
    );
    let digest = generated.elf_sha256();
    let guest = GUESTS
        .iter()
        .find(|guest| <[u8; 32]>::from(Sha256::digest(guest.elf)) == digest)
        .unwrap_or_else(|| {
            panic!(
                "aot-generated/ was generated from ELF {}, which is none of {:?}",
                hex(&digest),
                GUESTS.map(|guest| guest.name)
            )
        });
    check_replay_engine();
    // Before any pipeline run: the ledger reads its path once.
    let ledger = replay::Ledger::start();
    if let Err(err) = pico_aot_runtime::register(&COUNTED) {
        panic!("register the generated program: {err}");
    }

    let workers = workers();
    check_guest(
        guest,
        workers,
        [
            Arm {
                name: "interpreter",
                emulate: &|program, stdin, opts, each| {
                    emulate_with_pipeline_streaming(program, stdin, opts, workers, each)
                },
            },
            Arm {
                name: "AOT",
                emulate: &|program, stdin, opts, each| {
                    DISPATCHES.store(0, Ordering::Relaxed);
                    let aot = opts.with_snapshot_main(SnapshotMainMode::Aot);
                    emulate_with_pipeline_streaming(program, stdin, aot, workers, each)
                },
            },
        ],
        |problems| {
            let dispatches = DISPATCHES.load(Ordering::Relaxed);
            if dispatches == 0 {
                problems.push(
                    "the AOT snapshot thread entered no compiled block, so it interpreted the run"
                        .to_string(),
                );
            }
            format!(
                "; {dispatches} compiled-block dispatch(es) under ELF {}",
                hex(&digest)
            )
        },
    );
    check_guest(
        guest,
        workers,
        [
            Arm {
                name: "interpreter",
                emulate: &|program, stdin, opts, each| {
                    emulate_with_pipeline_streaming(program, stdin, opts, workers, each)
                },
            },
            Arm {
                name: "AOT, emitting",
                // Whole, as the splice needs the workers' records beside the AOT core's.
                emulate: &|program, stdin, opts, _| {
                    emitting::emulate(program, stdin, opts, workers)
                },
            },
        ],
        |problems| emitting::audit(emitting::Expect::Compiled, problems),
    );
    check_replay_workers(guest, &ledger, replay::Expect::Compiled);
    ledger.remove();
}

/// Runs every run of `guest` with the replay workers as interpreters and as AOT cores on the
/// recording blocks, both on an AOT snapshot thread, and compares the records. The two arms differ
/// in `replay_workers` alone.
fn check_replay_workers(guest: &Guest, ledger: &replay::Ledger, expect: replay::Expect) {
    let workers = workers();
    let totals = [Cell::new((0, 0)), Cell::new((0, 0))];
    check_guest(
        guest,
        workers,
        [
            Arm {
                name: "interpreter workers",
                emulate: &|program, stdin, opts, each| {
                    let opts = opts.with_snapshot_main(SnapshotMainMode::Aot);
                    ledger
                        .arm(|| {
                            emulate_with_pipeline_streaming(program, stdin, opts, workers, each)
                        })
                        .inspect(|output| {
                            totals[0].set((output.chunks, output.cycles));
                        })
                },
            },
            Arm {
                name: "AOT workers",
                emulate: &|program, stdin, opts, each| {
                    let opts = opts
                        .with_snapshot_main(SnapshotMainMode::Aot)
                        .with_replay_workers(ReplayWorkers::Aot);
                    ledger
                        .arm(|| {
                            emulate_with_pipeline_streaming(program, stdin, opts, workers, each)
                        })
                        .inspect(|output| {
                            totals[1].set((output.chunks, output.cycles));
                        })
                },
            },
        ],
        |problems| {
            ledger.audit(
                expect,
                pico_aot_runtime::RECORDER_CHECK,
                totals.each_ref().map(Cell::get),
                problems,
            )
        },
    );
}

/// The bootstrap stub's code under fib's digest, writing records when the emitting arm asks, with
/// a recording entry point that has no recording body, so the fallback runs every instruction.
fn stub_code() -> &'static AotProgram {
    static PROGRAM: OnceLock<AotProgram> = OnceLock::new();
    PROGRAM.get_or_init(|| {
        AotProgram::stamped(
            Sha256::digest(record_parity::FIB_ELF).into(),
            AotProgram::CODEGEN_STAMP,
            |emu| emitting::run_emitting(emu, |emu| AotProgram::STUB.run(emu)),
        )
        .with_recorder(|emu| emu.run_record_blocks(|_| None))
    })
}

/// Compares fib's records from the bootstrap stub's code, which interprets every chunk, with the
/// interpreter's, prints one line per run and every problem found, and panics if there was any.
pub fn check_stub_code() {
    if let Err(err) = pico_aot_runtime::register(stub_code()) {
        panic!("register the stub's code under fib's digest: {err}");
    }
    let fib = GUESTS
        .iter()
        .find(|guest| guest.name == "fib")
        .expect("fib is a guest");
    let workers = workers();
    check_guest(
        fib,
        workers,
        [
            Arm {
                name: "interpreter",
                emulate: &|program, stdin, opts, each| {
                    emulate_with_pipeline_streaming(program, stdin, opts, workers, each)
                },
            },
            Arm {
                name: "the stub's code, emitting",
                emulate: &|program, stdin, opts, _| {
                    emitting::emulate(program, stdin, opts, workers)
                },
            },
        ],
        |problems| emitting::audit(emitting::Expect::AllFallback, problems),
    );
}

/// The control of the third pass: the bootstrap stub's code under fib's digest, in the replay
/// workers. Every chunk has to read all-fallback (no compiled block entered, every instruction
/// interpreted by the worker's fallback), and the records still have to be the interpreter
/// workers'. Prints one line per run and every problem found, and panics if there was any.
pub fn check_stub_replay() {
    check_replay_engine();
    let ledger = replay::Ledger::start();
    if let Err(err) = pico_aot_runtime::register(stub_code()) {
        panic!("register the stub's code under fib's digest: {err}");
    }
    let fib = GUESTS
        .iter()
        .find(|guest| guest.name == "fib")
        .expect("fib is a guest");
    check_replay_workers(fib, &ledger, replay::Expect::AllFallback);
    ledger.remove();
}

/// What [`check_at_scale`] compares of a run: each record's kind, chunk index, public values and
/// `field_digests` rows, and the run's committed bytes, cycles and chunk count. Taken before the
/// other arm runs: at production chunk size one arm's records alone are gigabytes.
struct Reduced {
    records: Vec<(bool, usize, String, Vec<FieldDigest>)>,
    committed_bytes: Vec<u8>,
    cycles: u64,
    chunks: u32,
}

fn reduced(output: EmulationOutput) -> Reduced {
    Reduced {
        records: output
            .records
            .iter()
            .map(|record| {
                (
                    record.is_cpu_chunk,
                    pico_vm::emulator::record::RecordBehavior::chunk_index(record),
                    format!("{:?}", record.public_values),
                    field_digests(record),
                )
            })
            .collect(),
        committed_bytes: output.committed_bytes,
        cycles: output.cycles,
        chunks: output.chunks,
    }
}

/// The emitting pass on the guest `aot-generated/` was generated from, `elf`, with `input` its one
/// stdin element and `chunk_size` a production chunk size: records equal to the interpreter's on
/// every chunk, and the per-chunk bounds of [`emitting::Expect::CompiledAtScale`]. Prints every
/// difference, the per-chunk table and a verdict line, and returns the number of problems.
///
/// Not through `check_guest`, whose guests and runs are fixed: this one takes its guest and input
/// from the caller, such as a reth block. `EMITTING_DIFF_DUMP` set prints why the first record
/// whose local-memory chain differs differs (`chain_diff`).
pub fn check_at_scale(elf: &[u8], input: Vec<u8>, chunk_size: u32) -> usize {
    let generated = &pico_aot_dispatch::AOT;
    assert!(
        !generated.is_stub(),
        "aot-generated/ holds the bootstrap stub; generate the guest's crates into it first"
    );
    let digest: [u8; 32] = Sha256::digest(elf).into();
    assert_eq!(
        generated.elf_sha256(),
        digest,
        "aot-generated/ was generated from ELF {}, not from the ELF given, {}",
        hex(&generated.elf_sha256()),
        hex(&digest)
    );
    if let Err(err) = pico_aot_runtime::register(&COUNTED) {
        panic!("register the generated program: {err}");
    }

    let program = record_parity::program(elf);
    let stdin = record_parity::stdin(&[input]);
    let opts = record_parity::opts(chunk_size);
    let workers = workers();
    let dump = chain_diff::enabled();
    let take = |output: EmulationOutput| {
        let windows = dump.then(|| chain_diff::collect(&output));
        (reduced(output), windows)
    };
    let (interpreter, interpreter_windows) =
        emulate_with_pipeline(program.clone(), &stdin, opts, workers)
            .map(take)
            .unwrap_or_else(|err| panic!("the interpreter arm: {err}"));
    let (aot, aot_windows) = emitting::emulate(program, &stdin, opts, workers)
        .map(take)
        .unwrap_or_else(|err| panic!("the AOT, emitting arm: {err}"));

    let mut problems = Vec::new();
    if interpreter.committed_bytes != aot.committed_bytes {
        problems.push("committed bytes differ".to_string());
    }
    if (interpreter.cycles, interpreter.chunks) != (aot.cycles, aot.chunks) {
        problems.push(format!(
            "cycles and chunks: {} and {} vs {} and {}",
            interpreter.cycles, interpreter.chunks, aot.cycles, aot.chunks
        ));
    }
    if interpreter.chunks < 4 {
        problems.push(format!(
            "{} chunk(s) at chunk size {chunk_size}, short of the 4 the bounds are read over",
            interpreter.chunks
        ));
    }
    if interpreter.records.len() != aot.records.len() {
        problems.push(format!(
            "{} vs {} record(s)",
            interpreter.records.len(),
            aot.records.len()
        ));
    }
    for (index, (left, right)) in interpreter.records.iter().zip(&aot.records).enumerate() {
        if (left.0, left.1, &left.2) != (right.0, right.1, &right.2) {
            problems.push(format!(
                "record {index}: kind, chunk index or public values differ"
            ));
        }
        for ((field, len_l, digest_l), (_, len_r, digest_r)) in left.3.iter().zip(&right.3) {
            if is_compared(field) && (len_l, digest_l) != (len_r, digest_r) {
                problems.push(format!(
                    "record {index}: {field}: len {len_l} vs {len_r}, digest {digest_l:#018x} vs \
                     {digest_r:#018x}"
                ));
            }
        }
    }
    if let (Some(left), Some(right)) = (&interpreter_windows, &aot_windows) {
        let chain_differs = |index: &usize| {
            let row = |reduced: &Reduced| {
                reduced.records[*index]
                    .3
                    .iter()
                    .find(|row| row.0 == "cpu_local_memory_chain")
                    .map(|row| (row.1, row.2))
            };
            row(&interpreter) != row(&aot)
        };
        let first = (0..interpreter.records.len().min(aot.records.len())).find(chain_differs);
        if let Some(index) = first {
            let cpu_index = interpreter.records[..index]
                .iter()
                .filter(|record| record.0)
                .count();
            chain_diff::report(left, right, cpu_index);
        }
    }
    let suffix = emitting::audit(emitting::Expect::CompiledAtScale, &mut problems);
    for problem in &problems {
        println!("FAIL: {problem}");
    }
    println!(
        "[{} @ chunk {chunk_size}] {} record(s), {} chunk(s), {} cycle(s), {workers} worker(s){suffix}; \
         {} problem(s)",
        hex(&digest),
        aot.records.len(),
        aot.chunks,
        aot.cycles,
        problems.len()
    );
    problems.len()
}
