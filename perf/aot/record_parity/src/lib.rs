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
//! `AOT_PARITY_WORKERS` sets the worker count; unset, it is four, or the core count if lower.

use std::{
    num::NonZeroUsize,
    sync::atomic::{AtomicU64, Ordering},
};

use pico_aot_runtime::{AotEmulatorCore, AotProgram};
use pico_vm::{emulator::opts::SnapshotMainMode, mle::machine::riscv::emulate_with_pipeline};
use sha2::{Digest, Sha256};

#[path = "../../../../vm/tests/common/record_parity.rs"]
mod record_parity;
use record_parity::{check_guest, Arm, GUESTS};

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

/// The generated program, registered in its place: the same digest and the same code, reporting
/// after every batch how many compiled blocks its run has entered.
static COUNTED: AotProgram = AotProgram::new(pico_aot_dispatch::AOT.elf_sha256(), run_counted);

fn run_counted(emu: &mut AotEmulatorCore) -> Result<(), String> {
    let result = pico_aot_dispatch::AOT.run(emu);
    DISPATCHES.store(emu.compiled_block_dispatches(), Ordering::Relaxed);
    result
}

fn hex(digest: &[u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Compares the AOT snapshot thread with the interpreter's on every run of the guest
/// `aot-generated/` was generated from, prints one line per run and every problem found, and
/// panics if there was any.
pub fn check_generated_guest() {
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
    pico_aot_runtime::register(&COUNTED).expect("register the generated program");

    let workers = workers();
    check_guest(
        guest,
        workers,
        [
            Arm {
                name: "interpreter",
                emulate: &|program, stdin, opts| {
                    emulate_with_pipeline(program, stdin, opts, workers)
                },
            },
            Arm {
                name: "AOT",
                emulate: &|program, stdin, opts| {
                    DISPATCHES.store(0, Ordering::Relaxed);
                    let aot = opts.with_snapshot_main(SnapshotMainMode::Aot);
                    emulate_with_pipeline(program, stdin, aot, workers)
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
}
