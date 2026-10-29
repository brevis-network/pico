//! The snapshot pipeline, with the interpreter on its snapshot thread (`emulate_with_pipeline`),
//! against the one-interpreter path (`emulate_with_opts`), record by record.
//!
//! Both paths cut chunks and split the deferred pool with the same code, after every chunk, so
//! everything `common/record_parity.rs` compares must match.
//!
//! The shared `emulate_snapshot_pipeline` splits the pool as the GPU prover's pipeline does, from
//! chunk 16 on, and one case pins that it still does.

use std::{
    num::NonZeroUsize,
    sync::{Mutex, PoisonError},
};

use pico_vm::{
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{
        opts::{EmulatorOpts, SnapshotMainMode},
        riscv::riscv_emulator::EmulationError,
    },
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::witness::ProvingWitness,
    mle::machine::riscv::{emulate_with_opts, emulate_with_pipeline, EmulateError, Kb},
    proverchain::riscv::{emulate_snapshot_pipeline_with, max_pipeline_workers, DeferredSplit},
};

#[path = "common/record_parity.rs"]
mod record_parity;
use record_parity::{
    check_guest, fib_input, opts, program, stdin, workers, Arm, BLS12381_FP_ELF, FIB_ELF, GUESTS,
    WHOLE,
};

/// The pipeline takes its snapshot memory from one process-wide pool, so runs go one at a time.
static PIPELINE: Mutex<()> = Mutex::new(());

/// Every run of the guest called `name` in [`GUESTS`], down both paths.
fn check(name: &str) {
    let guest = GUESTS
        .iter()
        .find(|guest| guest.name == name)
        .unwrap_or_else(|| panic!("no guest {name}"));
    let _one_at_a_time = PIPELINE.lock().unwrap_or_else(PoisonError::into_inner);
    let workers = workers();
    check_guest(
        guest,
        workers,
        [
            Arm {
                name: "emulate_with_opts",
                emulate: &emulate_with_opts,
            },
            Arm {
                name: "emulate_with_pipeline",
                emulate: &|program, stdin, opts| {
                    emulate_with_pipeline(program, stdin, opts, workers)
                },
            },
        ],
        |_| String::new(),
    );
}

#[test]
fn fib() {
    check("fib");
}

#[test]
fn ed25519() {
    check("ed25519");
}

#[test]
fn poseidon2() {
    check("poseidon2");
}

#[test]
fn aggregator() {
    check("aggregator");
}

#[test]
fn bls12381_fp() {
    check("bls12381-fp");
}

/// The BLS12-381 field guest's run through the shared pipeline's own split, which the GPU
/// prover's pipeline also takes: the block that fills after the third chunk stays in the pool
/// until the run ends.
#[test]
fn the_shared_pipeline_holds_the_deferred_pool_back_as_gpu_base_does() {
    let _one_at_a_time = PIPELINE.lock().unwrap_or_else(PoisonError::into_inner);
    let witness = ProvingWitness::<KoalaBearPoseidon2, RiscvChipType<Kb>, Vec<u8>> {
        program: Some(program(BLS12381_FP_ELF)),
        vk_root: None,
        stdin: Some(stdin(&[])),
        flag_empty_stdin: false,
        config: None,
        opts: Some(opts(WHOLE)),
        records: Vec::new(),
    };
    let kinds = Mutex::new(String::new());
    emulate_snapshot_pipeline_with(
        &witness,
        workers(),
        DeferredSplit::FromChunk16,
        |record, _done| {
            let kind = if record.is_cpu_chunk { 'C' } else { 't' };
            kinds
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .push(kind);
        },
    )
    .expect("emulate_snapshot_pipeline_with");
    let kinds = kinds.into_inner().unwrap_or_else(PoisonError::into_inner);

    let last_cpu = kinds.rfind('C').expect("a CPU chunk");
    assert!(kinds.contains('t'), "no deferred record: {kinds}");
    assert!(
        !kinds[..last_cpu].contains('t'),
        "a deferred record before the last CPU chunk: {kinds}"
    );
}

/// The pipeline's own limit comes back as a value, before any thread starts.
#[test]
fn more_workers_than_cores_is_an_error() {
    let too_many = NonZeroUsize::new(max_pipeline_workers() + 1).expect("nonzero");
    let err = emulate_with_pipeline(
        program(FIB_ELF),
        &stdin(&fib_input(10)),
        opts(WHOLE),
        too_many,
    )
    .expect_err("more workers than cores");
    assert!(
        matches!(
            err,
            EmulateError::Emulation(EmulationError::TooManyWorkers { workers, cores })
                if workers == too_many.get() && cores == max_pipeline_workers()
        ),
        "{err:?}"
    );
}

#[test]
fn options_the_pipeline_cannot_honour_are_errors() {
    let err = emulate_with_pipeline(
        program(FIB_ELF),
        &stdin(&fib_input(10)),
        EmulatorOpts {
            chunk_batch_size: 2,
            ..opts(WHOLE)
        },
        workers(),
    )
    .expect_err("two chunks per batch");
    assert!(
        matches!(err, EmulateError::UnsupportedChunkBatchSize(2)),
        "{err:?}"
    );

    // This binary registers no AOT program, with or without the `aot-emulator` feature.
    let err = emulate_with_pipeline(
        program(FIB_ELF),
        &stdin(&fib_input(10)),
        opts(WHOLE).with_snapshot_main(SnapshotMainMode::Aot),
        workers(),
    )
    .expect_err("no AOT program");
    assert!(matches!(err, EmulateError::AotUnavailable), "{err:?}");
}
