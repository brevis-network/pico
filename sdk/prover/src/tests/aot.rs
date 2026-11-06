//! AOT emulation: what [`crate::ProverBuilder::aot`] refuses, and that a run through the AOT
//! pipeline proves.
//!
//! The registry keeps one program for the life of a process, so every case that registers one runs
//! in a child process. The program these cases register pairs a guest's digest with the bootstrap
//! stub's entry point, which interprets every block: they check the plumbing, and running compiled
//! code is the AOT harness's to check.

use std::{
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicU64, Ordering},
        OnceLock,
    },
    time::Duration,
};

use pico_aot_runtime::{AotEmulatorCore, AotError, AotProgram};
use pico_vm::{
    emulator::riscv::emulator::error::EmulationError, mle::machine::riscv::EmulateError,
};
use sha2::{Digest, Sha256};

use super::fixture::{
    assert_is_fib_output, builder, default_emulation_workers, emulate_fib, run_child,
    run_child_within, small_builder, COMMIT_OUT_OF_RANGE_ELF, FIB_ELF, N, OTHER_ELF, SMALL_CHUNK,
    SMALL_LOG_STACKED_HEIGHT,
};
use crate::{prover::emulator_opts, Phase, ProveError, Prover, Stdin};

const CHILD_VAR: &str = "PICO_PROVER_AOT_PROBE";

/// What the snapshot pipeline prints when its snapshot thread runs the AOT emulator.
const AOT_BANNER: &str = "[AOT] snapshot-main = AotMetaEmulator";

/// What it prints when its replay workers run the AOT core.
const WORKER_BANNER: &str = "[AOT] replay workers = AotReplayMetaEmulator";

fn is_child() -> bool {
    std::env::var(CHILD_VAR).is_ok()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Runs of the registered program with a sink set: a replay worker's, which writes records, and
/// never the snapshot thread's. The stub's code makes the interpreter's records, so these runs are
/// what shows which engine replayed.
static EMITTING_RUNS: AtomicU64 = AtomicU64::new(0);

/// The bootstrap stub's entry point, as the committed `aot-generated/` crate exports it.
fn interpret_every_block(emu: &mut AotEmulatorCore) -> Result<(), String> {
    if emu.is_emitting() {
        EMITTING_RUNS.fetch_add(1, Ordering::Relaxed);
    }
    AotProgram::STUB.run(emu)
}

fn program_for(elf: &[u8], slot: &'static OnceLock<AotProgram>) -> &'static AotProgram {
    slot.get_or_init(|| {
        AotProgram::stamped(
            sha256(elf),
            AotProgram::CODEGEN_STAMP,
            interpret_every_block,
        )
    })
}

pub(super) fn fib_program() -> &'static AotProgram {
    static PROGRAM: OnceLock<AotProgram> = OnceLock::new();
    program_for(FIB_ELF, &PROGRAM)
}

fn other_program() -> &'static AotProgram {
    static PROGRAM: OnceLock<AotProgram> = OnceLock::new();
    program_for(OTHER_ELF, &PROGRAM)
}

fn commit_out_of_range_program() -> &'static AotProgram {
    static PROGRAM: OnceLock<AotProgram> = OnceLock::new();
    program_for(COMMIT_OUT_OF_RANGE_ELF, &PROGRAM)
}

fn child_env() -> Vec<(&'static str, String)> {
    vec![(CHILD_VAR, "1".to_string())]
}

#[test]
fn the_bootstrap_stub_is_refused_as_not_generated() {
    let err = small_builder()
        .aot(&AotProgram::STUB)
        .build()
        .expect_err("build must refuse the stub");
    assert!(matches!(err, ProveError::AotNotGenerated), "build: {err}");
    assert!(err.to_string().contains("cargo pico aot"), "{err}");

    let err = small_builder()
        .aot(&AotProgram::STUB)
        .execute_chunked(Stdin::from(&N))
        .expect_err("execute must refuse the stub");
    assert!(matches!(err, ProveError::AotNotGenerated), "execute: {err}");
}

#[test]
fn code_generated_from_another_elf_is_refused() {
    let err = Prover::builder(OTHER_ELF)
        .log_stacked_height(SMALL_LOG_STACKED_HEIGHT)
        .aot(fib_program())
        .build()
        .expect_err("build must refuse fib's code for another ELF");
    let ProveError::AotElfMismatch {
        generated_from,
        elf,
    } = err
    else {
        panic!("expected AotElfMismatch, got {err}");
    };
    assert_eq!(generated_from, sha256(FIB_ELF));
    assert_eq!(elf, sha256(OTHER_ELF));
    let message = err.to_string();
    assert!(
        message.contains(&hex(&generated_from)) && message.contains(&hex(&elf)),
        "the message must name both digests: {message}"
    );
}

/// A build that fails registers nothing, so the process can still take another program; once one
/// is registered, a second is refused.
#[test]
fn a_failed_build_registers_nothing_and_a_second_program_is_refused() {
    const TEST_NAME: &str =
        "tests::aot::a_failed_build_registers_nothing_and_a_second_program_is_refused";
    const MARKER: &str =
        "[aot] a failed build registered nothing, and a second program was refused";
    if !is_child() {
        run_child(TEST_NAME, MARKER, &child_env());
        return;
    }
    let err = Prover::builder(OTHER_ELF)
        .log_stacked_height(SMALL_LOG_STACKED_HEIGHT)
        .aot(other_program())
        .verify_keys(true)
        .build()
        .expect_err("whitelist mode without a whitelist must fail the build");
    assert!(matches!(err, ProveError::InconsistentOptions(_)), "{err}");
    small_builder()
        .aot(fib_program())
        .execute_chunked(Stdin::from(&N))
        .expect("the first program registers and runs");
    let again = small_builder()
        .aot(fib_program())
        .build()
        .expect("the same program registers again");
    assert_eq!(
        again.emulation_workers().map(NonZeroUsize::get),
        Some(default_emulation_workers()),
        "the worker count defaults to the core count, at most 16"
    );
    let err = Prover::builder(OTHER_ELF)
        .log_stacked_height(SMALL_LOG_STACKED_HEIGHT)
        .aot(other_program())
        .build()
        .expect_err("a second program must be refused");
    let ProveError::AotRegistration(AotError::Conflict {
        registered,
        requested,
    }) = err
    else {
        panic!("expected AotRegistration(Conflict), got {err}");
    };
    assert_eq!(registered, sha256(FIB_ELF));
    assert_eq!(requested, sha256(OTHER_ELF));
    println!("{MARKER}");
}

#[test]
fn a_factory_installed_without_the_registry_is_refused() {
    const TEST_NAME: &str = "tests::aot::a_factory_installed_without_the_registry_is_refused";
    const MARKER: &str = "[aot] a foreign factory was refused";
    if !is_child() {
        run_child(TEST_NAME, MARKER, &child_env());
        return;
    }
    use pico_vm::{
        compiler::riscv::program::Program,
        emulator::{
            aot::{register_aot_factory, AotSnapshotEmulator},
            opts::EmulatorOpts,
            riscv::public_values::RecordFinalPvsState,
        },
    };
    fn foreign(
        _: std::sync::Arc<Program>,
        _: Vec<Vec<u8>>,
        _: EmulatorOpts,
        _: std::sync::Arc<RecordFinalPvsState>,
    ) -> Box<dyn AotSnapshotEmulator> {
        unreachable!("the prover must refuse before it asks for an emulator")
    }
    register_aot_factory(foreign);
    let err = small_builder()
        .aot(fib_program())
        .build()
        .expect_err("a foreign factory must be refused");
    assert!(
        matches!(err, ProveError::AotRegistration(AotError::ForeignFactory)),
        "expected AotRegistration(ForeignFactory), got {err}"
    );
    println!("{MARKER}");
}

/// The AOT workers run the program `aot` registers, so they are refused without it; and as AOT
/// code, the serial path cannot take them either.
#[test]
fn aot_workers_are_refused_without_aot_and_with_serial_emulation() {
    let err = small_builder()
        .aot_workers()
        .build()
        .expect_err("the workers have no program to run");
    assert!(
        matches!(&err, ProveError::InconsistentOptions(m) if m.contains("aot_workers()")),
        "{err}"
    );
    let err = small_builder()
        .aot(fib_program())
        .aot_workers()
        .serial_emulation()
        .build()
        .expect_err("serial emulation has no replay workers");
    assert!(
        matches!(&err, ProveError::InconsistentOptions(m) if m.contains("serial_emulation()")),
        "{err}"
    );
}

/// AOT code runs on the pipeline's snapshot thread only, so the serial path cannot take it.
#[test]
fn serial_emulation_is_refused_with_aot() {
    let err = small_builder()
        .aot(fib_program())
        .serial_emulation()
        .build()
        .expect_err("serial emulation has no snapshot thread to run AOT code on");
    assert!(
        matches!(&err, ProveError::InconsistentOptions(m) if m.contains("serial_emulation()")),
        "{err}"
    );
}

/// Proves and verifies fib to [`Phase::Combine`] through the AOT pipeline, with the output bytes
/// the interpreter commits, at the default worker count. The child's stdout carries the evidence
/// that the pipeline made the records: its banner, the worker count it ran, and the AOT runtime's
/// end-of-run line naming fib's digest, once per emulation the child ran.
#[test]
fn an_aot_run_proves_and_verifies_to_combine() {
    const TEST_NAME: &str = "tests::aot::an_aot_run_proves_and_verifies_to_combine";
    const MARKER: &str = "[aot] fib proved through the AOT pipeline";
    if !is_child() {
        let mut envs = child_env();
        envs.push((
            "RUST_LOG",
            "pico_aot_runtime=info,pico_vm::proverchain::riscv=info".to_string(),
        ));
        envs.push(("RUST_LOGGER", "flat".to_string()));
        let stdout = run_child(TEST_NAME, MARKER, &envs);
        // A prove and an execute: two emulations, and the stub's code dispatched no compiled block.
        let finished = format!(
            "AOT program for ELF {} finished: 0 compiled-block dispatches",
            hex(&sha256(FIB_ELF))
        );
        let workers = format!(
            "Emulator snapshot worker threads: {}\n",
            default_emulation_workers()
        );
        assert_eq!(stdout.matches(AOT_BANNER).count(), 2, "{stdout}");
        assert_eq!(stdout.matches(&workers).count(), 2, "{stdout}");
        assert_eq!(stdout.matches(&finished).count(), 2, "{stdout}");
        assert_eq!(stdout.matches(WORKER_BANNER).count(), 0, "{stdout}");
        return;
    }
    pico_vm::machine::logger::setup_logger();
    let mut prover = builder()
        .chunk_size(SMALL_CHUNK)
        .aot(fib_program())
        .build()
        .expect("prover");
    assert_eq!(
        prover.emulation_workers().map(NonZeroUsize::get),
        Some(default_emulation_workers())
    );
    assert!(prover.emulates_with_aot());
    assert!(!prover.replays_with_aot());
    let interpreted = emulate_fib(emulator_opts(SMALL_CHUNK));
    assert!(
        interpreted.chunks > 1,
        "a {SMALL_CHUNK}-instruction chunk must split this run across workers"
    );

    let proof = prover.prove(Stdin::from(&N)).expect("prove");
    assert_eq!(proof.phase(), Phase::Combine);
    assert_is_fib_output(proof.committed().as_bytes(), N);
    assert_eq!(proof.committed().as_bytes(), interpreted.committed_bytes);

    let execution = prover.execute_chunked(Stdin::from(&N)).expect("execute");
    assert_eq!(execution.committed_bytes, interpreted.committed_bytes);
    assert_eq!(execution.chunks, interpreted.chunks);
    assert_eq!(
        EMITTING_RUNS.load(Ordering::Relaxed),
        0,
        "the replay workers ran the AOT program"
    );
    println!("{MARKER}");
}

/// [`an_aot_run_proves_and_verifies_to_combine`] with the replay workers on the AOT program too
/// ([`crate::ProverBuilder::aot_workers`]): the same banner, worker count and end-of-run line, the
/// workers' banner beside them, and replays of the program on every chunk, which only an AOT
/// worker makes.
#[test]
fn aot_workers_prove_and_verify_to_combine() {
    const TEST_NAME: &str = "tests::aot::aot_workers_prove_and_verify_to_combine";
    const MARKER: &str = "[aot] fib proved with AOT replay workers";
    if !is_child() {
        let mut envs = child_env();
        envs.push((
            "RUST_LOG",
            "pico_aot_runtime=info,pico_vm::proverchain::riscv=info".to_string(),
        ));
        envs.push(("RUST_LOGGER", "flat".to_string()));
        let stdout = run_child(TEST_NAME, MARKER, &envs);
        // A prove and an execute: two emulations, and the stub's code dispatched no compiled block.
        let finished = format!(
            "AOT program for ELF {} finished: 0 compiled-block dispatches",
            hex(&sha256(FIB_ELF))
        );
        let workers = format!(
            "Emulator snapshot worker threads: {}\n",
            default_emulation_workers()
        );
        assert_eq!(stdout.matches(AOT_BANNER).count(), 2, "{stdout}");
        assert_eq!(stdout.matches(&workers).count(), 2, "{stdout}");
        assert_eq!(stdout.matches(&finished).count(), 2, "{stdout}");
        assert_eq!(stdout.matches(WORKER_BANNER).count(), 2, "{stdout}");
        return;
    }
    pico_vm::machine::logger::setup_logger();
    let mut prover = builder()
        .chunk_size(SMALL_CHUNK)
        .aot(fib_program())
        .aot_workers()
        .build()
        .expect("prover");
    assert_eq!(
        prover.emulation_workers().map(NonZeroUsize::get),
        Some(default_emulation_workers())
    );
    assert!(prover.emulates_with_aot());
    assert!(prover.replays_with_aot());
    let interpreted = emulate_fib(emulator_opts(SMALL_CHUNK));
    assert!(
        interpreted.chunks > 1,
        "a {SMALL_CHUNK}-instruction chunk must split this run across workers"
    );

    let proof = prover.prove(Stdin::from(&N)).expect("prove");
    assert_eq!(proof.phase(), Phase::Combine);
    assert_is_fib_output(proof.committed().as_bytes(), N);
    assert_eq!(proof.committed().as_bytes(), interpreted.committed_bytes);
    let proved = EMITTING_RUNS.load(Ordering::Relaxed);
    assert!(
        proved >= u64::from(interpreted.chunks),
        "{proved} AOT replays for {} chunks",
        interpreted.chunks
    );

    let execution = prover.execute_chunked(Stdin::from(&N)).expect("execute");
    assert_eq!(execution.committed_bytes, interpreted.committed_bytes);
    assert_eq!(execution.chunks, interpreted.chunks);
    let executed = EMITTING_RUNS.load(Ordering::Relaxed) - proved;
    assert!(
        executed >= u64::from(interpreted.chunks),
        "{executed} AOT replays for {} chunks",
        interpreted.chunks
    );
    println!("{MARKER}");
}

/// The emulation-abort guest on the AOT path with one worker: input it never got is the
/// interpreter's error, the out-of-range commit stops the run with an error, and the same prover
/// then proves. On this path the AOT code meets the commit first and reports it as an error where
/// the interpreter panics, so the run never reaches the unwind guard. A pipeline that hangs
/// instead fails at the timeout.
#[test]
fn an_emulator_failure_on_the_aot_path_is_an_error_and_the_prover_still_proves() {
    const TEST_NAME: &str = "tests::aot::\
        an_emulator_failure_on_the_aot_path_is_an_error_and_the_prover_still_proves";
    const MARKER: &str = "[aot] the AOT path stopped on the error and proved after it";
    if !is_child() {
        run_child_within(TEST_NAME, MARKER, &child_env(), Duration::from_secs(300));
        return;
    }
    let mut prover = Prover::builder(COMMIT_OUT_OF_RANGE_ELF)
        .log_stacked_height(SMALL_LOG_STACKED_HEIGHT)
        .aot(commit_out_of_range_program())
        .emulation_workers(NonZeroUsize::MIN)
        .build()
        .expect("prover");
    let out_of_range = Stdin::from(&Some(8u32));

    let short_input = |result: Result<crate::Execution, ProveError>, path: &str| match result {
        Err(ProveError::Emulate(EmulateError::Emulation(EmulationError::InsufficientInput {
            stream_ptr: 0,
            stream_len: 0,
        }))) => {}
        Err(other) => panic!("{path}: expected InsufficientInput, got {other}"),
        Ok(_) => panic!("{path}: a guest that read no input halted"),
    };
    short_input(prover.execute_chunked(Stdin::new()), "aot");
    let interpreter =
        || Prover::builder(COMMIT_OUT_OF_RANGE_ELF).log_stacked_height(SMALL_LOG_STACKED_HEIGHT);
    short_input(
        interpreter().execute_chunked(Stdin::new()),
        "interpreter pipeline",
    );
    short_input(
        interpreter()
            .serial_emulation()
            .execute_chunked(Stdin::new()),
        "serial interpreter",
    );

    assert_aot_failed(prover.execute_chunked(out_of_range.clone()), "execute");
    assert_aot_failed(prover.prove(out_of_range), "prove");

    let proof = prover
        .prove_to(Stdin::from(&None::<u32>), Phase::Riscv)
        .expect("after the failure, the same prover proves a run that halts");
    assert_eq!(proof.phase(), Phase::Riscv);
    println!("{MARKER}");
}

/// More failed AOT runs than the snapshot memory pool holds, then one that halts. An AOT batch takes
/// a pool memory that only a replay worker returns, so a batch the AOT code fails has to return
/// its own; a pool that lost one per failure would leave the last run waiting on it forever, which
/// the timeout turns into a failure.
#[test]
fn failed_aot_runs_leave_the_memory_pool_whole() {
    const TEST_NAME: &str = "tests::aot::failed_aot_runs_leave_the_memory_pool_whole";
    const MARKER: &str = "[aot] the run after the failures halted";
    const POOL: usize = 2;
    if !is_child() {
        let mut envs = child_env();
        envs.push(("MEMORY_POOL_SIZE", POOL.to_string()));
        run_child_within(TEST_NAME, MARKER, &envs, Duration::from_secs(300));
        return;
    }
    assert_eq!(
        pico_vm::emulator::riscv::memory::memory_pool_size(),
        POOL,
        "MEMORY_POOL_SIZE did not reach the pool"
    );
    // One worker: a worker holds a pool memory while it replays, so a pool of two serves one
    // worker and the batch being cut.
    let builder = || {
        Prover::builder(COMMIT_OUT_OF_RANGE_ELF)
            .log_stacked_height(SMALL_LOG_STACKED_HEIGHT)
            .aot(commit_out_of_range_program())
            .emulation_workers(NonZeroUsize::MIN)
    };
    for run in 0..=POOL {
        assert_aot_failed(
            builder().execute_chunked(Stdin::from(&Some(8u32))),
            &format!("failed run {run}"),
        );
    }
    builder()
        .execute_chunked(Stdin::from(&None::<u32>))
        .expect("the run after the failures halts");
    println!("{MARKER}");
}

fn assert_aot_failed<T>(result: Result<T, ProveError>, call: &str) {
    match result {
        Err(ProveError::Emulate(EmulateError::Emulation(EmulationError::AotExecutionFailed(
            message,
        )))) => assert!(
            message.contains("out of range: 8 >= 8"),
            "{call}: the error does not carry the AOT runtime's message: {message}"
        ),
        Err(other) => panic!("{call}: expected the AOT runtime's error, got {other}"),
        Ok(_) => panic!("{call}: the out-of-range commit did not stop the run"),
    }
}
