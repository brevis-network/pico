//! The default emulation: a build without `aot` emulates through the snapshot pipeline, with the
//! interpreter on its snapshot thread, and `serial_emulation` keeps the one-interpreter path.
//!
//! The pipeline's records against the single interpreter's, record by record, are the VM's own
//! test (`vm/tests/pipeline_record_parity.rs`); what is checked here is what this crate chooses,
//! and that the run it chose is the run that happened.

use std::{num::NonZeroUsize, time::Duration};

use pico_vm::{
    emulator::riscv::{emulator::error::EmulationError, memory::memory_pool_size},
    mle::machine::riscv::EmulateError,
    proverchain::riscv::max_pipeline_workers,
};

use super::fixture::{
    assert_same_run, default_emulation_workers, emulate_fib, run_child, run_child_within,
    small_builder, COMMIT_OUT_OF_RANGE_ELF, N, SMALL_CHUNK, SMALL_LOG_STACKED_HEIGHT,
};
use crate::{prover::emulator_opts, ProveError, Prover, ProverBuilder, Stdin};

const CHILD_VAR: &str = "PICO_PROVER_PIPELINE_PROBE";

/// What the snapshot pipeline logs when it starts, with its worker count after it.
const PIPELINE_BANNER: &str = "Emulator snapshot worker threads: ";

fn is_child() -> bool {
    std::env::var(CHILD_VAR).is_ok()
}

type Builder = fn() -> ProverBuilder;

/// A builder for each snapshot thread the pipeline can run, by name: the interpreter, and with the
/// `aot` feature the AOT program. What the pipeline refuses, it refuses on either.
fn pipeline_builders() -> Vec<(&'static str, Builder)> {
    vec![
        ("interpreter", small_builder),
        #[cfg(feature = "aot")]
        ("aot", || small_builder().aot(super::aot::fib_program())),
    ]
}

#[test]
fn a_default_build_runs_the_core_count_of_workers_up_to_sixteen() {
    let prover = small_builder().build().expect("prover");
    assert_eq!(
        prover.emulation_workers().map(NonZeroUsize::get),
        Some(default_emulation_workers())
    );
    assert!(!prover.emulates_with_aot());
    let prover = small_builder().serial_emulation().build().expect("prover");
    assert_eq!(prover.emulation_workers(), None);
    assert!(!prover.emulates_with_aot());
}

/// A worker count without `aot` is the pipeline's own, and caps what the default would run.
#[test]
fn emulation_workers_without_aot_set_the_pipelines_count() {
    let prover = small_builder()
        .emulation_workers(NonZeroUsize::MIN)
        .build()
        .expect("prover");
    assert_eq!(prover.emulation_workers(), Some(NonZeroUsize::MIN));
}

/// More workers than cores is refused at `build` and `execute`, rather than by the pipeline once a
/// prove has started.
#[test]
fn workers_beyond_the_core_count_are_refused() {
    let workers = max_pipeline_workers() + 1;
    let refused = |err: ProveError, call: &str| {
        assert!(
            matches!(&err, ProveError::InconsistentOptions(m)
                if m.starts_with(&format!("emulation_workers({workers}) exceeds"))),
            "{call}: {err}"
        );
    };
    for (path, builder) in pipeline_builders() {
        let beyond = || builder().emulation_workers(NonZeroUsize::new(workers).expect("non-zero"));
        refused(
            beyond().build().expect_err("build must refuse"),
            &format!("{path}: build"),
        );
        refused(
            beyond()
                .execute_chunked(Stdin::from(&N))
                .expect_err("execute must refuse"),
            &format!("{path}: execute"),
        );
    }
}

/// The serial path runs no workers, so a count beside it is a contradiction, not a cap.
#[test]
fn serial_emulation_is_refused_beside_a_worker_count() {
    let builder = || {
        small_builder()
            .serial_emulation()
            .emulation_workers(NonZeroUsize::MIN)
    };
    for (call, err) in [
        ("build", builder().build().expect_err("build must refuse")),
        (
            "execute",
            builder()
                .execute_chunked(Stdin::from(&N))
                .expect_err("execute must refuse"),
        ),
    ] {
        assert!(
            matches!(&err, ProveError::InconsistentOptions(m) if m.contains("serial_emulation()")),
            "{call}: {err}"
        );
    }
}

/// The pipeline's `execute` is the single interpreter's, at one worker and at the default count,
/// and the SDK's serial path is the VM's own single-interpreter run.
#[test]
fn the_pipeline_executes_the_run_the_serial_interpreter_executes() {
    let direct = emulate_fib(emulator_opts(SMALL_CHUNK));
    let serial = small_builder()
        .chunk_size(SMALL_CHUNK)
        .serial_emulation()
        .execute_chunked(Stdin::from(&N))
        .expect("serial execute");
    assert!(
        serial.chunks > 1,
        "a {SMALL_CHUNK}-instruction chunk must split this run, or the chunk counts compare \
         nothing: {} chunk(s)",
        serial.chunks
    );
    assert_eq!(serial.committed_bytes, direct.committed_bytes);
    assert_eq!(serial.cycles, direct.cycles);
    assert_eq!(serial.chunks, direct.chunks);

    for workers in [Some(NonZeroUsize::MIN), None] {
        let mut builder = small_builder().chunk_size(SMALL_CHUNK);
        if let Some(workers) = workers {
            builder = builder.emulation_workers(workers);
        }
        let pipeline = builder
            .execute_chunked(Stdin::from(&N))
            .expect("pipeline execute");
        assert_same_run(&pipeline, &serial);
    }
}

/// What was selected is what ran: the default `execute` starts the pipeline, at the worker count
/// the prover reports, and a serial one after it does not start another. The child's stdout
/// carries the evidence, one banner per pipeline start.
#[test]
fn a_default_execute_runs_the_pipeline_and_a_serial_one_does_not() {
    const TEST_NAME: &str =
        "tests::pipeline::a_default_execute_runs_the_pipeline_and_a_serial_one_does_not";
    const MARKER: &str = "[pipeline] the default execute ran the pipeline, the serial one did not";
    if !is_child() {
        let envs = [
            (CHILD_VAR, "1".to_string()),
            ("RUST_LOG", "pico_vm::proverchain::riscv=info".to_string()),
            ("RUST_LOGGER", "flat".to_string()),
        ];
        let stdout = run_child(TEST_NAME, MARKER, &envs);
        let started = format!("{PIPELINE_BANNER}{}\n", default_emulation_workers());
        assert_eq!(stdout.matches(&started).count(), 1, "{stdout}");
        assert_eq!(stdout.matches(PIPELINE_BANNER).count(), 1, "{stdout}");
        return;
    }
    pico_vm::machine::logger::setup_logger();
    small_builder()
        .chunk_size(SMALL_CHUNK)
        .execute_chunked(Stdin::from(&N))
        .expect("default execute");
    small_builder()
        .chunk_size(SMALL_CHUNK)
        .serial_emulation()
        .execute_chunked(Stdin::from(&N))
        .expect("serial execute");
    println!("{MARKER}");
}

/// A memory pool the pipeline would wait on forever is refused at `build` and `execute`, rather
/// than by the pipeline once a prove has started; the serial path never meets the pool, and runs.
#[test]
fn a_memory_pool_that_can_never_serve_the_run_is_refused() {
    const TEST_NAME: &str =
        "tests::pipeline::a_memory_pool_that_can_never_serve_the_run_is_refused";
    const MARKER: &str = "[pipeline] the pool that never refills was refused";
    if !is_child() {
        let envs = [
            (CHILD_VAR, "1".to_string()),
            ("MEMORY_RECYCLER_THREADS", "0".to_string()),
        ];
        run_child(TEST_NAME, MARKER, &envs);
        return;
    }
    let refused = |result: Result<(), ProveError>, call: &str| match result {
        Err(ProveError::InconsistentOptions(message)) => assert!(
            message.contains("MEMORY_RECYCLER_THREADS=0"),
            "{call}: {message}"
        ),
        Err(other) => panic!("{call}: expected InconsistentOptions, got {other}"),
        Ok(()) => panic!("{call}: a pool that never refills was accepted"),
    };
    for (path, builder) in pipeline_builders() {
        refused(builder().build().map(drop), &format!("{path}: build"));
        refused(
            builder().execute_chunked(Stdin::from(&N)).map(drop),
            &format!("{path}: execute"),
        );
    }
    small_builder()
        .serial_emulation()
        .execute_chunked(Stdin::from(&N))
        .expect("the serial path meets no pool");
    println!("{MARKER}");
}

/// More failed default runs than the snapshot memory pool holds, each way the guest can fail on
/// the snapshot thread, then one that halts. That thread takes a pool memory per batch and puts it
/// back once the batch is cut, so a batch that fails has to put it back too: a pool that lost one
/// per failure would leave a later run waiting on it forever, which the timeout turns into a
/// failure.
#[test]
fn failed_default_runs_leave_the_memory_pool_whole() {
    const TEST_NAME: &str = "tests::pipeline::failed_default_runs_leave_the_memory_pool_whole";
    const MARKER: &str = "[pipeline] the run after the failures halted";
    const POOL: usize = 2;
    if !is_child() {
        let envs = [
            (CHILD_VAR, "1".to_string()),
            ("MEMORY_POOL_SIZE", POOL.to_string()),
        ];
        run_child_within(TEST_NAME, MARKER, &envs, Duration::from_secs(300));
        return;
    }
    assert_eq!(
        memory_pool_size(),
        POOL,
        "MEMORY_POOL_SIZE did not reach the pool"
    );
    let builder =
        || Prover::builder(COMMIT_OUT_OF_RANGE_ELF).log_stacked_height(SMALL_LOG_STACKED_HEIGHT);
    for run in 0..=POOL {
        match builder().execute_chunked(Stdin::new()) {
            Err(ProveError::Emulate(EmulateError::Emulation(
                EmulationError::InsufficientInput { .. },
            ))) => {}
            Err(other) => panic!("short input {run}: expected InsufficientInput, got {other}"),
            Ok(_) => panic!("short input {run}: a guest that read no input halted"),
        }
    }
    for run in 0..=POOL {
        match builder().execute_chunked(Stdin::from(&Some(8u32))) {
            Err(ProveError::EmulationAborted(message)) => assert!(
                message.contains("out of range: 8 >= 8"),
                "abort {run}: {message}"
            ),
            Err(other) => panic!("abort {run}: expected EmulationAborted, got {other}"),
            Ok(_) => panic!("abort {run}: the out-of-range commit did not stop the run"),
        }
    }
    builder()
        .execute_chunked(Stdin::from(&None::<u32>))
        .expect("the run after the failures halts");
    println!("{MARKER}");
}
