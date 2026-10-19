//! The environment contract, one child-process assertion per variable.
//!
//! A child process for every case, because `set_var` in a live test binary races every other
//! thread's `getenv`, and because a variable the VM reads once per process has to be set before the
//! process first uses it.

use pico_vm::emulator::opts::EmulatorOpts;

use super::fixture::{emulate_fib, run_child, small_builder, N, SMALL_CHUNK};
use crate::{prover::emulator_opts, ProveError, Stdin};

const CHILD_VAR: &str = "PICO_PROVER_ENV_PROBE";
const EXPECT_VAR: &str = "PICO_PROVER_ENV_EXPECT";

fn is_child() -> bool {
    std::env::var(CHILD_VAR).is_ok()
}

/// What a run looks like in the terms an emulator option can move.
fn shape(records: usize, chunks: u32, batches: usize) -> String {
    format!("records={records} chunks={chunks} batches={batches}")
}

/// The run the prover's own emulation produces, at a chunk small enough that the chunk size and the
/// batching each leave a mark on it.
fn prover_run() -> String {
    let prover = small_builder()
        .chunk_size(SMALL_CHUNK)
        .build()
        .expect("prover");
    let run = prover.emulate(Stdin::from(&N)).expect("emulation");
    shape(
        run.records.len(),
        run.execution.chunks,
        run.execution.reports.len(),
    )
}

/// The run the same emulation would produce under `opts`.
fn run_under(opts: EmulatorOpts) -> String {
    let run = emulate_fib(opts);
    shape(run.records.len(), run.chunks, run.reports.len())
}

/// Two of the three variables `EmulatorOpts::default` reads. The parent first shows that the
/// variable's value, had it reached the options, would change the run; the child then runs the
/// prover with the variable set and must match the run without it. The third, `SPLIT_THRESHOLD`,
/// sets split options the record split on this path does not read, so no value of it changes a run
/// and a probe of it could not fail.
macro_rules! option_probe {
    ($test:ident, $name:literal, $value:literal, $leak:expr) => {
        #[test]
        fn $test() {
            const TEST_NAME: &str = concat!("tests::environment::", stringify!($test));
            const MARKER: &str = concat!("[env] ", $name, " did not reach the emulation");
            if is_child() {
                let expected = std::env::var(EXPECT_VAR).expect("expected run");
                assert_eq!(
                    prover_run(),
                    expected,
                    concat!($name, " reached the emulation")
                );
                println!("{MARKER}");
                return;
            }
            let clean = prover_run();
            #[allow(clippy::redundant_closure_call)]
            let leaked = run_under(($leak)(emulator_opts(SMALL_CHUNK)));
            assert_ne!(
                clean, leaked,
                concat!(
                    $name,
                    "=",
                    $value,
                    " leaves no mark, so this probe could not fail"
                )
            );
            run_child(
                TEST_NAME,
                MARKER,
                &[
                    (CHILD_VAR, "1".to_string()),
                    (EXPECT_VAR, clean),
                    ($name, $value.to_string()),
                ],
            );
        }
    };
}

option_probe!(
    chunk_size_does_not_reach_the_emulation,
    "CHUNK_SIZE",
    "2048",
    |opts: EmulatorOpts| EmulatorOpts {
        chunk_size: 2048,
        ..opts
    }
);

option_probe!(
    chunk_batch_size_does_not_reach_the_emulation,
    "CHUNK_BATCH_SIZE",
    "16",
    |opts: EmulatorOpts| EmulatorOpts {
        chunk_batch_size: 16,
        ..opts
    }
);

/// `PROVE_CONCURRENCY` is read only by a machine that was given no concurrency, and `vm`'s
/// `an_explicit_concurrency_outranks_the_environment` pins that. What this crate owes is that it
/// always gives one; the machine does not report its concurrency, so the call is checked where it
/// is made.
#[test]
fn the_prover_always_gives_its_machine_a_concurrency() {
    let in_code = include_str!("../prover.rs")
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .any(|line| line.contains(".with_concurrency(self.concurrency)"));
    assert!(
        in_code,
        "ProverBuilder::build no longer hands RiscvMachine an explicit concurrency, so \
         PROVE_CONCURRENCY decides it"
    );
}

/// `name=value` in a child, where `build` and `execute` must both refuse it by name or, when
/// `refused` is false, `build` must succeed.
fn event_limit_probe(test_name: &str, name: &str, value: &str, refused: bool) {
    let marker = format!("[env] {name}={value} checked");
    if is_child() {
        if refused {
            let named = format!("{name}={value}");
            let is_named = |err: &ProveError| matches!(err, ProveError::InconsistentOptions(m) if m.contains(&named));
            let err = small_builder()
                .build()
                .expect_err("build must refuse a loosened event limit");
            assert!(is_named(&err), "build: got {err}");
            let err = small_builder()
                .execute(Stdin::from(&N))
                .expect_err("execute must refuse a loosened event limit");
            assert!(is_named(&err), "execute: got {err}");
        } else {
            small_builder()
                .build()
                .expect("a value the VM ignores must not stop the build");
        }
        println!("{marker}");
        return;
    }
    run_child(
        test_name,
        &marker,
        &[(CHILD_VAR, "1".to_string()), (name, value.to_string())],
    );
}

/// The chunk-size check assumes the memory-event limit is on at scale 1, so the two variables that
/// loosen it are refused while they are still options rather than failing a proof mid-run.
#[test]
fn event_limits_off_is_refused() {
    event_limit_probe(
        "tests::environment::event_limits_off_is_refused",
        "CHUNK_EVENT_LIMITS_OFF",
        "1",
        true,
    );
}

#[test]
fn an_event_limit_scale_above_one_is_refused() {
    event_limit_probe(
        "tests::environment::an_event_limit_scale_above_one_is_refused",
        "CHUNK_EVENT_LIMIT_SCALE",
        "2",
        true,
    );
}

/// Outside 1 to 16 the VM reads the scale as 1, so there is nothing to refuse.
#[test]
fn an_event_limit_scale_below_one_builds() {
    event_limit_probe(
        "tests::environment::an_event_limit_scale_below_one_builds",
        "CHUNK_EVENT_LIMIT_SCALE",
        "0.5",
        false,
    );
}

#[test]
fn an_event_limit_scale_above_sixteen_builds() {
    event_limit_probe(
        "tests::environment::an_event_limit_scale_above_sixteen_builds",
        "CHUNK_EVENT_LIMIT_SCALE",
        "32",
        false,
    );
}

/// The four recursion knobs the crate documentation says reach it. Each child starts with the
/// variable set to the opposite of its default, so the VM resolves it from that value on first
/// use; a knob the VM stopped reading, or reads under another name, keeps its default.
macro_rules! knob_probe {
    ($test:ident, $name:literal, $default:literal) => {
        #[test]
        fn $test() {
            const TEST_NAME: &str = concat!("tests::environment::", stringify!($test));
            const MARKER: &str = concat!("[env] ", $name, " reached the VM");
            if is_child() {
                let value = pico_vm::mle::machine::recursion::witness_flags()
                    .iter()
                    .find(|(name, _)| *name == $name)
                    .map(|(_, value)| *value)
                    .expect(concat!($name, " is not in the flag table"));
                assert_eq!(value, !$default, concat!($name, " did not reach the VM"));
                println!("{MARKER}");
                return;
            }
            run_child(
                TEST_NAME,
                MARKER,
                &[
                    (CHILD_VAR, "1".to_string()),
                    ($name, if $default { "0" } else { "1" }.to_string()),
                ],
            );
        }
    };
}

knob_probe!(witness_hash_reaches_the_vm, "MLE_WITNESS_HASH", false);
knob_probe!(transcript_prof_reaches_the_vm, "MLE_TRANSCRIPT_PROF", false);
knob_probe!(walker_xcheck_reaches_the_vm, "MLE_WALKER_XCHECK", false);
knob_probe!(
    rec_parallel_children_reaches_the_vm,
    "MLE_REC_PARALLEL_CHILDREN",
    true
);

/// A variable the crate root documents as reaching the prover must be in the list callers warn
/// from, and nothing else may be. A row that reaches it only with the `aot` feature counts only in
/// a build with it.
#[test]
fn the_exported_variables_are_the_ones_the_crate_documents() {
    let mut documented: Vec<&str> = include_str!("../lib.rs")
        .lines()
        .filter(|line| line.starts_with("//! | `") && line.contains("| **yes"))
        .filter(|line| cfg!(feature = "aot") || !line.contains("| **yes, with the `aot` feature"))
        .flat_map(|line| {
            let names = line.split('|').nth(1).expect("a names column");
            names.split('`').skip(1).step_by(2)
        })
        .collect();
    let mut exported: Vec<&str> = crate::ENV_READ_BY_PROVER
        .iter()
        .map(|(name, _)| *name)
        .collect();
    documented.sort_unstable();
    exported.sort_unstable();
    assert!(!documented.is_empty(), "no documented variables found");
    assert_eq!(exported, documented);
}

/// A variable listed as no longer read is named by the crate documentation, and is neither in the
/// VM's recursion flag table nor among the variables that reach the prover: a caller must not warn
/// about one under both headings.
#[test]
fn the_variables_no_longer_read_reach_nothing() {
    let docs: String = include_str!("../lib.rs")
        .lines()
        .filter(|line| line.starts_with("//!"))
        .collect();
    let flags = pico_vm::mle::machine::recursion::witness_flags();
    for (name, _) in crate::ENV_NO_LONGER_READ {
        assert!(
            docs.contains(&format!("`{name}`")),
            "{name} is not in the crate documentation"
        );
        assert!(
            !flags.iter().any(|(flag, _)| flag == name),
            "{name} is in the VM's flag table"
        );
        assert!(
            !crate::ENV_READ_BY_PROVER
                .iter()
                .any(|(read, _)| read == name),
            "{name} is listed as read too"
        );
    }
}
