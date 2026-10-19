//! An emulator panic on the guest's own input comes back as [`ProveError::EmulationAborted`], and
//! the prover that met it still proves.
//!
//! The guest (`vm/examples/patch-testing/guests/commit-out-of-range`) issues `COMMIT` for digest
//! word 8 when its input asks it to. The public values hold eight words, and the emulator panics on
//! the index rather than returning an error.

use super::fixture::SMALL_LOG_STACKED_HEIGHT;
use crate::{Phase, ProveError, Prover, Stdin};

const COMMIT_OUT_OF_RANGE_ELF: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../perf/bench_data/rv64/commit-out-of-range-elf"
));

fn assert_aborted<T>(result: Result<T, ProveError>, call: &str) {
    match result {
        Err(ProveError::EmulationAborted(message)) => assert!(
            message.contains("out of range: 8 >= 8"),
            "{call}: the abort does not carry the emulator's message: {message}"
        ),
        Err(other) => panic!("{call}: expected EmulationAborted, got {other}"),
        Ok(_) => panic!("{call}: the out-of-range commit did not stop the run"),
    }
}

#[test]
fn an_emulator_abort_is_an_error_and_the_prover_still_proves() {
    let mut prover = Prover::builder(COMMIT_OUT_OF_RANGE_ELF)
        .log_stacked_height(SMALL_LOG_STACKED_HEIGHT)
        .build()
        .expect("prover");
    let out_of_range = Stdin::from(&Some(8u32));

    assert_aborted(prover.execute(out_of_range.clone()), "execute");
    assert_aborted(prover.prove(out_of_range), "prove");

    let proof = prover
        .prove_to(Stdin::from(&None::<u32>), Phase::Riscv)
        .expect("after an abort, the same prover proves a run that halts");
    assert_eq!(proof.phase(), Phase::Riscv);
}
