//! A proved RISC-V bundle that does not attest to a successful run.
//!
//! A run that halts non-zero cannot be produced here: the emulator refuses it at the HALT with
//! `HaltWithNonZeroExitCode` and emits no record for the halting chunk. What can be produced is a
//! real bundle in which a chunk with no CPU rows carries a non-zero exit code, to exercise this
//! check directly.

use pico_vm::{
    compiler::program::ProgramBehavior,
    mle::machine::riscv::{self, air_id},
};

use super::fixture::{builder, emulate_fib_on, fib_program, LOG_STACKED_HEIGHT};
use crate::{
    artifact::{LoadedPayload, ProofArtifact},
    binding,
    phase::Phase,
    prover::emulator_opts,
    ProveError,
};

#[test]
fn a_proved_bundle_carrying_a_non_zero_exit_code_is_refused() {
    let program = fib_program();
    let mut emulated = emulate_fib_on(program.clone(), emulator_opts(1 << LOG_STACKED_HEIGHT));
    binding::backfill_final_digests(&mut emulated.records);
    let (chunk, record) = emulated
        .records
        .iter_mut()
        .enumerate()
        .find(|(_, record)| record.cpu_events.is_empty())
        .expect("the deferred split emits a chunk with no CPU rows");
    record.public_values.exit_code = 1;

    // A real bundle, proved and verified by the machine, so the refusals below are this crate's.
    let bundle = riscv::prove_riscv(
        program.clone(),
        &emulated.records,
        LOG_STACKED_HEIGHT,
        false,
    )
    .expect("the altered chunk still proves");
    riscv::verify_riscv(
        &bundle,
        bundle.vk.pre_hash,
        &[(air_id::PROGRAM, riscv::riscv_program_commit(&bundle.vk))],
        program.initial_global_cumulative_sum(),
    )
    .expect("the bundle verifies at the RISC-V layer");

    let mut prover = builder().build().expect("prover");
    let is_refused = |err: &ProveError| matches!(err, ProveError::NonZeroExitCode { chunk: c, exit_code: 1 } if *c == chunk);

    let artifact = ProofArtifact {
        log_stacked_height: LOG_STACKED_HEIGHT,
        verify_keys: false,
        program_id: prover.program_id(),
        committed: emulated.committed_bytes.clone(),
        payload: LoadedPayload::Riscv(bundle),
    };
    let err = prover
        .verify_artifact(artifact)
        .expect_err("a chunk exiting 1 must not verify as a successful run");
    assert!(is_refused(&err), "verify_artifact: got {err}");

    let err = prover
        .prove_records(&emulated.records, emulated.committed_bytes, Phase::Riscv)
        .expect_err("nor may the prover return a proof of it");
    assert!(is_refused(&err), "prove_records: got {err}");
}
