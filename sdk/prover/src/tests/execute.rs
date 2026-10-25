//! Emulation without proving: the builder's keygen-free `execute` against the built prover's, and
//! the per-code precompile counts against the emulator's own.

use std::{collections::BTreeMap, sync::Arc};

use pico_vm::{
    compiler::riscv::compiler::{Compiler, SourceType},
    emulator::riscv::{
        emulator::RiscvEmulator, public_values::RecordFinalPvsState, syscalls::SyscallCode,
    },
    mle::machine::riscv::Kb,
};

use super::fixture::{
    small_builder, whitelist_builder, FIB_ELF, N, SMALL_CHUNK as CHUNK, SMALL_LOG_STACKED_HEIGHT,
};
use crate::{prover::emulator_opts, Execution, ProveError, Prover, Stdin};

/// Calls the BN254 base-field precompiles.
const BN254_FP_ELF: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../perf/bench_data/rv64/bn254-fp-elf"
));

/// Calls the BLS12-381 base-field precompiles.
const BLS12381_FP_ELF: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../perf/bench_data/rv64/bls12381-fp-elf"
));

fn assert_same_run(from_builder: &Execution, from_prover: &Execution) {
    assert_eq!(from_builder.committed_bytes, from_prover.committed_bytes);
    assert_eq!(from_builder.cycles, from_prover.cycles);
    assert_eq!(from_builder.chunks, from_prover.chunks);
    assert_eq!(from_builder.reports.len(), from_prover.reports.len());
    assert_eq!(from_builder.precompile_calls, from_prover.precompile_calls);
}

#[test]
fn the_builder_executes_the_run_the_built_prover_executes() {
    let builder = small_builder().chunk_size(CHUNK);
    let from_builder = builder.execute(Stdin::from(&N)).expect("builder execute");
    let from_prover = builder
        .build()
        .expect("prover")
        .execute(Stdin::from(&N))
        .expect("prover execute");
    assert!(
        from_builder.chunks > 1,
        "a {CHUNK}-instruction chunk must split this run, or the chunk counts compare nothing: {} \
         chunk(s)",
        from_builder.chunks
    );
    assert_same_run(&from_builder, &from_prover);
}

/// The whitelist binds proving only: `execute` runs without the artifact `build` refuses to go on
/// without.
#[test]
fn the_builder_executes_without_the_whitelist_build_requires() {
    let builder = whitelist_builder().verify_keys(true);
    builder
        .execute(Stdin::from(&N))
        .expect("execute needs no whitelist");
    let err = builder
        .build()
        .expect_err("build needs the whitelist artifact");
    assert!(
        matches!(err, ProveError::InconsistentOptions(_)),
        "got {err}"
    );
}

/// The chunk-size checks are the ones `build` makes, not a second copy of them.
#[test]
fn the_builder_refuses_the_chunk_sizes_build_refuses() {
    for (height, chunk) in [(SMALL_LOG_STACKED_HEIGHT, 0), (20, 1 << 21), (23, 1 << 24)] {
        let err = Prover::builder(FIB_ELF)
            .log_stacked_height(height)
            .chunk_size(chunk)
            .execute(Stdin::from(&N))
            .expect_err("an option build refuses");
        assert!(
            matches!(&err, ProveError::InconsistentOptions(m) if m.contains("chunk_size")),
            "height {height}, chunk {chunk}: got {err}"
        );
    }
}

/// The emulator's own counts for one run of every code that has its own table, keyed through
/// `SyscallCode::count_map` as the emulator keys them.
fn emulator_precompile_counts(elf: &[u8], chunk: u32) -> BTreeMap<SyscallCode, u64> {
    let program = Compiler::new(SourceType::RISCV, elf)
        .expect("the guest parses")
        .compile();
    let mut emulator = RiscvEmulator::new_single::<Kb>(
        program,
        Arc::new(RecordFinalPvsState::default()),
        emulator_opts(chunk),
        None,
    );
    emulator.write_stdin(&Stdin::new().into_emulator_stdin());
    while !emulator
        .emulate_batch(&mut |_| {})
        .expect("the guest emulates")
        .done
    {}
    emulator
        .state
        .syscall_counts
        .into_iter()
        .filter(|(code, _)| code.should_send() != 0)
        .collect()
}

/// Every precompile call is counted once, under the code the guest called: coalesced back the way
/// the emulator coalesces, the counts equal its own for every code that has its own table. The
/// records they are read from come after the deferred split, so this also shows the split neither
/// drops nor duplicates an event.
fn assert_counts_match_the_emulator(guest: &str, elf: &[u8]) {
    let started = std::time::Instant::now();
    let calls = Prover::builder(elf)
        .log_stacked_height(SMALL_LOG_STACKED_HEIGHT)
        .chunk_size(CHUNK)
        .execute(Stdin::new())
        .expect("execute")
        .precompile_calls;

    let expected = emulator_precompile_counts(elf, CHUNK);
    assert!(!expected.is_empty(), "{guest}: calls no precompile");
    let mut coalesced = BTreeMap::new();
    for (code, n) in &calls {
        *coalesced.entry(code.count_map()).or_insert(0) += n;
    }
    assert_eq!(coalesced, expected, "{guest}: per-code counts disagree");

    let split: Vec<_> = calls
        .iter()
        .filter(|(code, _)| code.count_map() != **code && calls.contains_key(&code.count_map()))
        .collect();
    assert!(
        !split.is_empty(),
        "{guest}: no coalesced code was called beside the code it coalesces into: {calls:?}"
    );
    println!(
        "[execute] {guest}: {calls:?}, {:.1}s",
        started.elapsed().as_secs_f64()
    );
}

#[test]
fn bn254_field_precompile_calls_are_counted_per_code() {
    assert_counts_match_the_emulator("bn254-fp", BN254_FP_ELF);
}

#[test]
fn bls12381_field_precompile_calls_are_counted_per_code() {
    assert_counts_match_the_emulator("bls12381-fp", BLS12381_FP_ELF);
}
