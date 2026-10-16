//! Runs split across more than one chunk: where the committed-value digest lives, and a commit that
//! straddles a chunk boundary.

use pico_vm::emulator::riscv::record::EmulationRecord;

use super::fixture::{assert_is_fib_output, builder, emulate_fib, N, SMALL_CHUNK};
use crate::{binding, phase::Phase, proof::Payload, prover::emulator_opts, Stdin};

/// A run whose halting chunk is not the first: the first proof's copy of the digest reads zero,
/// so the digest has to be read from a later one.
#[test]
fn a_multi_chunk_run_reads_the_digest_from_the_chunk_that_carries_it() {
    let mut prover = builder().chunk_size(SMALL_CHUNK).build().expect("prover");

    let execution = prover.execute(Stdin::from(&N)).expect("emulate");
    assert!(
        execution.chunks > 1,
        "a {SMALL_CHUNK}-instruction chunk must split this run, or the test asserts nothing: {} \
         chunk(s)",
        execution.chunks
    );

    let proof = prover
        .prove_to(Stdin::from(&N), Phase::Convert)
        .expect("convert");
    assert!(proof.chunk_count().unwrap_or(0) > 1);
    assert_is_fib_output(proof.committed().as_bytes(), N);

    let Payload::Convert(set) = &proof.payload else {
        panic!("a Convert proof carries its set");
    };
    let copies: Vec<[u8; 32]> = set
        .iter()
        .map(|(p, _)| binding::recursion_committed_digest(&p.public_values, Phase::Convert))
        .collect::<Result<_, _>>()
        .expect("each proof's copy");
    assert_eq!(
        copies[0], [0u8; 32],
        "the first proof carries the digest, so this run never reads past it"
    );
    assert!(copies.iter().any(|copy| *copy != [0u8; 32]));
}

/// A chunk size at which fib(10)'s eight COMMIT ecalls would fall on both sides of a chunk boundary
/// if the emulator did not hold the cut while the commit is in flight.
const COMMIT_SPLITTING_CHUNK: u32 = 9500;

/// The distinct nonzero committed-value digests across `records`.
fn nonzero_digests(records: &[EmulationRecord]) -> std::collections::BTreeSet<[u32; 8]> {
    records
        .iter()
        .map(|r| r.public_values.committed_value_digest)
        .filter(|d| d.iter().any(|&w| w != 0))
        .collect()
}

/// The emulator holds the cut until the commit is whole, so even at a chunk size that lands inside
/// it every record carries none or the final digest.
#[test]
fn the_emulator_keeps_the_commit_in_one_chunk() {
    let emulated = emulate_fib(emulator_opts(COMMIT_SPLITTING_CHUNK));
    assert!(emulated.records.len() > 1, "fib(10) fits one chunk");
    let digests = nonzero_digests(&emulated.records);
    assert_eq!(
        digests.len(),
        1,
        "a partial digest reached a record: {digests:?}"
    );
}

/// Should a commit still end up cut — the hold only spends a fixed reserve — the backfill leaves
/// every record with none or the final digest.
#[test]
fn a_commit_split_across_chunks_is_backfilled() {
    let mut emulated = emulate_fib(emulator_opts(COMMIT_SPLITTING_CHUNK));
    let last = emulated.records.last().expect("records").public_values;
    // The digest a chunk cut after its first three words would carry.
    let first = emulated
        .records
        .iter()
        .position(|r| {
            r.public_values
                .committed_value_digest
                .iter()
                .any(|&w| w != 0)
        })
        .expect("a record carrying the digest");
    let mut partial = last.committed_value_digest;
    partial[3..].fill(0);
    emulated.records[first].public_values.committed_value_digest = partial;
    assert!(nonzero_digests(&emulated.records).len() > 1);

    binding::backfill_final_digests(&mut emulated.records);
    let digests = nonzero_digests(&emulated.records);
    assert_eq!(digests.len(), 1, "a partial digest survived: {digests:?}");
    assert!(digests.contains(&last.committed_value_digest));
}

/// A chunk size that would split the commit, proved end to end: the commit tail stays in one chunk
/// and the combine root verifies.
#[test]
fn a_chunk_size_inside_the_commit_still_proves_to_combine() {
    let mut prover = builder()
        .chunk_size(COMMIT_SPLITTING_CHUNK)
        .build()
        .expect("prover");
    let proof = prover.prove(Stdin::from(&N)).expect("combine");
    assert_eq!(proof.phase(), Phase::Combine);
    assert_is_fib_output(proof.committed().as_bytes(), N);
}
