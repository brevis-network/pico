//! The zkevm-standards IO path, host to guest and back: [`Stdin::from_input`] hands one block to a
//! guest that reads it with `read_input` and writes with `write_output`, and the run's committed
//! bytes are everything it wrote, in order.
//!
//! The guest (`vm/examples/patch-testing/guests/standard-io`) panics unless repeated `read_input`
//! calls and `pico_sdk::io::input()` return the same block. It writes `b"io:"`, the input in 7-byte
//! pieces, a zero-length write from NULL, and the input's length as a little-endian `u64`.

use super::fixture::SMALL_LOG_STACKED_HEIGHT;
use crate::{Phase, Prover, Stdin};

const STANDARD_IO_ELF: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../perf/bench_data/rv64/standard-io-elf"
));

fn expected_output(input: &[u8]) -> Vec<u8> {
    let length = (input.len() as u64).to_le_bytes();
    [&b"io:"[..], input, &length[..]].concat()
}

/// Empty, one byte, not a multiple of the 8-byte word, and 64 KiB.
fn inputs() -> Vec<Vec<u8>> {
    vec![
        vec![],
        vec![0x2a],
        (0..13).collect(),
        (0..65536u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
            .collect(),
    ]
}

#[test]
fn one_block_in_and_every_written_byte_out() {
    for input in inputs() {
        let execution = Prover::builder(STANDARD_IO_ELF)
            .execute(Stdin::from_input(&input))
            .expect("the guest runs to a successful halt");
        assert_eq!(
            execution.committed_bytes,
            expected_output(&input),
            "input of {} byte(s)",
            input.len()
        );
    }
}

/// The proof binds the same bytes the execution reported.
#[test]
fn the_proof_commits_every_written_byte() {
    let input: Vec<u8> = (0..13).collect();
    let mut prover = Prover::builder(STANDARD_IO_ELF)
        .log_stacked_height(SMALL_LOG_STACKED_HEIGHT)
        .build()
        .expect("prover");
    let proof = prover
        .prove_to(Stdin::from_input(&input), Phase::Riscv)
        .expect("prove and verify");
    assert_eq!(proof.committed().as_bytes(), expected_output(&input));
}
