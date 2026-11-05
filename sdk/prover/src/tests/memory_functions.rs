//! The guest runtime's memory functions against byte-by-byte references, run in the emulator: every
//! alignment, lengths 0 to 40 and three longer ones, and `memmove` over overlapping ranges.
//! The guest (`vm/examples/patch-testing/guests/memory-functions`) exits with the failing
//! function's number, 1 `memcpy`, 2 `memset` or 3 `memmove`, which the emulator reports as an
//! abnormal termination.

use super::fixture::{MEMORY_FUNCTIONS_ELF, SMALL_LOG_STACKED_HEIGHT};
use crate::{Prover, Stdin};

#[test]
fn memcpy_memset_and_memmove_match_their_references() {
    let prover = Prover::builder(MEMORY_FUNCTIONS_ELF)
        .log_stacked_height(SMALL_LOG_STACKED_HEIGHT)
        .build()
        .expect("prover");
    let execution = prover
        .execute(Stdin::default())
        .unwrap_or_else(|e| panic!("a memory function fails its reference: {e}"));
    assert!(execution.committed_bytes.is_empty());
}
