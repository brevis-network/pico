//! The guest runtime's memory functions against byte-by-byte references, run in the emulator: every
//! alignment, lengths 0 to 40 and longer ones, `memmove` over overlapping ranges, and `memcmp` /
//! `bcmp` on equal and differing ranges. The guest
//! (`vm/examples/patch-testing/guests/memory-functions`) exits with the failing function's number,
//! 1 `memcpy`, 2 `memset`, 3 `memmove` or 4 `memcmp` / `bcmp`, which the emulator reports as an
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
    // The assembly keeps every access aligned (`docs/guest-runtime.md`, "Memory functions"). The
    // guest is built without misaligned word accesses, so its own code makes none either.
    assert_eq!(execution.misaligned_accesses, 0);
}
