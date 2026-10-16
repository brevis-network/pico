//! A real guest's committed bytes, read back the two ways the crate offers.

use super::fixture::{assert_is_fib_output, emulate_fib, LOG_STACKED_HEIGHT, N};
use crate::{committed::CommittedValues, prover::emulator_opts};

/// The fixture commits `(n, F(n), F(n+1))` ABI-encoded with `commit_bytes`: three 32-byte
/// big-endian words. `read::<(u32, u32, u32)>()` decodes the first word's zero padding without an
/// error, which is why the crate example decodes such output from `as_bytes` instead.
#[test]
fn abi_encoded_output_is_decoded_from_the_bytes_not_read() {
    let emulated = emulate_fib(emulator_opts(1 << LOG_STACKED_HEIGHT));

    let mut committed = CommittedValues::new(emulated.committed_bytes);
    let misread: (u32, u32, u32) = committed.read().expect("twelve bytes decode as three u32");
    assert_eq!(
        misread,
        (0, 0, 0),
        "the read landed on something other than padding"
    );
    assert_eq!(committed.remaining().len(), 96 - 12);

    assert_is_fib_output(committed.as_bytes(), N);
}
