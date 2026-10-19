//! Guest exercise for the two Ed25519 precompiles.
//!
//! Every accelerated path the patched `curve25519-dalek-ng` offers is here: `decompress` (which
//! asks the `FD_EDDECOMPRESS` hook first and only then traps to `ED_DECOMPRESS`), scalar
//! multiplication and the double-base multiply, both of which run on `ED_ADD`. Point addition
//! and compression are field arithmetic in the crate, not precompiles; they are here because
//! they are what turns a decompressed point back into something comparable.
//!
//! The four 32-byte inputs come from stdin, which is what `--elf ed25519` in
//! `vm/examples/common/parse_args.rs` writes there; the built ELF ships as
//! `perf/bench_data/rv64/ed25519-elf`.
//!
//! Each result is committed. Without that the whole body is dead code: `let _ = point * scalar`
//! has no observable effect, and an optimised guest would drop the very syscalls this exists to
//! exercise.

#![no_main]
pico_sdk::entrypoint!(main);

use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
};
use pico_sdk::io::commit_bytes;

pub fn main() {
    let mut byte_arrays = [[0u8; 32]; 4];
    for byte_array in &mut byte_arrays {
        *byte_array = pico_sdk::io::read_as();
    }
    let [bytes1, bytes2, bytes3, bytes4] = byte_arrays;

    // Decompress
    let compressed1 = CompressedEdwardsY(bytes1);
    let point1 = compressed1.decompress().unwrap();
    let compressed2 = CompressedEdwardsY(bytes2);
    let point2 = compressed2.decompress().unwrap();

    // Compress
    commit_bytes(point1.compress().as_bytes());

    // Add
    commit_bytes((point1 + point2).compress().as_bytes());

    // Scalar Mul
    let scalar1 = Scalar::from_bytes_mod_order(bytes3);
    commit_bytes((point1 * scalar1).compress().as_bytes());

    // MSM
    let scalar2 = Scalar::from_bytes_mod_order(bytes4);
    commit_bytes(
        EdwardsPoint::vartime_double_scalar_mul_basepoint(&scalar1, &point1, &scalar2)
            .compress()
            .as_bytes(),
    );
}
