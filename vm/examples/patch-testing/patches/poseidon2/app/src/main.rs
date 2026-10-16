//! Guest exercise for the poseidon2 precompile.
//!
//! Hashes a 32-element `KoalaBear` buffer with `Poseidon2::hash_many` and feeds each result back
//! into the buffer, `n` times. `n` comes from stdin, which is what `--elf poseidon2 --n N` in
//! `vm/examples/common/parse_args.rs` writes there; the built ELF ships as
//! `perf/bench_data/rv64/poseidon2-elf`.
//!
//! The iteration count used to be a hard-coded 67000 while stdin went unread, so `--n` did
//! nothing and every invocation was a 201k-event run. Reading it left the loop as it was: the
//! buffer and `hash_many` are still the path it covers, and `--n 67000` runs the old loop. The
//! digests hashed after it (below) add four permutations and 96 committed bytes to every run.
//!
//! Feeding the result back gives every round a different input, so the loop's permutations are a
//! chain rather than one call repeated. It does not exercise the chip's canonicality constraints:
//! an honest run writes only canonical words. Those are tested against hand-built rows in
//! `vm/src/chips/precompiles/poseidon2/tests.rs`.
//!
//! After the loop it hashes three fixed inputs with `pico_sdk::poseidon2::hash`, the machine's
//! eight-element sponge, and commits each digest: `sdk/prover/src/tests/poseidon2.rs` holds them
//! to the host's `poseidon2_hash_iter` of the same elements. Their lengths -- `DIGEST_LENGTHS` --
//! take every exit the sponge has: no input at all, exactly one full block, and two full blocks
//! and half of a third (8 + 8 + 4).

#![no_main]
// `poseidon2_hash` is deprecated over its single-element output, not over the precompile
// underneath it -- which is what this file exists to exercise. See the attribute in
// `sdk/sdk/src/lib.rs`.
#![allow(deprecated)]

pico_sdk::entrypoint!(main);

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::KoalaBear;
use pico_sdk::poseidon2_hash::Poseidon2;

pub fn main() {
    let n: u32 = pico_sdk::io::read_as();

    let mut inputs: Vec<KoalaBear> = vec![KoalaBear::ONE; 32];

    println!("Starting Poseidon2 loop...");
    for _ in 0..n {
        let result = Poseidon2::hash_many(&inputs);
        inputs.fill(result);
    }
    println!("Finished Poseidon2 loop.");

    let out = inputs[0].as_canonical_u32();
    println!("poseidon2 hash_many x{n}: {out}");
    pico_sdk::io::commit(&out);

    for len in DIGEST_LENGTHS {
        let digest = pico_sdk::poseidon2::hash((1..=len).map(KoalaBear::from_u32));
        pico_sdk::io::commit(&digest.map(|f| f.as_canonical_u32()));
    }
}

/// The inputs hashed after the loop are `1..=len` for each of these. `sdk/prover/src/tests/
/// poseidon2.rs` and this case's prover repeat the list on the host; change all three together.
const DIGEST_LENGTHS: [u32; 3] = [0, 8, 20];
