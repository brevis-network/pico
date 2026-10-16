//! `pico_sdk::poseidon2::hash` in a guest, against the machine's own sponge on the host.
//!
//! The poseidon2 guest (`vm/examples/patch-testing/patches/poseidon2`) commits, after its loop, the
//! digest of `1..=len` for each length in [`DIGEST_LENGTHS`]. Those digests come out of the
//! Poseidon2 precompile; the host hashes the same elements with `poseidon2_hash_iter`. Equal
//! digests say the guest runs the machine's sponge and not merely an eight-element Poseidon2.

use pico_mle_core::p3_field::{PrimeCharacteristicRing, PrimeField32};
use pico_vm::{
    emulator::riscv::syscalls::SyscallCode,
    mle::machine::riscv::Kb,
    primitives::{consts::DIGEST_SIZE, Poseidon2HashField},
};

use super::fixture::{POSEIDON2_ELF, SMALL_LOG_STACKED_HEIGHT};
use crate::{Prover, Stdin};

/// The guest's list, repeated: it hashes `1..=len` for each. Change the two together.
const DIGEST_LENGTHS: [u32; 3] = [0, 8, 20];

/// The guest's loop runs this many times; each `hash_many` over its 32 elements permutes three
/// times (15 + 15 absorbed, then the last two padded).
const LOOP_ROUNDS: u32 = 1;

#[test]
fn the_guest_hash_is_the_machines_poseidon2_hash_iter() {
    let execution = Prover::builder(POSEIDON2_ELF)
        .log_stacked_height(SMALL_LOG_STACKED_HEIGHT)
        .execute(Stdin::from(&LOOP_ROUNDS))
        .expect("the poseidon2 guest emulates");

    // `commit(&out)` first, one `u32`; then one `[u32; DIGEST_SIZE]` per length, bincode's fixed
    // little-endian words with no length prefix.
    let committed = &execution.committed_bytes;
    let digest_bytes = DIGEST_SIZE * 4;
    assert_eq!(
        committed.len(),
        4 + DIGEST_LENGTHS.len() * digest_bytes,
        "the guest's committed layout changed"
    );
    for (k, &len) in DIGEST_LENGTHS.iter().enumerate() {
        let start = 4 + k * digest_bytes;
        let guest: Vec<u32> = committed[start..start + digest_bytes]
            .as_chunks::<4>()
            .0
            .iter()
            .map(|word| u32::from_le_bytes(*word))
            .collect();
        let host: Vec<u32> = Kb::poseidon2_hash_iter((1..=len).map(Kb::from_u32).collect())
            .iter()
            .map(|f| f.as_canonical_u32())
            .collect();
        assert_eq!(
            guest, host,
            "digest of 1..={len}: the guest's hash is not the machine's"
        );
    }

    // The digests alone would also match a guest that permuted in software. This says every
    // permutation went through the precompile, as many as the sponge takes: none for the empty
    // input, one for the single full block -- a block that absorbs nothing is not permuted
    // again -- and three for 8 + 8 + 4.
    let permutations = LOOP_ROUNDS as u64 * 3 + 1 + 3;
    assert_eq!(
        execution
            .precompile_calls
            .get(&SyscallCode::POSEIDON2_PERMUTE)
            .copied(),
        Some(permutations),
        "Poseidon2 precompile calls"
    );
}
