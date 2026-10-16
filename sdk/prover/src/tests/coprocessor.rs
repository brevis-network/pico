//! The Pico-zkCoprocessor guest: what `pico-sdk`'s `coprocessor` feature commits, value by value.
//!
//! The guest (`vm/examples/patch-testing/patches/coprocessor`) commits 160 bytes: the input
//! commitment -- the Poseidon2 Merkle root over its 64 receipts -- then the three dummy
//! commitments, and last the SHA-256 of what it wrote to the coprocessor output stream (fd 9).
//! This runs it in the emulator and holds each to the value it has to be; it does not prove it.
//! The Poseidon2 precompile the root is computed through is proved in `precompiles.rs`, on the
//! poseidon2 guest.

use pico_vm::emulator::riscv::syscalls::SyscallCode;
use sha2::{Digest, Sha256};

use super::fixture::SMALL_LOG_STACKED_HEIGHT;
use crate::{Prover, Stdin};

/// The trading-volume guest built with `pico-sdk/coprocessor`.
const COPROCESSOR_ELF: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../perf/bench_data/rv64/coprocessor-elf"
));

/// The swap amount every receipt carries (`receipts.rs`, `field_0.value`), and the receipt count.
const SWAP_VALUE: u128 = 0x1_0d12_bdb1_67e2_01e0;
const RECEIPTS: u128 = 64;

/// The input commitment the guest commits, pinned. It is the root under coprocessor-sdk's
/// commitment scheme and the machine's KoalaBear Poseidon2, so it moves when either does -- and it
/// is the value the other side of a coprocessor proof has to reproduce.
const INPUT_COMMITMENT: [u8; 32] = [
    19, 184, 231, 255, 125, 71, 139, 14, 18, 208, 189, 136, 74, 90, 102, 89, 112, 16, 79, 28, 47,
    114, 129, 236, 32, 117, 165, 40, 108, 8, 154, 193,
];

/// The KoalaBear prime, `2^31 - 2^24 + 1`.
const KOALABEAR_P: u32 = 0x7f00_0001;

#[test]
fn the_coprocessor_guest_commits_its_inputs_and_its_volume() {
    let execution = Prover::builder(COPROCESSOR_ELF)
        .log_stacked_height(SMALL_LOG_STACKED_HEIGHT)
        .execute(Stdin::new())
        .expect("the coprocessor guest emulates");

    // Eight permutations per receipt leaf (106 elements at 15 a block, the last one padded) and two
    // per Merkle node (16 elements), over 64 leaves and 63 nodes. Every one is a precompile call.
    assert_eq!(
        execution
            .precompile_calls
            .get(&SyscallCode::POSEIDON2_PERMUTE)
            .copied(),
        Some(64 * 8 + 63 * 2),
        "Poseidon2 precompile calls"
    );

    let committed = &execution.committed_bytes;
    assert_eq!(committed.len(), 160, "the guest's committed layout changed");
    // The root is eight KoalaBear elements, each written big-endian; every one is canonical, since
    // the precompile writes only canonical words.
    for word in committed[..32].as_chunks::<4>().0 {
        let word = u32::from_be_bytes(*word);
        assert!(
            word < KOALABEAR_P,
            "input commitment word {word} is not canonical"
        );
    }
    assert_eq!(
        committed[..32],
        INPUT_COMMITMENT,
        "the input commitment moved"
    );
    assert_eq!(
        committed[32..128],
        [0u8; 96],
        "the guest's chain id is 0, which has no dummy commitments, so all three are zero"
    );

    // The output stream carried the summed volume as a big-endian `U256`.
    let mut volume = [0u8; 32];
    volume[16..].copy_from_slice(&(SWAP_VALUE * RECEIPTS).to_be_bytes());
    assert_eq!(
        committed[128..],
        Sha256::digest(volume)[..],
        "the output digest is not the SHA-256 of the volume"
    );
}
