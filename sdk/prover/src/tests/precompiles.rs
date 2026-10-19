//! Guests that call the poseidon2 and Ed25519 precompiles, proved: the fixtures that say the MLE
//! RISC-V air table holds those three airs (ids 47, 48 and 49).
//!
//! Each is first checked to call its precompiles -- a guest that fell back to software would prove
//! without touching the three AIRs -- then proved to [`Phase::Convert`]: the RISC-V proof, where
//! the precompile AIRs are, and the convert proof over it, whose program carries one presence flag
//! per optional air, both verified.
//!
//! A chip the emulator serves and the table lacks is refused as `ProveError::UnsupportedChip`; no
//! chip in the pool is one (`vm/src/mle/machine/riscv.rs`,
//! `every_chip_the_emulator_serves_has_an_air`), so no guest here reaches it.

use pico_vm::emulator::riscv::syscalls::SyscallCode;

use super::fixture::{LOG_STACKED_HEIGHT, POSEIDON2_ELF};
use crate::{
    proof::{digest_words, Payload},
    Phase, Prover, Stdin,
};

/// Decompresses, adds and multiplies Ed25519 points
/// (`vm/examples/patch-testing/patches/curve25519-dalek-ng`).
const ED25519_ELF: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../perf/bench_data/rv64/ed25519-elf"
));

/// The basepoint, its negation and two scalars, as `vm/examples/common/parse_args.rs` writes them
/// for this guest.
fn ed25519_stdin() -> Stdin {
    let mut basepoint = [0x66u8; 32];
    basepoint[0] = 0x58;
    let mut negated = basepoint;
    negated[31] |= 0x80;
    let mut scalar = [0u8; 32];
    scalar[..4].copy_from_slice(&10u32.to_le_bytes());
    let mut second = scalar;
    second[4] = 1;
    let mut stdin = Stdin::new();
    stdin
        .write(&basepoint)
        .write(&negated)
        .write(&scalar)
        .write(&second);
    stdin
}

fn assert_proves(guest: &str, elf: &[u8], stdin: Stdin, calls: &[SyscallCode]) {
    let mut prover = Prover::builder(elf)
        .log_stacked_height(LOG_STACKED_HEIGHT)
        .build()
        .expect("prover");
    let made = prover
        .execute(stdin.clone())
        .expect("the guest emulates")
        .precompile_calls;
    for code in calls {
        assert!(
            made.contains_key(code),
            "{guest} never called {code:?}, so proving it covers none of that precompile's AIR: \
             {made:?}"
        );
    }
    let proof = prover
        .prove_to(stdin, Phase::Convert)
        .unwrap_or_else(|err| panic!("{guest}: {err}"));
    assert_eq!(proof.phase(), Phase::Convert);
    let Payload::Convert(set) = &proof.payload else {
        panic!("{guest}: a Convert proof carries its set");
    };
    let first = &set[0].1;
    assert_eq!(
        proof.vk_pre_hash(),
        Some(digest_words(&first.pre_hash)),
        "{guest}: a convert proof reports its first proof's key"
    );
    assert_eq!(
        proof.vk_merged_commit(),
        first
            .inner
            .merged_preprocessed_commit
            .as_ref()
            .map(digest_words)
    );
    assert!(
        proof.vk_merged_commit().is_some(),
        "{guest}: a recursion key is merged"
    );
}

#[test]
fn a_poseidon2_guest_proves() {
    assert_proves(
        "poseidon2",
        POSEIDON2_ELF,
        Stdin::from(&1u32),
        &[SyscallCode::POSEIDON2_PERMUTE],
    );
}

#[test]
fn an_ed25519_guest_proves() {
    assert_proves(
        "ed25519",
        ED25519_ELF,
        ed25519_stdin(),
        &[SyscallCode::ED_ADD, SyscallCode::ED_DECOMPRESS],
    );
}
