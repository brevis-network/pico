//! `verify_keys(true)` end to end, and the fresh-process verification only it makes possible.
//!
//! The whitelist is the one the repo ships, pinned to the root published beside it — the path a
//! caller takes. So beyond the machinery and the pinning, this checks that the keys this prover
//! derives for a real guest are members of the release whitelist.

use super::fixture::{
    assert_is_fib_output, run_child, scratch_dir, shipped_whitelist_builder, whitelist_builder, N,
};
use crate::{artifact::ProofArtifact, proof::Payload, ProveError, Stdin};

const CHILD_VAR: &str = "PICO_PROVER_WHITELIST_CHILD";
const PROOF_PATH: &str = "PICO_PROVER_WHITELIST_PROOF";
const MARKER: &str = "[whitelist] the pinned root accepted the root proof in a fresh process";
const ALTERED_FILE: &str = "altered_vk.pico";
const MODE_MARKER: &str = "[whitelist] the two modes gave the ELF two program ids";

/// The whitelist arm proves, and the root it produces verifies in a process that keygen'd nothing
/// — which is the only thing that makes a combine root portable between machines.
///
/// Run with `cargo test --release -p pico-prover -- --ignored --test-threads=1 --nocapture
/// tests::whitelist`, which also runs [`the_program_id_depends_on_the_mode`] and prints both
/// markers. It is out of the default suite for its cost, not its value: whitelist mode pads every
/// RISC-V chip to its catch-all height at a stacked height of 23, so the bucketed chain here is
/// orders of magnitude more work than the natural-height chain in `chain.rs`. What only this test
/// reaches is `verify_keys(true)` proving end to end and a root verifying through
/// `MleApexVerifier`.
#[test]
#[ignore = "whitelist mode pads every chip to its catch-all height: minutes and tens of GB"]
fn the_whitelist_path_proves_and_verifies_from_a_pinned_root() {
    if std::env::var(CHILD_VAR).is_ok() {
        return fresh_process_case();
    }

    let dir = scratch_dir("whitelist");
    let mut prover = shipped_whitelist_builder()
        .build()
        .expect("whitelist prover");
    let mut proof = prover.prove(Stdin::from(&N)).expect("whitelist chain");
    assert!(proof.verify_keys());
    assert_is_fib_output(proof.committed().as_bytes(), N);

    let proof_path = dir.join("combine.pico");
    proof.write(&proof_path).expect("write the root");

    // The whitelisted root key with its body altered under its own identity: its pre-hash and
    // merged commitment still name a member, its constraint set is no longer the one they were
    // computed from.
    let Payload::Combine(root) = &mut proof.payload else {
        panic!("a Combine proof carries a root");
    };
    let mut vk = (*root.1).clone();
    vk.inner.per_air[0].is_required = !vk.inner.per_air[0].is_required;
    root.1 = std::sync::Arc::new(vk);
    proof
        .write(dir.join(ALTERED_FILE))
        .expect("write the altered root");

    run_child(
        "tests::whitelist::the_whitelist_path_proves_and_verifies_from_a_pinned_root",
        MARKER,
        &[
            (CHILD_VAR, "1".to_string()),
            (PROOF_PATH, proof_path.to_string_lossy().into_owned()),
        ],
    );
}

/// One ELF, one height, two program ids: whitelist mode pads the program table before committing
/// to it, so a contract has to pin the whitelist-mode id, not the one a dev-mode prover reports.
#[test]
#[ignore = "keygens the program at the whitelist height in both modes; run with the whitelist test"]
fn the_program_id_depends_on_the_mode() {
    let dev = whitelist_builder().build().expect("dev-mode prover");
    let whitelist = shipped_whitelist_builder()
        .build()
        .expect("whitelist prover");

    assert_ne!(dev.program_id(), whitelist.program_id());
    assert_ne!(
        dev.program_id().vkey_hash(),
        whitelist.program_id().vkey_hash()
    );
    println!("{MODE_MARKER}");
}

fn fresh_process_case() {
    let proof_path = std::env::var(PROOF_PATH).expect("proof path");
    let prover = shipped_whitelist_builder()
        .build()
        .expect("whitelist verifier");

    let verified = prover
        .verify_artifact(ProofArtifact::read(&proof_path).expect("read"))
        .expect("a root proof must verify against the whitelist that produced it");
    assert_is_fib_output(verified.committed().as_bytes(), N);

    // The altered key never reaches the whitelist verifier: reading the file recomputes the key's
    // pre-hash from its body and refuses the mismatch.
    let altered = std::path::Path::new(&proof_path).with_file_name(ALTERED_FILE);
    let err = ProofArtifact::read(altered)
        .expect_err("a whitelisted identity over an altered key body must not load");
    assert!(
        matches!(err, ProveError::VkIdentityMismatch { .. }),
        "got {err}"
    );

    println!("{MARKER}");
}
