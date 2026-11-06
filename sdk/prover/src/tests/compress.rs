//! The compress phase — the final compression layer — through the facade: what the proof
//! says about itself, the container it travels in, and what another prover can and cannot answer
//! for. One compress proof of fib serves every dev-mode assertion, and the combine root of the
//! same input serves the swapped-key cases: those two chains are the cost of the default run. Of
//! the two ignored whitelist tests, the shipped-whitelist one proves one whitelist chain and the
//! trimmed-map one three, one per entry point (`prove_to(Compress)`, `prove_to(Wrap)`,
//! `prove_evm`), each refused at compress.

use std::sync::Arc;

use pico_vm::mle::machine::vk_map::MleVkMap;

use super::fixture::{
    assert_is_fib_output, builder, run_child, scratch_dir, shipped_whitelist,
    shipped_whitelist_builder, whitelist_builder_with_map, N,
};
use crate::{
    artifact::ProofArtifact,
    phase::Phase,
    proof::{Payload, Proof},
    ProveError, Stdin,
};

const CHILD_VAR: &str = "PICO_PROVER_COMPRESS_CHILD";
const PROOF_PATH: &str = "PICO_PROVER_COMPRESS_PROOF";
const MARKER: &str =
    "[compress] the pinned whitelist accepted the compress proof in a fresh process";
/// The whitelisted compress key with its merged commitment altered: loads, is no member.
const ALTERED_COMMIT_FILE: &str = "compress-altered-commit.pico";
/// The container's header pre-hash altered (one bit flipped): refused at read.
const ALTERED_HEADER_FILE: &str = "compress-altered-header.pico";

/// The compress layer's acceptance line: the final proof is at most 300 KiB.
const SIZE_LIMIT: usize = 300 * 1024;

#[test]
fn a_compress_proof_round_trips_and_another_prover_refuses_it() {
    let mut prover = builder().build().expect("prover");
    let proof = prover
        .prove_to(Stdin::from(&N), Phase::Compress)
        .expect("compress");

    // What the proof says about itself.
    assert_eq!(proof.phase(), Phase::Compress);
    assert!(proof.binds_complete_execution());
    assert_is_fib_output(proof.committed().as_bytes(), N);
    assert_eq!(proof.proof_count(), 1);
    assert_eq!(proof.distinct_shapes(), Some(1));
    let pre_hash = proof
        .vk_pre_hash()
        .expect("a compress key is a KoalaBear-digest key");
    assert!(proof.vk_merged_commit().is_some());
    let size = proof.size_bytes().expect("size");
    assert!(
        size <= SIZE_LIMIT,
        "the compress proof is {size} bytes, past the {SIZE_LIMIT}-byte line"
    );

    // The container round-trips, and the prover that made it answers for it.
    let dir = scratch_dir("compress");
    let path = dir.join("proof-compress.pico");
    proof.write(&path).expect("write the compress proof");
    let artifact = ProofArtifact::read(&path).expect("read it back");
    assert_eq!(artifact.phase(), Phase::Compress);
    assert_eq!(artifact.claimed_program_id(), proof.program_id());
    let again = prover
        .verify_artifact(artifact)
        .expect("the prover that keygen'd the compress shape verifies its own file");
    assert_eq!(again.phase(), Phase::Compress);
    assert!(again.binds_complete_execution());
    assert_eq!(again.committed().as_bytes(), proof.committed().as_bytes());
    assert_eq!(again.vk_pre_hash(), Some(pre_hash));
    assert_eq!(
        again.chunk_count(),
        None,
        "a loaded container stores no count"
    );
    assert_eq!(
        again.distinct_shapes(),
        None,
        "verification keygens nothing"
    );

    // A container whose key does not hash to the identity its header names is refused before any
    // verification. The header's pre-hash words start at byte 12 (after the magic and the two
    // version words); the check is the container's own and does not depend on the payload variant.
    let honest = std::fs::read(&path).expect("proof file");
    let mut bytes = honest.clone();
    bytes[12] ^= 1;
    let altered_header = dir.join("proof-compress-altered-header.pico");
    std::fs::write(&altered_header, bytes).expect("write");
    assert!(
        matches!(
            ProofArtifact::read(&altered_header),
            Err(ProveError::VkIdentityMismatch { .. })
        ),
        "a key under a foreign identity was not refused"
    );

    // The compress proof and the combine root are the same proof type under the same key type, so
    // the two can be mixed: the compress proof under the root's key, and the root proof and key
    // under a Compress label. Both write consistent containers that no prover has an honest
    // compress shape for, and are refused by name.
    let root = prover.prove(Stdin::from(&N)).expect("combine");
    let Payload::Combine(root) = &root.payload else {
        panic!("a Phase::Combine proof carries the root");
    };
    let Payload::Compress(compress) = &proof.payload else {
        panic!("a Phase::Compress proof carries the compress proof");
    };
    let mixed = [
        (
            "the compress proof under the root's key",
            Payload::Compress(Box::new((compress.0.clone(), root.1.clone()))),
        ),
        (
            "the root proof and key under a Compress label",
            Payload::Compress(root.clone()),
        ),
    ];
    for (i, (case, payload)) in mixed.into_iter().enumerate() {
        let swapped = Proof {
            payload,
            ..proof_header(&proof)
        };
        let swapped_path = dir.join(format!("proof-compress-mixed-{i}.pico"));
        swapped
            .write(&swapped_path)
            .expect("the container does not judge keys");
        let err = prover
            .verify_artifact(ProofArtifact::read(&swapped_path).expect("read"))
            .expect_err(case);
        assert!(
            matches!(
                err,
                ProveError::WhitelistRequired {
                    phase: Phase::Compress
                }
            ),
            "{case}: got {err}"
        );
    }

    // Another prover outside whitelist mode has no compress shape and no apex to fall back on:
    // refused by name. (A second `Prover` in this process; the fresh-process
    // arm of the container is `tests/chain.rs`.)
    let another = builder().build().expect("a second prover");
    let err = another
        .verify_artifact(ProofArtifact::read(&path).expect("read"))
        .expect_err("another prover outside whitelist mode cannot answer for a compress file");
    assert!(
        matches!(
            err,
            ProveError::WhitelistRequired {
                phase: Phase::Compress
            }
        ),
        "got {err}"
    );
}

/// The identity fields of `proof`, for a `Proof` built around another payload; the payload here is
/// a placeholder the caller replaces.
fn proof_header(proof: &Proof) -> Proof {
    Proof {
        phase: proof.phase,
        program_id: proof.program_id,
        log_stacked_height: proof.log_stacked_height,
        verify_keys: proof.verify_keys,
        committed: proof.committed.clone(),
        committed_value_digest: proof.committed_value_digest,
        chunk_count: proof.chunk_count,
        distinct_shapes: proof.distinct_shapes,
        misaligned_accesses: proof.misaligned_accesses,
        payload: Payload::Convert(Vec::new()),
    }
}

/// A compress proof made under the shipped whitelist is answered for like a combine root: by a
/// second prover in this process that keygen'd no compress shape (so the apex, not a retained
/// key, answers), and by a fresh whitelist-mode process against the pinned root. The compress key
/// is a whitelist leaf. Two bad copies of the file: the key with its merged commitment
/// altered loads (the commitment is not in the pre-hash preimage) but is no whitelist member, so
/// the apex refuses it; a header pre-hash the key body does not hash to is refused at read.
///
/// Run with `cargo test --release -p pico-prover -- --ignored --test-threads=1 --nocapture
/// tests::compress`.
#[test]
#[ignore = "whitelist mode pads every chip to its catch-all height: minutes and tens of GB"]
fn a_whitelist_mode_compress_proof_verifies_through_the_apex() {
    if std::env::var(CHILD_VAR).is_ok() {
        return fresh_process_case();
    }

    let dir = scratch_dir("compress-whitelist");
    let mut prover = shipped_whitelist_builder()
        .build()
        .expect("whitelist prover");
    let mut proof = prover
        .prove_to(Stdin::from(&N), Phase::Compress)
        .expect("whitelist compress");
    assert!(proof.verify_keys());
    assert_eq!(proof.phase(), Phase::Compress);
    assert_is_fib_output(proof.committed().as_bytes(), N);
    let path = dir.join("compress.pico");
    proof.write(&path).expect("write the compress proof");

    // The prover that made it, then one built the same way that keygen'd no compress shape: the
    // second has only the apex to answer with.
    let again = prover
        .verify_artifact(ProofArtifact::read(&path).expect("read"))
        .expect("the prover that made the compress proof answers for its file");
    assert_eq!(again.phase(), Phase::Compress);
    let other = shipped_whitelist_builder()
        .build()
        .expect("a second whitelist prover");
    let verified = other
        .verify_artifact(ProofArtifact::read(&path).expect("read"))
        .expect(
            "a whitelist-mode prover with no compress shape verifies the file through the apex",
        );
    assert_is_fib_output(verified.committed().as_bytes(), N);

    // The key's merged commitment altered under its own pre-hash: the identity the whitelist
    // indexes changes, the pre-hash the reader recomputes does not.
    let Payload::Compress(compress) = &mut proof.payload else {
        panic!("a Compress proof carries the compress proof");
    };
    let mut vk = (*compress.1).clone();
    let commit = vk
        .inner
        .merged_preprocessed_commit
        .as_mut()
        .expect("a compress key is merged-preprocessed");
    assert_ne!(
        commit[0], commit[1],
        "the swap below must change the commitment"
    );
    commit.swap(0, 1);
    compress.1 = Arc::new(vk);
    proof
        .write(dir.join(ALTERED_COMMIT_FILE))
        .expect("the container does not judge keys");
    // The header's pre-hash words start at byte 12 (after the magic and the two version words).
    let mut bytes = std::fs::read(&path).expect("proof file");
    bytes[12] ^= 1;
    std::fs::write(dir.join(ALTERED_HEADER_FILE), bytes).expect("write");

    run_child(
        "tests::compress::a_whitelist_mode_compress_proof_verifies_through_the_apex",
        MARKER,
        &[
            (CHILD_VAR, "1".to_string()),
            (PROOF_PATH, path.to_string_lossy().into_owned()),
        ],
    );
}

fn fresh_process_case() {
    let proof_path = std::env::var(PROOF_PATH).expect("proof path");
    let prover = shipped_whitelist_builder()
        .build()
        .expect("whitelist verifier");

    let verified = prover
        .verify_artifact(ProofArtifact::read(&proof_path).expect("read"))
        .expect("a compress proof must verify against the whitelist that produced it");
    assert_eq!(verified.phase(), Phase::Compress);
    assert_is_fib_output(verified.committed().as_bytes(), N);

    // The altered commitment loads and reaches the apex, which finds no such member.
    let altered = std::path::Path::new(&proof_path).with_file_name(ALTERED_COMMIT_FILE);
    let artifact = ProofArtifact::read(&altered)
        .expect("the altered copy loads: its key body still hashes to its pre-hash");
    let err = prover
        .verify_artifact(artifact)
        .expect_err("a key outside the whitelist must be refused");
    assert!(
        matches!(
            err,
            ProveError::Verification {
                phase: Phase::Compress,
                ..
            }
        ) && err.to_string().contains("not in the whitelist"),
        "got {err}"
    );

    // The altered header never reaches the whitelist verifier.
    let altered = std::path::Path::new(&proof_path).with_file_name(ALTERED_HEADER_FILE);
    assert!(
        matches!(
            ProofArtifact::read(&altered),
            Err(ProveError::VkIdentityMismatch { .. })
        ),
        "a key under a foreign identity was not refused"
    );

    println!("{MARKER}");
}

/// With the whitelist's compress leaf dropped, a whitelist-mode prover refuses to make a compress
/// proof: its key is keygen'd and looked up before anything is proved under it, so no file that no
/// apex would accept is ever written. The map is the shipped artifact without its last leaf,
/// re-rooted; the chain up to the root still proves under it. Embed and wrap pass through
/// compress, so `prove_to(Wrap)` and `prove_evm` are refused the same way, at compress.
#[test]
#[ignore = "whitelist mode pads every chip to its catch-all height: minutes and tens of GB"]
fn a_compress_key_outside_the_whitelist_is_refused() {
    let (path, _) = shipped_whitelist();
    let shipped = MleVkMap::load_bin(&path);
    let mut ids = shipped.entries.clone();
    // The last leaf is the compress node: `the_shipped_artifact_matches_this_binary` pins the
    // leaf order.
    let _compress_leaf = ids.pop().expect("the compress leaf");
    let map = MleVkMap::build(ids);
    let dir = scratch_dir("compress-trimmed-map");
    let mut prover = whitelist_builder_with_map(&map, &dir)
        .build()
        .expect("whitelist prover under the trimmed map");
    let err = prover
        .prove_to(Stdin::from(&N), Phase::Compress)
        .expect_err("the compress key is no member of the trimmed map");
    assert!(
        matches!(
            err,
            ProveError::KeyNotWhitelisted {
                phase: Phase::Compress,
                missing: 1
            }
        ),
        "got {err}"
    );
    #[cfg(feature = "multi-field-transcript")]
    {
        let refused = |err: ProveError| {
            assert!(
                matches!(
                    err,
                    ProveError::KeyNotWhitelisted {
                        phase: Phase::Compress,
                        missing: 1
                    }
                ),
                "got {err}"
            )
        };
        refused(
            prover
                .prove_to(Stdin::from(&N), Phase::Wrap)
                .expect_err("wrap passes through compress, whose key is no member"),
        );
        refused(
            prover
                .prove_evm(Stdin::from(&N))
                .expect_err("prove_evm passes through compress, whose key is no member"),
        );
    }
}
