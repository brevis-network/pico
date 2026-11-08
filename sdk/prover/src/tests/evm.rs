//! `Prover::prove_evm` and the `EvmBundle` it returns.
//!
//! One test here proves to wrap in the default suite, in dev mode; it runs in CI's wrap job. The
//! whitelist-mode run is opt-in for its cost.

use std::num::NonZeroUsize;

use pico_mle_core::{
    codec::Encode, p3_field::PrimeCharacteristicRing, protocol::proof_size::ProofShape,
};
use pico_vm::{
    compiler::recursion::circuit::wrap_mle::wrap_public_inputs,
    emulator::recursion::public_values::RECURSION_PUBLIC_VALUES_COL_MAP,
    mle::machine::{embed::EmbedSc, wrap::WrapArtifacts},
    primitives::consts::RECURSION_NUM_PVS,
};

use super::fixture::{
    assert_is_fib_output, builder, scratch_dir, shipped_whitelist, shipped_whitelist_builder,
    small_builder, N,
};
use crate::{
    evm::{be32, check_pinned_root, check_public_inputs, wrap_input_digest},
    phase::Phase,
    proof::{staged_path, write_wrap_files, Payload},
    types::Kb,
    EvmBundle, ProveError, Stdin, WRAP_CONSTRAINTS_FILE, WRAP_WITNESS_FILE,
};

/// Where the dev-mode wrap test leaves the bundle's two files, for a gnark solve after it; they go
/// to a scratch directory otherwise.
const WRAP_OUT: &str = "PICO_PROVER_WRAP_OUT";

/// Artifacts with nothing in them: enough to exercise the writer without a wrap proof.
fn empty_artifacts() -> WrapArtifacts {
    WrapArtifacts {
        constraints: Vec::new(),
        witness: Default::default(),
        vkey_hash: Default::default(),
        committed_values_digest: Default::default(),
        vk_root: None,
        num_extraction_squeezes: 0,
        num_vars: 0,
        num_felts: 0,
        num_exts: 0,
    }
}

fn staged(path: &std::path::Path) -> std::path::PathBuf {
    staged_path(path).expect("a file")
}

/// Staging changes no byte of what the vm's own writer produces, and leaves nothing behind.
#[test]
fn the_wrap_files_are_what_the_vm_writes() {
    let dir = scratch_dir("evm_write");
    let (constraints, witness) = (dir.join(WRAP_CONSTRAINTS_FILE), dir.join(WRAP_WITNESS_FILE));
    let artifacts = empty_artifacts();
    write_wrap_files(&artifacts, &constraints, &witness).expect("write");

    let (vm_constraints, vm_witness) = (dir.join("vm_constraints"), dir.join("vm_witness"));
    artifacts
        .save(
            vm_constraints.to_str().unwrap(),
            vm_witness.to_str().unwrap(),
        )
        .expect("the vm's writer");
    for (ours, vm) in [(&constraints, &vm_constraints), (&witness, &vm_witness)] {
        assert_eq!(std::fs::read(ours).unwrap(), std::fs::read(vm).unwrap());
        assert!(!staged(ours).exists(), "{} was left staged", ours.display());
    }
}

/// The vm's witness writer panics when it cannot create its file. The write returns an error
/// instead, and the old pair stays as it was.
#[test]
fn a_witness_that_cannot_be_written_is_an_error_and_keeps_the_old_pair() {
    let dir = scratch_dir("evm_write_panic");
    let (constraints, witness) = (dir.join(WRAP_CONSTRAINTS_FILE), dir.join(WRAP_WITNESS_FILE));
    std::fs::write(&constraints, "old circuit").unwrap();
    std::fs::write(&witness, "old witness").unwrap();
    // A directory where the staged witness goes: `File::create` fails on it.
    std::fs::create_dir(staged(&witness)).unwrap();

    let err = write_wrap_files(&empty_artifacts(), &constraints, &witness)
        .expect_err("the witness cannot be written");
    assert!(matches!(err, ProveError::Io { .. }), "got {err}");
    assert_eq!(
        std::fs::read_to_string(&constraints).unwrap(),
        "old circuit"
    );
    assert_eq!(std::fs::read_to_string(&witness).unwrap(), "old witness");
    assert!(!staged(&constraints).exists());
}

/// A new circuit that cannot be given its witness is removed, not left beside the old one.
#[test]
fn a_witness_that_cannot_be_moved_into_place_takes_the_new_circuit_with_it() {
    let dir = scratch_dir("evm_write_rename");
    let (constraints, witness) = (dir.join(WRAP_CONSTRAINTS_FILE), dir.join(WRAP_WITNESS_FILE));
    std::fs::write(&constraints, "old circuit").unwrap();
    // A non-empty directory cannot be replaced by a file.
    std::fs::create_dir(&witness).unwrap();
    std::fs::write(witness.join("keep"), "").unwrap();

    let err = write_wrap_files(&empty_artifacts(), &constraints, &witness)
        .expect_err("the witness path is a directory");
    assert!(matches!(err, ProveError::Io { .. }), "got {err}");
    assert!(
        !constraints.exists(),
        "the new circuit was left without its witness"
    );
    assert!(!staged(&constraints).exists() && !staged(&witness).exists());
}

/// Two paths whose staged names collide would have one move overwrite the other's file.
#[test]
fn colliding_paths_are_refused_before_anything_is_written() {
    let dir = scratch_dir("evm_write_collide");
    let witness = dir.join(WRAP_WITNESS_FILE);
    std::fs::write(&witness, "old witness").unwrap();
    for constraints in [witness.clone(), staged(&witness)] {
        let err = write_wrap_files(&empty_artifacts(), &constraints, &witness)
            .expect_err("the paths collide");
        assert!(matches!(err, ProveError::Io { .. }), "got {err}");
    }
    assert_eq!(std::fs::read_to_string(&witness).unwrap(), "old witness");
    assert_eq!(
        std::fs::read_dir(&*dir).unwrap().count(),
        1,
        "something was written"
    );
}

/// A lossy conversion would write under a name the caller never gave.
#[cfg(unix)]
#[test]
fn a_path_that_is_not_utf8_is_refused() {
    use std::os::unix::ffi::OsStrExt;

    let dir = scratch_dir("evm_write_utf8");
    let witness = dir.join(std::ffi::OsStr::from_bytes(b"\xffwitness.json"));
    let err = write_wrap_files(
        &empty_artifacts(),
        &dir.join(WRAP_CONSTRAINTS_FILE),
        &witness,
    )
    .expect_err("not UTF-8");
    assert!(matches!(err, ProveError::Io { .. }), "got {err}");
    assert_eq!(
        std::fs::read_dir(&dir).unwrap().count(),
        0,
        "something was written"
    );
}

/// Outside whitelist mode `prove_evm` refuses, and refuses first: the fib guest reads one element
/// and this input has none, so emulation would fail, and only a check made before it can return
/// the refusal instead.
#[test]
fn prove_evm_refuses_outside_whitelist_mode_before_emulating() {
    let mut prover = small_builder().build().expect("dev-mode prover");

    let emulated = prover
        .execute_chunked(Stdin::new())
        .expect_err("the fib guest reads one element");
    assert!(
        format!("{emulated}").contains("read past the end of stdin"),
        "this input must be one emulation rejects; got {emulated}"
    );

    let err = prover
        .prove_evm(Stdin::new())
        .expect_err("dev mode has no on-chain verifier");
    assert!(matches!(err, ProveError::EvmRequiresWhitelist), "got {err}");
}

/// The oracle is the VM's own `wrap_public_inputs`, the values the gnark witness is written from,
/// read off a real wrap of the fib guest. `prove_evm` refuses dev mode, so the bundle is assembled
/// here from the dev-mode proof, and the conversion `prove_evm` ends with is checked on it
/// separately.
#[test]
fn a_wrap_proof_gives_the_program_id_and_the_bundle_the_circuits_public_inputs() {
    let mut prover = builder().build().expect("prover");
    let mut proof = prover.prove_to(Stdin::from(&N), Phase::Wrap).expect("wrap");
    let Payload::Wrap { embed, artifacts } = &mut proof.payload else {
        panic!("a Phase::Wrap proof carries the wrap artifacts");
    };
    // The embed proof's wire size is the one its shape gives under the embed (BN254) encoding.
    let shape =
        ProofShape::from_proof(&embed.1.inner, &embed.0).expect("the embed proof's heights");
    assert_eq!(
        shape.encoded_len::<EmbedSc>(&embed.1.inner.params),
        embed
            .0
            .encode_to_vec()
            .expect("encode the embed proof")
            .len(),
        "the embed proof's wire size is not the one its shape gives ({shape:?})"
    );

    let (vkey_hash, committed_values_digest) = wrap_public_inputs(&embed.0);
    assert_eq!(vkey_hash, artifacts.vkey_hash);
    assert_eq!(committed_values_digest, artifacts.committed_values_digest);
    let expected = be32(vkey_hash);
    let expected_digest = be32(committed_values_digest);
    assert_ne!(
        expected, [0u8; 32],
        "an all-zero vkey_hash compares nothing"
    );
    assert_ne!(
        expected_digest, [0u8; 32],
        "an all-zero digest compares nothing"
    );

    // The fib digest's first byte has bit 5 clear, so it cannot tell a `0x1f` mask from `0x3f`.
    // A first byte of `0xff` through the vm's own packer sets all three bits it drops.
    let mut doctored = embed.0.clone();
    let pvs = doctored
        .public_values
        .iter_mut()
        .find(|p| p.len() == RECURSION_NUM_PVS)
        .expect("recursion public values");
    let mut digest: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(37));
    digest[0] = 0xff;
    let slots = RECURSION_PUBLIC_VALUES_COL_MAP
        .committed_value_digest
        .iter()
        .flat_map(|w| w.0);
    for (slot, byte) in slots.zip(digest) {
        pvs[slot] = Kb::from_u8(byte);
    }
    assert_eq!(
        be32(wrap_public_inputs(&doctored).1),
        wrap_input_digest(digest)
    );

    check_public_inputs(&proof).expect("the honest witness agrees with the proof");

    // A witness whose public inputs differ from the proof's, in either copy of either input.
    let refused = |proof: &crate::Proof| {
        matches!(
            check_public_inputs(proof),
            Err(ProveError::Verification {
                phase: Phase::Wrap,
                ..
            })
        )
    };
    let doctor: [fn(&mut WrapArtifacts); 4] = [
        |a| a.vkey_hash = a.committed_values_digest,
        |a| a.committed_values_digest = a.vkey_hash,
        |a| a.witness.vkey_hash.push('0'),
        |a| a.witness.committed_values_digest.push('0'),
    ];
    for (i, doctor) in doctor.iter().enumerate() {
        let Payload::Wrap { artifacts, .. } = &mut proof.payload else {
            unreachable!()
        };
        let (fields, strings) = (
            (artifacts.vkey_hash, artifacts.committed_values_digest),
            artifacts.witness.clone(),
        );
        doctor(artifacts);
        assert!(refused(&proof), "doctored witness {i} was accepted");
        let Payload::Wrap { artifacts, .. } = &mut proof.payload else {
            unreachable!()
        };
        (artifacts.vkey_hash, artifacts.committed_values_digest) = fields;
        artifacts.witness = strings;
    }

    // A guest that never committed carries an all-zero digest.
    let digest = proof.committed_value_digest;
    proof.committed_value_digest = [0; 32];
    assert!(matches!(
        check_public_inputs(&proof),
        Err(ProveError::EvmNoCommittedDigest)
    ));
    proof.committed_value_digest = digest;
    check_public_inputs(&proof).expect("restored");

    assert_eq!(proof.program_id().vkey_hash(), expected);
    assert_eq!(prover.program_id(), proof.program_id());

    // The root the circuit pins decides, not the root the bundle is handed: none is a dev-mode
    // wrap, and another one belongs to another whitelist.
    let root: [u32; 8] = std::array::from_fn(|i| 1000 + i as u32);
    let mut other = root;
    other[7] += 1;
    assert!(matches!(
        check_pinned_root(&proof, root),
        Err(ProveError::EvmRequiresWhitelist)
    ));
    let pin = |proof: &mut crate::Proof, root: Option<[u32; 8]>| {
        let Payload::Wrap { artifacts, .. } = &mut proof.payload else {
            unreachable!()
        };
        artifacts.vk_root = root.map(|r| r.map(Kb::from_u32));
    };
    pin(&mut proof, Some(root));
    check_pinned_root(&proof, root).expect("the root the circuit pins");
    assert!(matches!(
        check_pinned_root(&proof, other),
        Err(ProveError::Verification {
            phase: Phase::Wrap,
            ..
        })
    ));
    pin(&mut proof, None);

    let bundle = EvmBundle {
        proof,
        vk_root: [0; 8],
    };
    assert_eq!(bundle.program_id().vkey_hash(), expected);
    assert_eq!(bundle.committed_value_digest(), expected_digest);

    let dir = scratch_dir("evm_bundle");
    let out = std::env::var_os(WRAP_OUT).map_or_else(|| dir.join("bundle"), Into::into);
    bundle.write_to(&out).expect("write_to");
    for name in [WRAP_CONSTRAINTS_FILE, WRAP_WITNESS_FILE] {
        let len = std::fs::metadata(out.join(name))
            .unwrap_or_else(|e| panic!("{name}: {e}"))
            .len();
        assert!(len > 0, "{name} is empty");
    }

    let err = EvmBundle::from_wrap_proof(bundle.into_proof(), [0; 8])
        .expect_err("a dev-mode proof makes no bundle");
    assert!(matches!(err, ProveError::EvmRequiresWhitelist), "got {err}");

    println!(
        "[program-id] vkey_hash = 0x{}",
        expected
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    );
}

/// Chunks proved at once under the whitelist: a chunk that takes the catch-all shape needs about
/// 200 GB.
const WHITELIST_CONCURRENCY: usize = 2;

/// `prove_evm` end to end under the whitelist the repo ships, and the bundle's two public inputs
/// against the wrap circuit's, read off the same proof.
///
/// Run with `cargo test --release -p pico-prover -- --ignored --exact
/// tests::evm::prove_evm_under_the_shipped_whitelist --nocapture`: through compress and embed, about
/// 75 seconds and a 36 GiB peak for this guest on a 124-core host.
#[test]
#[ignore = "whitelist mode proved to wrap: tens of GB, a large machine's run"]
fn prove_evm_under_the_shipped_whitelist() {
    let (_, pinned) = shipped_whitelist();
    let mut prover = shipped_whitelist_builder()
        .concurrency(NonZeroUsize::new(WHITELIST_CONCURRENCY).expect("nonzero"))
        .build()
        .expect("whitelist prover");
    let bundle = prover
        .prove_evm(Stdin::from(&N))
        .expect("prove_evm under the shipped whitelist");
    assert!(bundle.proof().verify_keys());
    assert_eq!(bundle.proof().phase(), Phase::Wrap);
    assert_eq!(bundle.vk_root(), pinned);
    assert_eq!(bundle.program_id(), prover.program_id());
    assert_is_fib_output(bundle.committed().as_bytes(), N);

    let Payload::Wrap { embed, .. } = &bundle.proof().payload else {
        panic!("prove_evm returns a Phase::Wrap proof");
    };
    // The embed key the wrap circuit, and its Groth16 setup, are made for: the soundness manifest's
    // whitelist-set embed key. The vm crate's artifact test holds the key keygen'd over the
    // synthesized compress layout against the same row; this is the one a real `prove_evm` makes.
    let pre_hash: Vec<String> = embed.1.pre_hash.iter().map(|x| x.to_string()).collect();
    let merged: Option<Vec<String>> = embed
        .1
        .inner
        .merged_preprocessed_commit
        .map(|c| c.iter().map(|x| x.to_string()).collect());
    println!("[evm] embed key vk_pre_hash={pre_hash:?} merged_preprocessed_commit={merged:?}");
    let manifest: serde_json::Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../mle-core/tests/soundness_manifest.json"
    )))
    .expect("the soundness manifest parses");
    let row = manifest["keys"]
        .as_array()
        .expect("the manifest's keys")
        .iter()
        .find(|k| k["machine"] == "embed" && k["mode"] == "whitelist")
        .expect("the manifest's whitelist-set embed key");
    let decimals = |v: &serde_json::Value| -> Vec<String> {
        v.as_array()
            .expect("an array of decimal strings")
            .iter()
            .map(|x| x.as_str().expect("a decimal string").to_string())
            .collect()
    };
    let stale = "prove_evm's embed key is not the soundness manifest's whitelist-set embed key";
    assert_eq!(pre_hash, decimals(&row["vk_pre_hash"]), "{stale}");
    assert_eq!(
        merged,
        row.get("merged_preprocessed_commit").map(decimals),
        "{stale}"
    );
    // A whitelist-mode embed proof has the embed row's shape: the one embed shape the manifest
    // records, at the recorded wire size.
    let shape =
        ProofShape::from_proof(&embed.1.inner, &embed.0).expect("the embed proof's heights");
    let bytes = embed
        .0
        .encode_to_vec()
        .expect("encode the embed proof")
        .len() as u64;
    let recorded = &manifest["proof_shapes"]["embed"];
    assert_eq!(
        recorded["shapes"].as_u64(),
        Some(1),
        "the soundness manifest records other than one embed proof shape"
    );
    assert_eq!(
        (
            serde_json::from_value::<ProofShape>(recorded["largest"]["shape"].clone()).ok(),
            recorded["largest"]["bytes"].as_u64()
        ),
        (Some(shape), Some(bytes)),
        "prove_evm's embed proof is not the shape and size the soundness manifest records"
    );
    let (vkey_hash, committed_values_digest) = wrap_public_inputs(&embed.0);
    assert_eq!(bundle.program_id().vkey_hash(), be32(vkey_hash));
    assert_eq!(
        bundle.committed_value_digest(),
        be32(committed_values_digest)
    );

    let dir = scratch_dir("evm_whitelist");
    bundle.write_to(&dir).expect("write_to");
    for name in [WRAP_CONSTRAINTS_FILE, WRAP_WITNESS_FILE] {
        let len = std::fs::metadata(dir.join(name))
            .unwrap_or_else(|e| panic!("{name}: {e}"))
            .len();
        assert!(len > 0, "{name} is empty");
    }

    let hex = |bytes: [u8; 32]| bytes.iter().map(|b| format!("{b:02x}")).collect::<String>();
    println!(
        "[evm] whitelist-mode vkey_hash=0x{} committed_value_digest=0x{}",
        hex(bundle.program_id().vkey_hash()),
        hex(bundle.committed_value_digest())
    );
}
