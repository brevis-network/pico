//! The facade against an independent run of the machines, and the container against a fresh
//! process.
//!
//! The oracle is the direct machine path below, driven exactly as `vm/examples/test_mle_e2e.rs`
//! drives it. It shares the emulator options with the facade deliberately: the two arms must differ
//! in one thing only, which is who sequences the chain.
//!
//! Nothing here compares proof bytes. The proof-of-work grind searches in parallel, so two honest
//! runs of the same input select different witnesses and diverge; byte equality would be a flake,
//! not an oracle. What is compared is what the two runs mean.

use pico_mle_core::{
    config::recursion_params_with_100_bits_security,
    p3_field::{PrimeCharacteristicRing, PrimeField32},
    StarkEngine,
};
use pico_vm::{
    compiler::{
        program::ProgramBehavior,
        riscv::{
            compiler::{Compiler, SourceType},
            program::Program,
        },
    },
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{recursion::public_values::RECURSION_PUBLIC_VALUES_COL_MAP, stdin::EmulatorStdin},
    mle::machine::{
        combine::CombineMachine,
        convert::{ConvertMachine, ProofWithVk},
        exe::RiscvVmVk,
        riscv::{self, air_id, RiscvProof},
    },
    primitives::consts::RECURSION_NUM_PVS,
};

use super::fixture::{
    assert_is_fib_output, builder, run_child, scratch_dir, FIB_ELF, LOG_STACKED_HEIGHT, N,
};
use crate::{
    artifact::ProofArtifact,
    binding,
    error::ProveError,
    phase::Phase,
    proof::{Payload, Proof},
    prover::{emulator_opts, ProgramId},
    Stdin,
};

const CHILD_VAR: &str = "PICO_PROVER_FRESH_PROCESS";
const ARTIFACT_DIR: &str = "PICO_PROVER_ARTIFACT_DIR";

fn words(digest: &[crate::types::Kb; 8]) -> [u32; 8] {
    digest.map(|f| f.as_canonical_u32())
}

/// What one run of the chain means, independent of the bytes it produced.
#[derive(Debug)]
struct Facts {
    program_id: [u32; 8],
    chunk_count: usize,
    riscv_vk_pre_hash: [u32; 8],
    committed_value_digest: [u8; 32],
    committed: Vec<u8>,
    combine_vk_pre_hash: [u32; 8],
    combine_vk_merged: Option<[u32; 8]>,
}

struct Direct {
    facts: Facts,
    riscv: RiscvProof,
    root: ProofWithVk,
}

/// The chain driven straight against the machines, as the end-to-end example drives it.
fn direct_chain(n: u32) -> Direct {
    let program = Compiler::new(SourceType::RISCV, FIB_ELF)
        .expect("parse the fib ELF")
        .compile();

    let mut stdin = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    stdin.write(&n);
    let stdin = stdin.finalize();

    let emulated = riscv::emulate_with_opts(
        program.clone(),
        &stdin,
        emulator_opts(1 << LOG_STACKED_HEIGHT),
    )
    .expect("emulation");

    let bundle = riscv::prove_riscv(
        program.clone(),
        &emulated.records,
        LOG_STACKED_HEIGHT,
        false,
    )
    .expect("riscv prove");
    let initial_gcs = program.initial_global_cumulative_sum();
    riscv::verify_riscv(
        &bundle,
        bundle.vk.pre_hash,
        &[(air_id::PROGRAM, riscv::riscv_program_commit(&bundle.vk))],
        initial_gcs,
    )
    .expect("riscv verify");

    let chunk_count = bundle.chunk_proofs.len();
    let riscv_vk_pre_hash = words(&bundle.vk.pre_hash);
    let committed_value_digest =
        binding::riscv_committed_digest(&bundle.chunk_proofs).expect("digest");

    let riscv_vm_vk = RiscvVmVk::from_program_and_vk(&program, &bundle.vk);
    let program_id = words(&riscv_vm_vk.digest());

    let keep = RiscvProof {
        vk: bundle.vk.clone(),
        chunk_proofs: bundle.chunk_proofs.clone(),
    };
    let (riscv_vk, riscv_proofs) = bundle.into_parts();

    let convert = ConvertMachine::new(
        riscv_vk,
        riscv_vm_vk.clone(),
        &riscv_proofs,
        recursion_params_with_100_bits_security(),
        false,
    )
    .expect("convert machine");
    let convert_proofs = convert
        .prove_with_vks(&riscv_proofs)
        .expect("convert prove");
    for (proof, vk) in &convert_proofs {
        convert.engine.verify(&**vk, proof).expect("convert verify");
    }

    let mut combine = CombineMachine::new(
        recursion_params_with_100_bits_security(),
        riscv_vm_vk,
        false,
    );
    let root = combine.prove_tree(convert_proofs).expect("combine prove");
    combine.verify(&root).expect("combine verify");

    Direct {
        facts: Facts {
            program_id,
            chunk_count,
            riscv_vk_pre_hash,
            committed_value_digest,
            committed: emulated.committed_bytes,
            combine_vk_pre_hash: words(&root.1.pre_hash),
            combine_vk_merged: root.1.inner.merged_preprocessed_commit.as_ref().map(words),
        },
        riscv: keep,
        root,
    }
}

/// Wrap a payload the direct path produced as a [`Proof`], so the facade's own container and
/// verification entry point can be pointed at it. Only reachable from inside the crate, which is
/// the point: this is the cross-verification arm, not an API.
fn as_proof(facts: &Facts, phase: Phase, payload: Payload) -> Proof {
    Proof {
        phase,
        program_id: ProgramId::from_words(facts.program_id),
        log_stacked_height: LOG_STACKED_HEIGHT,
        verify_keys: false,
        committed: facts.committed.clone(),
        committed_value_digest: facts.committed_value_digest,
        chunk_count: Some(facts.chunk_count),
        distinct_shapes: Some(1),
        payload,
    }
}

/// The facade proves the same thing the chain does, and each side's proof is accepted by the
/// other. The container round-trips through a fresh process, and its two version fields are
/// checked before any verification runs.
#[test]
fn the_facade_proves_what_the_direct_chain_proves() {
    if std::env::var(CHILD_VAR).is_ok() {
        return fresh_process_cases();
    }

    let direct = direct_chain(N);
    assert_is_fib_output(&direct.facts.committed, N);

    let mut prover = builder().build().expect("prover");
    let riscv_proof = prover
        .prove_to(Stdin::from(&N), Phase::Riscv)
        .expect("facade riscv");
    let combine_proof = prover.prove(Stdin::from(&N)).expect("facade combine");

    // the two runs mean the same thing
    assert_eq!(riscv_proof.phase(), Phase::Riscv);
    assert_eq!(combine_proof.phase(), Phase::Combine);
    assert_eq!(
        riscv_proof.program_id().as_words(),
        direct.facts.program_id,
        "the facade attests to a different program"
    );
    assert_eq!(combine_proof.program_id(), riscv_proof.program_id());
    assert_eq!(riscv_proof.chunk_count(), Some(direct.facts.chunk_count));
    assert_eq!(
        riscv_proof.vk_pre_hash(),
        Some(direct.facts.riscv_vk_pre_hash),
        "the facade keygen'd a different RISC-V key"
    );
    assert_eq!(
        riscv_proof.committed_value_digest(),
        direct.facts.committed_value_digest,
        "the two runs committed different output"
    );
    assert_eq!(
        combine_proof.committed_value_digest(),
        direct.facts.committed_value_digest,
        "the recursion layer lost the committed-value digest"
    );
    assert_eq!(
        combine_proof.vk_pre_hash(),
        Some(direct.facts.combine_vk_pre_hash),
        "the facade keygen'd a different root shape"
    );
    assert_eq!(
        combine_proof.vk_merged_commit(),
        direct.facts.combine_vk_merged,
        "the facade's root circuit is not the direct path's"
    );
    assert_eq!(riscv_proof.proof_count(), direct.facts.chunk_count);
    assert_eq!(combine_proof.proof_count(), 1);
    assert_eq!(riscv_proof.distinct_shapes(), Some(1));

    // the committed bytes are the guest's, checked against a host-computed value
    let committed = combine_proof.committed();
    assert_is_fib_output(committed.as_bytes(), N);
    assert_eq!(committed.as_bytes(), direct.facts.committed.as_slice());

    // cross-verification, each side's proof through the other's verifier
    riscv::verify_riscv(
        match &riscv_proof.payload {
            Payload::Riscv(bundle) => bundle,
            _ => unreachable!("a Phase::Riscv proof carries a RISC-V bundle"),
        },
        direct.riscv.vk.pre_hash,
        &[(
            air_id::PROGRAM,
            riscv::riscv_program_commit(&direct.riscv.vk),
        )],
        Compiler::new(SourceType::RISCV, FIB_ELF)
            .expect("elf")
            .compile()
            .initial_global_cumulative_sum(),
    )
    .expect("the facade's RISC-V bundle must verify under the direct path's trusted inputs");

    let dir = scratch_dir("chain");
    let direct_riscv_file = dir.join("direct_riscv.pico");
    as_proof(
        &direct.facts,
        Phase::Riscv,
        Payload::Riscv(RiscvProof {
            vk: direct.riscv.vk.clone(),
            chunk_proofs: direct.riscv.chunk_proofs.clone(),
        }),
    )
    .write(&direct_riscv_file)
    .expect("write the direct bundle");
    prover
        .verify_artifact(ProofArtifact::read(&direct_riscv_file).expect("read"))
        .expect("the direct path's RISC-V bundle must verify through the facade's entry point");

    let direct_root_file = dir.join("direct_combine.pico");
    as_proof(
        &direct.facts,
        Phase::Combine,
        Payload::Combine(Box::new(direct.root.clone())),
    )
    .write(&direct_root_file)
    .expect("write the direct root");
    prover
        .verify_artifact(ProofArtifact::read(&direct_root_file).expect("read"))
        .expect("the direct path's root must verify on the facade's own keygen'd shapes");

    // what the container refuses to carry
    // The payload is irrelevant here; the refusal is by phase, because no verification entry point
    // can answer for a convert proof from a file.
    let err = as_proof(&direct.facts, Phase::Convert, Payload::Convert(Vec::new()))
        .write(dir.join("convert.pico"))
        .expect_err("a convert proof has no fresh-process verification path");
    assert!(
        matches!(
            err,
            ProveError::UnverifiableInFreshProcess {
                phase: Phase::Convert
            }
        ),
        "got {err}"
    );

    // the artifacts the fresh process is given
    let riscv_file = dir.join("riscv.pico");
    riscv_proof.write(&riscv_file).expect("write riscv");
    let combine_file = dir.join("combine.pico");
    combine_proof.write(&combine_file).expect("write combine");

    let honest = std::fs::read(&riscv_file).expect("read back");
    std::fs::write(dir.join("bad_format.pico"), patch_word(&honest, 4, 999)).expect("write");
    std::fs::write(dir.join("bad_codec.pico"), patch_word(&honest, 8, 999)).expect("write");
    // The header's copy of the stored key's identity moved, the body's did not.
    let claimed = u32::from_le_bytes(honest[12..16].try_into().expect("header word"));
    std::fs::write(
        dir.join("bad_vk_identity.pico"),
        patch_word(&honest, 12, claimed.wrapping_add(1)),
    )
    .expect("write");

    // Output bytes swapped for forged ones of the same length, the proof left untouched.
    let mut forged = as_proof(
        &direct.facts,
        Phase::Riscv,
        Payload::Riscv(RiscvProof {
            vk: direct.riscv.vk.clone(),
            chunk_proofs: direct.riscv.chunk_proofs.clone(),
        }),
    );
    forged.committed = vec![0xAB; direct.facts.committed.len()];
    forged
        .write(dir.join("forged_committed.pico"))
        .expect("write");

    // A root paired with a verifying key the verifier never keygen'd for it.
    as_proof(
        &direct.facts,
        Phase::Combine,
        Payload::Combine(Box::new((direct.root.0.clone(), direct.riscv.vk.clone()))),
    )
    .write(dir.join("hostile_vk.pico"))
    .expect("write");

    // The honest root's key with its body altered and its stored identity kept.
    let mut altered_vk = (*direct.root.1).clone();
    altered_vk.inner.per_air[0].is_required = !altered_vk.inner.per_air[0].is_required;
    as_proof(
        &direct.facts,
        Phase::Combine,
        Payload::Combine(Box::new((
            direct.root.0.clone(),
            std::sync::Arc::new(altered_vk),
        ))),
    )
    .write(dir.join("altered_vk.pico"))
    .expect("write");

    // The same root with only its complete flag cleared; everything else is the accepted case.
    let mut incomplete = direct.root.clone();
    for pvs in incomplete.0.public_values.iter_mut() {
        if pvs.len() == RECURSION_NUM_PVS {
            pvs[RECURSION_PUBLIC_VALUES_COL_MAP.flag_complete] = crate::types::Kb::ZERO;
        }
    }
    as_proof(
        &direct.facts,
        Phase::Combine,
        Payload::Combine(Box::new(incomplete)),
    )
    .write(dir.join("incomplete.pico"))
    .expect("write");

    run_child(
        "tests::chain::the_facade_proves_what_the_direct_chain_proves",
        FRESH_MARKER,
        &[
            (CHILD_VAR, "1".to_string()),
            (ARTIFACT_DIR, dir.to_string_lossy().into_owned()),
        ],
    );
}

const FRESH_MARKER: &str = "[fresh] every fresh-process case behaved";

fn patch_word(bytes: &[u8], at: usize, value: u32) -> Vec<u8> {
    let mut out = bytes.to_vec();
    out[at..at + 4].copy_from_slice(&value.to_le_bytes());
    out
}

/// What a process that has proved nothing accepts from a container and what it refuses: one
/// prover, built from the ELF alone.
fn fresh_process_cases() {
    let dir = std::path::PathBuf::from(std::env::var(ARTIFACT_DIR).expect("artifact dir"));
    let prover = builder().build().expect("prover");

    // (1) an honest RISC-V proof is ACCEPTED — without this the rest is just "everything fails".
    let accepted = prover
        .verify_artifact(ProofArtifact::read(dir.join("riscv.pico")).expect("read"))
        .expect("an honest RISC-V artifact must verify from the ELF alone");
    assert_is_fib_output(accepted.committed().as_bytes(), N);
    assert_eq!(
        accepted.distinct_shapes(),
        None,
        "verification keygens nothing"
    );

    // (2) output bytes swapped, proof untouched: rejected by the SHA-256 rebinding.
    let err = prover
        .verify_artifact(ProofArtifact::read(dir.join("forged_committed.pico")).expect("read"))
        .expect_err("forged output bytes must not be readable");
    assert!(
        matches!(err, ProveError::CommittedValuesUnbound),
        "got {err}"
    );

    // (3) an honest recursion proof with no whitelist: refused by name, never answered with
    // something that resembles verification.
    let err = prover
        .verify_artifact(ProofArtifact::read(dir.join("combine.pico")).expect("read"))
        .expect_err("a recursion proof cannot be verified from a file without a whitelist");
    assert!(
        matches!(
            err,
            ProveError::WhitelistRequired {
                phase: Phase::Combine
            }
        ),
        "got {err}"
    );

    // (4) a root carrying a key of the file's choosing: the same refusal, and nothing keygens from
    // the file. There is no configuration in which the container's key reaches a verifier circuit.
    let err = prover
        .verify_artifact(ProofArtifact::read(dir.join("hostile_vk.pico")).expect("read"))
        .expect_err("a hostile verifying key must not be keygen'd from");
    assert!(
        matches!(
            err,
            ProveError::WhitelistRequired {
                phase: Phase::Combine
            }
        ),
        "got {err}"
    );

    // (5)+(6) both version fields are named before anything is verified.
    let err = ProofArtifact::read(dir.join("bad_format.pico"))
        .expect_err("a foreign container version must be named");
    assert!(
        matches!(err, ProveError::FormatVersion { found: 999, .. }),
        "got {err}"
    );
    let err = ProofArtifact::read(dir.join("bad_codec.pico"))
        .expect_err("a foreign proof codec must be named");
    assert!(
        matches!(err, ProveError::CodecVersion { found: 999, .. }),
        "got {err}"
    );

    // (7) the header's key identity and the body's disagree — what a stored type whose serde shape
    // moved without a container version bump would look like. Named, not decoded around.
    let err = ProofArtifact::read(dir.join("bad_vk_identity.pico"))
        .expect_err("a key the body does not decode to must be named");
    assert!(
        matches!(err, ProveError::VkIdentityMismatch { .. }),
        "got {err}"
    );

    // (8) a key whose body no longer hashes to the identity stored with it: refused on read, before
    // any verifier sees the key.
    let err = ProofArtifact::read(dir.join("altered_vk.pico"))
        .expect_err("a key altered under its own identity must be named");
    assert!(
        matches!(err, ProveError::VkIdentityMismatch { .. }),
        "got {err}"
    );

    // (9) a root binding no complete execution: refused before the whitelist question, so this
    // prover answers it by name rather than with WhitelistRequired as in (3) and (4).
    let err = prover
        .verify_artifact(ProofArtifact::read(dir.join("incomplete.pico")).expect("read"))
        .expect_err("a root with no complete flag must not verify");
    assert!(matches!(err, ProveError::Incomplete), "got {err}");

    // The operating point is the caller's expectation, not the file's claim, and it is named as
    // such even though the program identity moves with it. Then the identity alone.
    let claiming = |edit: fn(&mut ProofArtifact)| {
        let mut artifact = ProofArtifact::read(dir.join("riscv.pico")).expect("read");
        edit(&mut artifact);
        prover
            .verify_artifact(artifact)
            .expect_err("the file must not decide what it is verified as")
    };
    let err = claiming(|a| {
        a.log_stacked_height -= 1;
        a.program_id = ProgramId::from_words([1; 8]);
    });
    assert!(
        matches!(err, ProveError::OperatingPointMismatch { .. }),
        "height: got {err}"
    );
    let err = claiming(|a| a.verify_keys = !a.verify_keys);
    assert!(
        matches!(err, ProveError::OperatingPointMismatch { .. }),
        "mode: got {err}"
    );
    let err = claiming(|a| a.program_id = ProgramId::from_words([1; 8]));
    assert!(
        matches!(err, ProveError::ProgramMismatch { found, .. } if found == ProgramId::from_words([1; 8])),
        "got {err}"
    );

    println!("{FRESH_MARKER}");
}

/// The forbidden move of the trust model, guarded structurally rather than by a test that has to
/// construct it: the container stores no child layouts, so there is nothing to feed
/// `preregister_root_shape`, and no file in the crate names either.
///
/// The crate is walked rather than listed, so a module added later is covered the day it appears.
/// `tests/` is skipped because this file names both forbidden strings itself.
#[test]
fn nothing_keygens_a_verifier_circuit_from_a_loaded_file() {
    fn rust_files(dir: &std::path::Path, out: &mut Vec<std::path::PathBuf>) {
        for entry in std::fs::read_dir(dir).expect("read the crate source") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                if path.file_name().is_some_and(|name| name != "tests") {
                    rust_files(&path, out);
                }
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    rust_files(&src, &mut files);

    // The walk is the whole guard, so a walk that found nothing has to fail rather than pass.
    let names: Vec<String> = files
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    for expected in ["lib.rs", "artifact.rs", "prover.rs", "proof.rs"] {
        assert!(
            names.iter().any(|n| n == expected),
            "the source walk missed {expected}; it found {names:?}"
        );
    }

    for path in &files {
        let source = std::fs::read_to_string(path).expect("read a source file");
        for forbidden in ["preregister_root_shape", "RecursionVkLayout"] {
            // The doc comment in `artifact.rs` names the method it forbids; the code must not.
            let in_code = source
                .lines()
                .filter(|line| !line.trim_start().starts_with("//"))
                .any(|line| line.contains(forbidden));
            assert!(!in_code, "{} reaches `{forbidden}`", path.display());
        }
    }
}

/// The end-to-end example is the only *independent* execution of the chain, and folding it
/// onto this crate would turn the oracle into a second run of the thing under test. It must keep
/// driving the machines itself.
#[test]
fn the_end_to_end_example_still_drives_the_machines_directly() {
    let source = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../vm/examples/test_mle_e2e.rs"
    ));
    assert!(
        !source.contains("pico_prover"),
        "the independent oracle now runs through the facade"
    );
    // `emulate_with_committed_bytes` here: it sizes the pinned event buffers from the chunk size.
    for call in [
        "riscv::emulate_with_committed_bytes(",
        "riscv::prove_riscv(",
        "riscv::verify_riscv(",
        "ConvertMachine::new(",
        "CombineMachine::new(",
        ".prove_tree(",
    ] {
        assert!(
            source.contains(call),
            "the end-to-end example no longer calls `{call}`"
        );
    }
}
