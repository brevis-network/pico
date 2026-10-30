//! The in-memory export a verifier outside this crate takes: the VK bundle and the v3 envelope,
//! checked by `pico_verifier::verify`.

use pico_verifier::VerifyError;
use pico_vm::mle::machine::{
    vk_bundle::{encode_vk_bundle_v2, riscv_vm_vk_for_elf},
    vk_map::MleVkMap,
};

use super::fixture::{assert_is_fib_output, small_builder, whitelist_builder, FIB_ELF, N};
use crate::{
    phase::Phase,
    proof::{Payload, Proof},
    prover::ProgramId,
    ProveError, Stdin,
};

fn proof(verify_keys: bool, phase: Phase, payload: Payload) -> Proof {
    Proof {
        phase,
        program_id: ProgramId::from_words([0; 8]),
        log_stacked_height: 23,
        verify_keys,
        committed: Vec::new(),
        committed_value_digest: [0; 32],
        chunk_count: None,
        distinct_shapes: None,
        payload,
    }
}

#[test]
fn only_a_whitelist_mode_root_exports() {
    let err = proof(false, Phase::Combine, Payload::Convert(Vec::new()))
        .export_v3()
        .unwrap_err();
    assert!(
        matches!(err, ProveError::WhitelistModeRequired { .. }),
        "{err}"
    );
    let err = proof(true, Phase::Convert, Payload::Convert(Vec::new()))
        .export_v3()
        .unwrap_err();
    assert!(
        matches!(
            err,
            ProveError::NotARootProof {
                phase: Phase::Convert
            }
        ),
        "{err}"
    );

    let prover = small_builder().build().expect("dev-mode prover");
    let err = prover.vk_bundle().unwrap_err();
    assert!(
        matches!(err, ProveError::WhitelistModeRequired { .. }),
        "{err}"
    );
}

/// `shipped_whitelist` pins the shipped root; a caller's root still has to match it, and it does
/// not combine with a file. Both refused before keygen.
#[test]
fn the_shipped_whitelist_is_pinned() {
    let err = whitelist_builder()
        .shipped_whitelist()
        .trusted_vk_root([1; 8])
        .build()
        .unwrap_err();
    assert!(matches!(err, ProveError::VkRootMismatch { .. }), "{err}");

    let err = whitelist_builder()
        .shipped_whitelist()
        .verify_keys(false)
        .build()
        .unwrap_err();
    assert!(
        matches!(&err, ProveError::InconsistentOptions(m) if m.contains("verify_keys(false)")),
        "{err}"
    );
}

/// Whitelist mode from the compiled-in whitelist, proved, exported in memory and verified by the
/// stable verifier alone; any change to the committed bytes is refused. The prover's bundle is the
/// one the ethproofs bundle tool builds from the ELF.
///
/// Run with `cargo test --release -p pico-prover -- --ignored --nocapture tests::export`.
#[test]
#[ignore = "whitelist mode pads every chip to its catch-all height: minutes and tens of GB"]
fn a_shipped_whitelist_root_verifies_with_pico_verifier() {
    let started = std::time::Instant::now();
    let mut prover = whitelist_builder()
        .shipped_whitelist()
        .build()
        .expect("whitelist prover");
    println!("[export] build {:.1?}", started.elapsed());

    let proving = std::time::Instant::now();
    let proof = prover.prove(Stdin::from(&N)).expect("whitelist chain");
    println!("[export] prove {:.1?}", proving.elapsed());

    let bundle = prover.vk_bundle().expect("vk bundle");
    let (envelope, committed) = proof.export_v3().expect("export");
    assert_is_fib_output(&committed, N);
    println!(
        "[export] bundle {} B, envelope {} B, committed {} B",
        bundle.len(),
        envelope.len(),
        committed.len()
    );

    let verifying = std::time::Instant::now();
    pico_verifier::verify(&bundle, &envelope, &committed).expect("the export verifies");
    println!("[export] verify {:.1?}", verifying.elapsed());

    let mut tampered = committed.clone();
    tampered[committed.len() - 1] ^= 1;
    let err = pico_verifier::verify(&bundle, &envelope, &tampered).unwrap_err();
    assert!(matches!(err, VerifyError::CommittedValuesUnbound), "{err}");
    let err = pico_verifier::verify(&bundle, &envelope, &[]).unwrap_err();
    assert!(matches!(err, VerifyError::CommittedValuesUnbound), "{err}");

    let from_elf = encode_vk_bundle_v2(
        &riscv_vm_vk_for_elf(FIB_ELF).expect("riscv vm vk"),
        &MleVkMap::shipped().expect("shipped whitelist"),
    )
    .expect("bundle from the ELF");
    assert_eq!(
        bundle, from_elf,
        "the prover's bundle differs from the ethproofs tool's"
    );
    println!("[export] the shipped-whitelist root verified with pico_verifier");
}
