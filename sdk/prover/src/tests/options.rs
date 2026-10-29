//! Builder validation, the whitelist pinning check, and the errors a bad ELF, input or record set
//! comes back as.

use std::num::NonZeroUsize;

use pico_mle_core::config::MAX_RISCV_LOG_STACKED_HEIGHT;

use super::fixture::{
    emulate_fib, fib_program, scratch_dir, shipped_whitelist, shipped_whitelist_builder,
    small_builder, whitelist_builder, FIB_ELF, LOG_STACKED_HEIGHT, SMALL_LOG_STACKED_HEIGHT,
};
use crate::{prover::emulator_opts, ProveError, Prover};

/// `1 << log_stacked_height`.
#[test]
fn chunk_size_defaults_to_the_stacked_height() {
    for (height, chunk) in [(SMALL_LOG_STACKED_HEIGHT, 1 << 20), (23, 1 << 23)] {
        let resolved = Prover::builder(FIB_ELF)
            .log_stacked_height(height)
            .resolved_chunk_size();
        assert_eq!(resolved.ok(), Some(chunk), "height {height}");
    }

    let opts = emulator_opts(1 << LOG_STACKED_HEIGHT);
    assert_eq!(opts.chunk_size, 1 << LOG_STACKED_HEIGHT);
    assert_eq!(opts.chunk_batch_size, 1);
    assert_eq!(
        opts.split_opts.deferred,
        (1usize << LOG_STACKED_HEIGHT) >> 2
    );
}

/// A chunk of `2^n` instructions needs a stacked height of at least `n`; the pair is rejected at
/// `build` rather than proving the wrong shape.
#[test]
fn build_rejects_a_chunk_wider_than_the_stacked_height() {
    let err = small_builder()
        .chunk_size(1 << (SMALL_LOG_STACKED_HEIGHT + 1))
        .build()
        .expect_err("an oversized chunk must be refused");
    assert!(
        matches!(&err, ProveError::InconsistentOptions(m) if m.contains("chunk_size")),
        "got {err}"
    );

    // The boundary itself is legal: a chunk of exactly 2^n fits a height of n.
    small_builder()
        .chunk_size(1 << SMALL_LOG_STACKED_HEIGHT)
        .build()
        .expect("an exactly-sized chunk must be accepted");
}

/// A chunk of 2^24 instructions overruns the chunk clock, which the emulator asserts rather than
/// reports. It is wider than the tallest stack the backend admits, so `build` refuses it as too
/// wide for the stack, before keygen.
#[test]
fn build_rejects_a_chunk_the_chunk_clock_cannot_address() {
    let err = crate::Prover::builder(FIB_ELF)
        .log_stacked_height(MAX_RISCV_LOG_STACKED_HEIGHT)
        .chunk_size(1 << 24)
        .build()
        .expect_err("a chunk past the chunk-clock budget must be refused");
    assert!(
        matches!(&err, ProveError::InconsistentOptions(m) if m.contains("chunk_size")),
        "got {err}"
    );
}

/// Zero is the one chunk size that builds a prover which can never emulate anything: `max_cycles`
/// is derived from it. Refused by name at `build`, not as a max-cycles failure on the first
/// instruction of every later run.
#[test]
fn build_rejects_a_zero_chunk_size() {
    let err = crate::Prover::builder(FIB_ELF)
        .chunk_size(0)
        .build()
        .expect_err("a zero chunk must be refused");
    assert!(
        matches!(&err, ProveError::InconsistentOptions(m) if m.contains("chunk_size 0")),
        "got {err}"
    );
}

/// An input element the caller's `Serialize` refused is reported before anything is emulated, and
/// the guest never runs against a stdin missing an element it will read.
#[test]
fn an_input_element_that_would_not_serialize_is_reported_by_execute() {
    struct Unserializable;

    impl serde::Serialize for Unserializable {
        fn serialize<S: serde::Serializer>(&self, _: S) -> Result<S::Ok, S::Error> {
            Err(serde::ser::Error::custom("this type cannot be encoded"))
        }
    }

    let mut stdin = crate::Stdin::new();
    stdin.write(&Unserializable);

    let err = small_builder()
        .execute(stdin)
        .expect_err("an unserializable element must stop the run");
    assert!(
        matches!(err, ProveError::InvalidInput { index: 0, .. }),
        "got {err}"
    );
}

/// 24 is the first height past the backend maximum: its RS domain, `2^25`, does not exist in
/// KoalaBear. Refused as an option rather than as a panic in the first DFT.
#[test]
fn build_rejects_a_stacked_height_the_backend_cannot_prove() {
    let err = crate::Prover::builder(FIB_ELF)
        .log_stacked_height(24)
        .build()
        .expect_err("24 is past the backend maximum");
    assert!(
        matches!(&err, ProveError::InconsistentOptions(m)
            if m.contains("maximum") && m.contains("two-adicity 24")),
        "got {err}"
    );
}

/// At or below 10 the riscv preset has no WHIR round. Refused as an option rather than as a panic
/// in keygen.
#[test]
fn build_rejects_a_stacked_height_with_no_whir_round() {
    let err = crate::Prover::builder(FIB_ELF)
        .log_stacked_height(10)
        .build()
        .expect_err("no WHIR round at 10");
    assert!(
        matches!(&err, ProveError::InconsistentOptions(m)
            if m.contains("log_stacked_height 10") && m.contains("no WHIR round")),
        "got {err}"
    );
}

/// The whitelist is an artifact, and an artifact can only prove itself self-consistent. Both the
/// file and the root pinned out of band are required, and neither is optional.
#[test]
fn verify_keys_requires_both_the_artifact_and_a_pinned_root() {
    let err = whitelist_builder()
        .verify_keys(true)
        .build()
        .expect_err("no artifact");
    assert!(
        matches!(&err, ProveError::InconsistentOptions(m) if m.contains("vk_map")),
        "got {err}"
    );

    let err = whitelist_builder()
        .verify_keys(true)
        .vk_map("/nonexistent/mle_vk_map.json")
        .build()
        .expect_err("no pinned root");
    assert!(
        matches!(&err, ProveError::InconsistentOptions(m) if m.contains("trusted_vk_root")),
        "got {err}"
    );

    let err = small_builder()
        .vk_map("/nonexistent/mle_vk_map.json")
        .build()
        .expect_err("a whitelist nothing would read");
    assert!(
        matches!(&err, ProveError::InconsistentOptions(m) if m.contains("verify_keys(false)")),
        "got {err}"
    );
}

/// Whitelist mode's shape tables are sized for one stacked height: below it the tallest chips do
/// not pack, above it the recursion tiers are unmeasured. The whitelist height is the backend
/// maximum, so a taller one is refused as past the maximum before the shape tables are consulted.
#[test]
fn verify_keys_rejects_every_stacked_height_but_its_own() {
    let whitelist = crate::prover::WHITELIST_LOG_STACKED_HEIGHT;
    for height in [whitelist - 1, whitelist + 1] {
        let err = crate::Prover::builder(FIB_ELF)
            .log_stacked_height(height)
            .verify_keys(true)
            .vk_map("/nonexistent/mle_vk_map.json")
            .trusted_vk_root([0; 8])
            .build()
            .expect_err("a height the shape tables are not sized for");
        // Past the backend maximum the height is refused before the whitelist is consulted.
        let reason = if height > MAX_RISCV_LOG_STACKED_HEIGHT {
            "maximum"
        } else {
            "shape tables"
        };
        assert!(
            matches!(&err, ProveError::InconsistentOptions(m) if m.contains(reason)),
            "height {height}: got {err}"
        );
    }
}

/// Replacing the entries **and** the claimed root together leaves the file self-consistent, so
/// `try_load_json` accepts it. The root pinned out of band is the only thing that does not.
#[test]
fn a_wholly_substituted_whitelist_still_fails_against_a_pinned_root() {
    use pico_mle_core::p3_field::PrimeField32;
    use pico_vm::mle::machine::vk_map::{MleVkMap, VkIdentity};

    let dir = super::fixture::scratch_dir("vk_map_substitution");
    let id = |seed: u32| -> VkIdentity {
        use pico_mle_core::p3_field::PrimeCharacteristicRing;
        (
            std::array::from_fn(|i| crate::types::Kb::from_u32(seed + i as u32)),
            std::array::from_fn(|i| crate::types::Kb::from_u32(1000 + seed + i as u32)),
        )
    };
    let words = |map: &MleVkMap| map.root().map(|f| f.as_canonical_u32());

    let honest = MleVkMap::build(vec![id(0), id(100)]);
    let honest_path = dir.join("honest.json");
    honest.save_json(&honest_path);
    let pinned = words(&honest);

    // The substitution: a different entry set, and the root recomputed to match it. Nothing inside
    // the file is inconsistent — `try_load_json` accepts it.
    let substituted = MleVkMap::build(vec![id(7), id(700)]);
    let substituted_path = dir.join("substituted.json");
    substituted.save_json(&substituted_path);
    MleVkMap::try_load_json(&substituted_path)
        .expect("the substituted file is internally consistent, which is the whole problem");

    let err = whitelist_builder()
        .verify_keys(true)
        .vk_map(&substituted_path)
        .trusted_vk_root(pinned)
        .build()
        .expect_err("a substituted whitelist must not pass a pinned root");
    match err {
        ProveError::VkRootMismatch { loaded, pinned: p } => {
            assert_eq!(p, pinned);
            assert_eq!(loaded, words(&substituted));
        }
        other => panic!("expected VkRootMismatch, got {other}"),
    }

    // The honest artifact under the same pin is accepted, so the rejection above is not just
    // "every whitelist fails".
    whitelist_builder()
        .verify_keys(true)
        .vk_map(&honest_path)
        .trusted_vk_root(pinned)
        .build()
        .expect("the honest artifact must pass its own pinned root");
}

/// The whitelist the repo ships is the `.bin` form, and it is accepted under the root published
/// beside it. Under any other root it is refused like any whitelist, with the root the file really
/// rebuilds — so the refusal comes from reading the file, not from failing to. Its JSON twin
/// rebuilds the same root, so the two forms are interchangeable.
#[test]
fn the_shipped_whitelist_loads_under_its_published_root() {
    use pico_mle_core::p3_field::PrimeField32;
    use pico_vm::mle::machine::vk_map::MleVkMap;

    let (bin, published) = shipped_whitelist();
    let mut wrong = published;
    wrong[0] = wrong[0].wrapping_add(1);
    let err = whitelist_builder()
        .verify_keys(true)
        .vk_map(&bin)
        .trusted_vk_root(wrong)
        .build()
        .expect_err("a root the shipped whitelist does not rebuild");
    match err {
        ProveError::VkRootMismatch { loaded, pinned } => {
            assert_eq!(loaded, published);
            assert_eq!(pinned, wrong);
        }
        other => panic!("expected VkRootMismatch, got {other}"),
    }

    let dir = scratch_dir("shipped_whitelist");
    let json = dir.join("mle_vk_map_kb.json");
    MleVkMap::try_load_bin(&bin)
        .expect("the shipped whitelist")
        .save_json(&json);
    let root_of = |path: &std::path::Path| {
        crate::prover::load_vk_map(path)
            .expect("load")
            .root()
            .map(|f| f.as_canonical_u32())
    };
    assert_eq!(root_of(&json), published);

    shipped_whitelist_builder()
        .build()
        .expect("the shipped whitelist under its published root");
}

/// A whitelist that cannot be read is the loader's error, in either form, reported before keygen.
#[test]
fn a_missing_whitelist_is_reported_as_one() {
    for path in [
        "/nonexistent/mle_vk_map.bin",
        "/nonexistent/mle_vk_map.json",
    ] {
        let err = whitelist_builder()
            .verify_keys(true)
            .vk_map(path)
            .trusted_vk_root([0; 8])
            .build()
            .expect_err("no whitelist at that path");
        assert!(matches!(err, ProveError::VkMap(_)), "{path}: got {err}");
    }
}

/// An ELF the compiler cannot parse is an `Err`, not an abort.
#[test]
fn an_invalid_elf_is_an_error() {
    let err = Prover::new(b"not an elf").expect_err("garbage must not build a prover");
    assert!(matches!(err, ProveError::InvalidElf(_)), "got {err}");
}

/// A guest asking for input the host never supplied is an `Err`, not a panic inside the
/// emulator.
#[test]
fn missing_stdin_is_an_error() {
    let err = small_builder()
        .execute(crate::Stdin::new())
        .expect_err("the fib guest reads one element");
    assert!(
        format!("{err}").contains("read past the end of stdin"),
        "got {err}"
    );
}

/// All five phases can be named. Without the feature, the outer two say so by name rather than
/// being absent from the enum.
#[test]
#[cfg(not(feature = "multi-field-transcript"))]
fn the_outer_phases_can_be_named_and_report_themselves_missing() {
    let mut prover = small_builder().build().expect("prover");
    for phase in [crate::Phase::Embed, crate::Phase::Wrap] {
        let err = prover
            .prove_to(crate::Stdin::from(&super::fixture::N), phase)
            .expect_err("no outer config in this build");
        assert!(
            matches!(&err, ProveError::FeatureMissing { phase: p, feature } if *p == phase
                && *feature == "multi-field-transcript"),
            "got {err}"
        );
    }
}

/// An empty record set reaches the recursion layer as a typed error, not as an assert. The
/// facade cannot produce one — an emulation always emits at least one record — so it is asserted
/// where it can actually arrive.
#[test]
fn an_empty_record_set_is_an_error() {
    use pico_mle_core::config::recursion_params_with_100_bits_security;
    use pico_vm::mle::machine::{convert::ConvertMachine, exe::RiscvVmVk, riscv::RiscvMachine};

    let program = fib_program();
    // Keygen on the GPU needs the shared pool, which only `build` sets up otherwise.
    #[cfg(feature = "cuda")]
    pico_vm::mle::machine::riscv::init_mle_gpu_pool(0);
    let machine =
        RiscvMachine::new(program.clone(), SMALL_LOG_STACKED_HEIGHT, false).expect("riscv keygen");
    let riscv_vk = std::sync::Arc::new(machine.vk().clone());
    let vm_vk = RiscvVmVk::from_program_and_vk(&program, machine.vk());

    let result = ConvertMachine::new(
        riscv_vk,
        vm_vk,
        &[],
        recursion_params_with_100_bits_security(),
        false,
    );
    match result {
        Ok(_) => panic!("an empty bundle has no layouts to keygen for"),
        Err(err) => assert!(format!("{err}").contains("non-empty"), "got {err}"),
    }
}

/// A stacked height that cannot hold the program's own preprocessed tables is refused while it is
/// still an option. The backend aborts on that pair rather than reporting it, so the alternative to
/// this check is a panic where a caller cannot catch one.
#[test]
fn a_stacked_height_the_program_does_not_fit_is_an_error() {
    let err = crate::Prover::builder(FIB_ELF)
        .log_stacked_height(11)
        .chunk_size(1 << 11)
        .build()
        .expect_err("fib's preprocessed tables are taller than 2^11");
    assert!(
        matches!(&err, ProveError::InconsistentOptions(m) if m.contains("preprocessed tables")),
        "got {err}"
    );
}

/// A prover that cannot prove what it was handed returns `Err` rather than aborting. Forced by
/// proving one guest's execution against another guest's keys, which is the failure a prover is
/// most likely to meet in production.
#[test]
fn a_prover_failure_is_an_error() {
    let emulated = emulate_fib(emulator_opts(1 << SMALL_LOG_STACKED_HEIGHT));

    // Keys for a different guest. Keygen does not run it, so its own behaviour is irrelevant; what
    // matters is that its program table is not the one these records executed.
    let mut prover = crate::Prover::builder(super::fixture::OTHER_ELF)
        .log_stacked_height(SMALL_LOG_STACKED_HEIGHT)
        .build()
        .expect("prover for the second guest");
    let err = prover
        .prove_records(
            &emulated.records,
            emulated.committed_bytes,
            crate::Phase::Riscv,
        )
        .expect_err("one guest's execution must not prove under another's keys");
    assert!(
        matches!(
            err,
            ProveError::Proving { .. } | ProveError::Verification { .. }
        ),
        "got {err}"
    );
}

/// The options a prover was built with read back as given or defaulted.
#[test]
fn the_builder_carries_the_concurrency_it_was_given() {
    let n = NonZeroUsize::new(3).unwrap();
    let prover = small_builder().concurrency(n).build().expect("prover");
    assert_eq!(prover.concurrency(), n);
    assert_eq!(prover.log_stacked_height(), SMALL_LOG_STACKED_HEIGHT);
    assert_eq!(prover.chunk_size(), 1 << SMALL_LOG_STACKED_HEIGHT);
    assert!(!prover.verify_keys());
}
