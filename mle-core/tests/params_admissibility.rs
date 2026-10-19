//! A parameter set the pipeline cannot run is refused when it is built, naming the parameter at
//! fault, instead of constructing and failing later inside proving: an RS domain the field has no
//! subgroup for, a WHIR schedule with no round or with rounds that fold past the stacked height,
//! a round whose query count is not a positive integer within `MAX_WHIR_QUERIES`, and a grinding or
//! query-index sample wider than the transcript draws from one field element. Keygen makes the
//! field checks for a parameter set no preset built.
//!
//! Every production preset and every weak test shape still constructs, and the presets keep their
//! pinned schedules.

use std::panic::{self, UnwindSafe};

use pico_mle_core::{
    config::{
        check_field_admissible, check_sample_widths, compress_params_with_100_bits_security,
        embed_params_with_100_bits_security,
        koala_bear_poseidon2::{default_duplex_sponge, KoalaBearPoseidon2Config},
        max_sample_bits, recursion_params_with_100_bits_security,
        riscv_params_with_100_bits_security, try_compress_params_with_100_bits_security,
        try_riscv_params_with_100_bits_security, ParamsError, ProximityRegime, SystemParams,
        WhirConfig, WhirParams, WhirProximityStrategy, WhirRoundConfig,
        MAX_RISCV_LOG_STACKED_HEIGHT, MAX_WHIR_QUERIES,
    },
    interaction::LogUpSecurityParameters,
    keygen::MultiStarkKeygenBuilder,
    p3_koala_bear::KoalaBear,
    test_utils::test_system_params_small,
    FiatShamirTranscript,
};

/// The text an infallible constructor panics with.
fn panic_text<T>(f: impl FnOnce() -> T + UnwindSafe) -> String {
    let payload = panic::catch_unwind(f)
        .err()
        .expect("the constructor must refuse");
    payload
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
        .expect("a string panic payload")
}

fn logup() -> LogUpSecurityParameters {
    LogUpSecurityParameters {
        max_interaction_count: 1 << 30,
        log_max_message_length: 7,
        pow_bits: 18,
    }
}

/// `SystemParams::try_new` at `l_skip = 4` with fixed grinding; the inputs the checks read are free.
fn try_params(
    log_blowup: usize,
    n_stack: usize,
    log_final_poly_len: usize,
    proximity: WhirProximityStrategy,
    security_bits: usize,
) -> Result<SystemParams, ParamsError> {
    SystemParams::try_new(
        log_blowup,
        4,
        n_stack,
        64,
        log_final_poly_len,
        5,
        15,
        proximity,
        security_bits,
        logup(),
        3,
    )
}

#[test]
fn riscv_h24_is_refused_at_construction() {
    let err =
        try_riscv_params_with_100_bits_security(24).expect_err("2^25 is not a KoalaBear domain");
    assert_eq!(
        err,
        ParamsError::RsDomainTooLarge {
            log_stacked_height: 24,
            log_blowup: 1,
            log_rs_domain_size: 25,
            two_adicity: 24,
        }
    );
    let text = err.to_string();
    println!("riscv(24): RS domain log-size 25 refused: {text}");
    assert!(
        text.contains("log_stacked_height 24") && text.contains("two-adicity 24"),
        "{text}"
    );
    assert_eq!(panic_text(|| riscv_params_with_100_bits_security(24)), text);
}

#[test]
fn compress_h23_is_refused_at_construction() {
    let err =
        try_compress_params_with_100_bits_security(23).expect_err("2^25 is not a KoalaBear domain");
    assert_eq!(
        err,
        ParamsError::RsDomainTooLarge {
            log_stacked_height: 23,
            log_blowup: 2,
            log_rs_domain_size: 25,
            two_adicity: 24,
        }
    );
    let text = err.to_string();
    println!("compress(23): RS domain log-size 25 refused: {text}");
    assert!(
        text.contains("log_stacked_height 23") && text.contains("two-adicity 24"),
        "{text}"
    );
    assert_eq!(
        panic_text(|| compress_params_with_100_bits_security(23)),
        text
    );
}

/// The admitted range ends exactly where the domain does, so the constant and the check agree.
#[test]
fn the_riscv_maximum_is_the_last_height_with_a_domain() {
    assert_eq!(MAX_RISCV_LOG_STACKED_HEIGHT, 23);
    assert!(try_riscv_params_with_100_bits_security(MAX_RISCV_LOG_STACKED_HEIGHT).is_ok());
    assert!(matches!(
        try_riscv_params_with_100_bits_security(MAX_RISCV_LOG_STACKED_HEIGHT + 1),
        Err(ParamsError::RsDomainTooLarge { .. })
    ));
    assert!(try_compress_params_with_100_bits_security(22).is_ok());
}

/// At or below the final polynomial length (10) a preset has no WHIR round, and the prover sizes
/// its codeword buffers by `num_rounds - 1`. A height below `l_skip` is reported as asked, not as
/// the `l_skip` it would saturate to.
#[test]
fn a_schedule_with_no_whir_round_is_refused() {
    let err = try_riscv_params_with_100_bits_security(10).expect_err("no WHIR round at 10");
    println!("riscv(10): {err}");
    assert_eq!(
        err,
        ParamsError::NoWhirRound {
            log_stacked_height: 10,
            log_final_poly_len: 10,
        }
    );
    assert!(try_compress_params_with_100_bits_security(10).is_err());
    assert!(try_riscv_params_with_100_bits_security(11).is_ok());

    for preset in [
        try_riscv_params_with_100_bits_security,
        try_compress_params_with_100_bits_security,
    ] {
        assert_eq!(
            preset(2),
            Err(ParamsError::NoWhirRound {
                log_stacked_height: 2,
                log_final_poly_len: 10,
            })
        );
    }
}

/// `log_stacked_height` 5 with `k = 4` and no final polynomial takes two rounds, folding 8
/// variables out of 5, and `log_final_poly_len()` would wrap.
#[test]
fn rounds_that_fold_past_the_stacked_height_are_refused() {
    let err = try_params(1, 1, 0, WhirProximityStrategy::UniqueDecoding, 100)
        .expect_err("8 folded variables out of 5");
    println!("log_stacked_height 5, log_final_poly_len 0: {err}");
    assert_eq!(
        err,
        ParamsError::WhirRoundsOverrun {
            log_stacked_height: 5,
            k: 4,
            num_rounds: 2,
        }
    );

    // A config that bypassed the constructor panics by name rather than wrapping.
    let whir = WhirConfig {
        k: 4,
        rounds: vec![WhirRoundConfig { num_queries: 1 }; 2],
        mu_pow_bits: 0,
        query_phase_pow_bits: 0,
        folding_pow_bits: 0,
        proximity: WhirProximityStrategy::UniqueDecoding,
    };
    assert_eq!(
        panic_text(move || whir.log_final_poly_len(5)),
        err.to_string()
    );
}

/// At rate 1/2 the agreement bound of `ListDecoding { m: 1 }`, `sqrt(rho) * 3/2`, passes 1, so a
/// query buys nothing and the round would be sized at 0 queries.
#[test]
fn a_regime_with_no_distance_at_the_rate_is_refused() {
    let err = try_params(1, 16, 10, WhirProximityStrategy::ListDecoding { m: 1 }, 100)
        .expect_err("no security per query");
    println!("ListDecoding {{ m: 1 }} at log_blowup 1: {err}");
    assert_eq!(
        err,
        ParamsError::NoQuerySecurity {
            round: 0,
            regime: ProximityRegime::ListDecoding { m: 1 },
            log_inv_rate: 1,
        }
    );
}

/// A target the query-phase grinding (20 bits) already meets leaves the queries nothing to do, and
/// every round would be sized at 0 queries.
#[test]
fn a_target_the_query_grinding_covers_is_refused() {
    let err =
        try_params(1, 16, 10, WhirProximityStrategy::UniqueDecoding, 20).expect_err("no queries");
    println!("security_bits 20: {err}");
    assert_eq!(
        err,
        ParamsError::NoQueries {
            security_bits: 20,
            query_phase_pow_bits: 20,
        }
    );
}

#[test]
fn a_query_count_past_the_cap_is_refused() {
    let num_queries = WhirConfig::queries(ProximityRegime::UniqueDecoding, 100_000 - 20, 1);
    assert!(num_queries > MAX_WHIR_QUERIES);
    let err = try_params(1, 16, 10, WhirProximityStrategy::UniqueDecoding, 100_000)
        .expect_err("past the cap");
    println!("security_bits 100000: {err}");
    assert_eq!(
        err,
        ParamsError::TooManyQueries {
            round: 0,
            num_queries,
        }
    );
}

/// Queries per round, then the mu, query-phase, folding and LogUp grinding bits.
fn schedule(params: &SystemParams) -> (Vec<usize>, [usize; 4]) {
    let whir = &params.whir;
    (
        whir.rounds.iter().map(|round| round.num_queries).collect(),
        [
            whir.mu_pow_bits,
            whir.query_phase_pow_bits,
            whir.folding_pow_bits,
            params.logup.pow_bits,
        ],
    )
}

#[test]
fn production_presets_keep_their_schedules() {
    for h in 11..=MAX_RISCV_LOG_STACKED_HEIGHT {
        riscv_params_with_100_bits_security(h);
    }
    for h in 11..=22 {
        compress_params_with_100_bits_security(h);
    }

    let riscv = [15, 20, 5, 18];
    let compress = [15, 20, 5, 18];
    let cases = [
        (
            "riscv(20)",
            riscv_params_with_100_bits_security(20),
            vec![193, 88, 81],
            riscv,
        ),
        (
            "riscv(22)",
            riscv_params_with_100_bits_security(22),
            vec![193, 88, 81],
            riscv,
        ),
        (
            "riscv(23)",
            riscv_params_with_100_bits_security(23),
            vec![193, 88, 81, 81],
            riscv,
        ),
        (
            "compress(20)",
            compress_params_with_100_bits_security(20),
            vec![118, 84, 81],
            compress,
        ),
        (
            "compress(22)",
            compress_params_with_100_bits_security(22),
            vec![118, 84, 81],
            compress,
        ),
        (
            "recursion",
            recursion_params_with_100_bits_security(),
            vec![118, 84, 81],
            [13, 20, 4, 18],
        ),
        (
            "embed",
            embed_params_with_100_bits_security(),
            vec![57, 28, 19],
            [18, 20, 16, 18],
        ),
    ];
    for (label, params, queries, pow_bits) in cases {
        assert_eq!(schedule(&params), (queries, pow_bits), "{label}");
        // Embed sits exactly at the two-adicity (24); nothing here may refuse it.
        assert_eq!(
            check_field_admissible::<KoalaBear>(&params),
            Ok(()),
            "{label}"
        );
    }
}

/// The weak shapes the backends' unit tests build (`security_bits = 5`, heights down to 3, `k`
/// down to 1). Late rounds of the smallest draw more queries than their domain has points, which
/// is why the query cap is not a domain bound.
#[test]
fn weak_test_shapes_still_construct() {
    let shapes = [
        (2, 5, 3),
        (3, 6, 3),
        (2, 8, 3),
        (2, 2, 2),
        (0, 3, 1),
        (2, 2, 1),
        (0, 8, 3),
        (4, 8, 3),
        (4, 8, 4),
        (4, 19, 4),
    ];
    for (l_skip, n_stack, k_whir) in shapes {
        let params = test_system_params_small(l_skip, n_stack, k_whir);
        assert!(
            params.num_whir_rounds() > 0,
            "({l_skip}, {n_stack}, {k_whir})"
        );
    }
    SystemParams::new_for_testing(5);
}

/// `sample_bits` keeps the low bits of one KoalaBear element, and `2^31 > p = 2^31 - 2^24 + 1`, so
/// 30 is the widest draw: the transcript serves it, and panics one bit past it.
#[test]
fn the_widest_sample_is_the_one_the_transcript_draws() {
    assert_eq!(max_sample_bits::<KoalaBear>(), 30);
    let mut transcript = default_duplex_sponge();
    FiatShamirTranscript::<KoalaBearPoseidon2Config>::sample_bits(&mut transcript, 30);
    let text = panic_text(move || {
        FiatShamirTranscript::<KoalaBearPoseidon2Config>::sample_bits(&mut transcript, 31)
    });
    assert!(text.contains("ORDER_U64"), "{text}");
}

#[test]
fn a_sample_wider_than_the_transcript_draws_is_refused() {
    let params = try_params(1, 16, 10, WhirProximityStrategy::UniqueDecoding, 100).unwrap();
    assert_eq!(check_sample_widths::<KoalaBear>(&params), Ok(()));

    let mut grinding = params.clone();
    grinding.whir.query_phase_pow_bits = 31;
    let err = check_sample_widths::<KoalaBear>(&grinding).expect_err("31-bit grinding");
    println!("query_phase_pow_bits 31: {err}");
    assert_eq!(
        err.to_string(),
        "WHIR query grinding asks for 31-bit samples, but the transcript derives at most 30 bits \
         from one field element"
    );

    let mut logup = params.clone();
    logup.logup.pow_bits = 31;
    assert_eq!(
        check_sample_widths::<KoalaBear>(&logup),
        Err(ParamsError::SampleTooWide {
            sample: "LogUp grinding",
            bits: 31,
            max_bits: 30,
        })
    );

    // A query index wider than 30 bits needs a domain past 2^34, which the RS-domain check refuses
    // first on KoalaBear; scored on its own, the width check still names it.
    let mut index = params;
    index.n_stack = 30;
    assert_eq!(
        check_sample_widths::<KoalaBear>(&index),
        Err(ParamsError::SampleTooWide {
            sample: "WHIR query index",
            bits: 31,
            max_bits: 30,
        })
    );
    assert!(matches!(
        check_field_admissible::<KoalaBear>(&index),
        Err(ParamsError::RsDomainTooLarge { .. })
    ));
}

fn whir_params(k: usize) -> WhirParams {
    WhirParams {
        k,
        log_final_poly_len: 10,
        query_phase_pow_bits: 20,
        proximity: WhirProximityStrategy::UniqueDecoding,
        folding_pow_bits: 5,
        mu_pow_bits: 15,
    }
}

/// `k = 0` folds nothing, and the round count would divide by it.
#[test]
fn a_zero_folding_factor_is_refused() {
    assert_eq!(
        WhirConfig::try_new(1, 20, whir_params(0), 100),
        Err(ParamsError::ZeroFoldingFactor)
    );
}

/// A domain past what a `usize` indexes would size the round list at about `2^38` entries.
#[test]
fn an_unaddressable_domain_is_refused() {
    assert_eq!(
        WhirConfig::try_new(1, 1 << 40, whir_params(4), 100),
        Err(ParamsError::RsDomainUnaddressable {
            log_rs_domain_size: (1 << 40) + 1,
        })
    );
    assert_eq!(
        WhirConfig::try_new(1, 63, whir_params(4), 100),
        Err(ParamsError::RsDomainUnaddressable {
            log_rs_domain_size: 64,
        })
    );
}

/// A `SystemParams` built by hand never meets a preset's field check; keygen makes it before any
/// trace is committed.
#[test]
fn keygen_refuses_params_its_field_cannot_run() {
    let wide = try_params(1, 16, 10, WhirProximityStrategy::UniqueDecoding, 100).unwrap();
    let mut grinding = wide.clone();
    grinding.whir.query_phase_pow_bits = 31;
    let expected = check_field_admissible::<KoalaBear>(&grinding)
        .expect_err("31-bit grinding")
        .to_string();
    let config = KoalaBearPoseidon2Config::default_from_params(grinding);
    assert_eq!(
        panic_text(move || MultiStarkKeygenBuilder::new(config)),
        expected
    );

    let domain = try_params(1, 20, 10, WhirProximityStrategy::UniqueDecoding, 100).unwrap();
    let expected = check_field_admissible::<KoalaBear>(&domain)
        .expect_err("2^25 is not a KoalaBear domain")
        .to_string();
    let config = KoalaBearPoseidon2Config::default_from_params(domain);
    assert_eq!(
        panic_text(move || MultiStarkKeygenBuilder::new_with_merged_preprocessed(config)),
        expected
    );

    MultiStarkKeygenBuilder::new(KoalaBearPoseidon2Config::default_from_params(wide));
}
