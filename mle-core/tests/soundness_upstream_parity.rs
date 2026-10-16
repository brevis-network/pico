//! Parity gate for the soundness calculator.
//!
//! Pins `mle-core/src/config/soundness/calculator.rs` to fixed reference values. The calculator
//! charges the list size in the fold error, uses the *next* WHIR round's list size for the
//! OOD/shift terms, charges `L_PCS` as a penalty rather than a bonus, and charges the
//! `sample_bits` bias on grinding and on query draws.
//!
//! Every expected value below is a reference total at the fixed shape the constants below spell
//! out. A drift here means the calculator has changed in a way that moves a security verdict —
//! treat it as a soundness regression, not a flaky test. Each row pins the total, which is the
//! minimum over the components, so a divergence confined to a component that is not binding
//! passes.

use pico_mle_core::config::{
    koala_bear_poseidon2::KoalaBearPoseidon2Config,
    log_up_params::log_up_security_params_koala_bear_100_bits,
    soundness::{base_field_order, challenge_field_bits, SoundnessCalculator},
    SystemParams, WhirProximityStrategy,
};

const L_SKIP: usize = 4;
const N_STACK: usize = 16;
const W_STACK: usize = 64;
const LOG_BLOWUP: usize = 4;
const LOG_FINAL_POLY_LEN: usize = 10;
/// The shape the reference values were produced at has degree-4 AIRs.
const MAX_CONSTRAINT_DEGREE: usize = 4;

fn shape(
    proximity: WhirProximityStrategy,
    folding_pow: usize,
    mu_pow: usize,
    logup_pow: Option<usize>,
    security_bits: usize,
) -> SystemParams {
    let log2_list = SoundnessCalculator::whir_proximity_gap_security(
        proximity.initial_round(),
        challenge_field_bits::<KoalaBearPoseidon2Config>(),
        L_SKIP + N_STACK,
        LOG_BLOWUP,
        W_STACK,
    )
    .log2_list_size;
    let mut logup = log_up_security_params_koala_bear_100_bits(log2_list);
    if let Some(p) = logup_pow {
        logup.pow_bits = p;
    }
    SystemParams::new(
        LOG_BLOWUP,
        L_SKIP,
        N_STACK,
        W_STACK,
        LOG_FINAL_POLY_LEN,
        folding_pow,
        mu_pow,
        proximity,
        security_bits,
        logup,
        MAX_CONSTRAINT_DEGREE,
    )
}

fn run(label: &str, params: &SystemParams, expected: f64) {
    let s = SoundnessCalculator::calculate(
        params,
        base_field_order::<KoalaBearPoseidon2Config>(),
        challenge_field_bits::<KoalaBearPoseidon2Config>(),
        1_000, // max_num_constraints_per_air
        21,    // num_airs
        params.max_constraint_degree,
        params.log_stacked_height(), // max_log_trace_height
        2_000,                       // num_trace_columns
        params.w_stack,              // num_stacked_columns
        13,                          // n_logup
    );
    let q: Vec<usize> = params.whir.rounds.iter().map(|r| r.num_queries).collect();
    let qsum: usize = q.iter().sum();
    println!(
        "{label}\n  pow_bits={} folding={} mu={} queries={q:?} (sum {qsum})\n  \
         TOTAL={:.4}  expected={expected:.4}  delta={:+.6}\n  \
         logup={:.4} gkr_sc={:.4} gkr_batch={:.4} zerocheck={:.4} constraint={:.4} stacked={:.4} whir={:.4}\n  \
         whir: mu={:.4} fold={:.4} ood={:.4} shift={:.4} | query={:.4} prox={:.4} sumcheck={:.4} gamma={:.4}",
        params.logup.pow_bits,
        params.whir.folding_pow_bits,
        params.whir.mu_pow_bits,
        s.total_bits,
        s.total_bits - expected,
        s.logup_bits,
        s.gkr_sumcheck_bits,
        s.gkr_batching_bits,
        s.zerocheck_sumcheck_bits,
        s.constraint_batching_bits,
        s.stacked_reduction_bits,
        s.whir_bits,
        s.whir_details.mu_batching_bits,
        s.whir_details.fold_rbr_bits,
        s.whir_details.ood_rbr_bits,
        s.whir_details.shift_rbr_bits,
        s.whir_details.query_bits,
        s.whir_details.proximity_gaps_bits,
        s.whir_details.sumcheck_bits,
        s.whir_details.gamma_batching_bits,
    );
    assert!(
        (s.total_bits - expected).abs() < 5e-4,
        "{label}: got {:.4}, expected {expected:.4}",
        s.total_bits
    );
}

/// The expected values come from the closed-form Lemma 3.1 degree bound, so the gate does not
/// apply when `soundness-bchks25-optimized` swaps in the brute-forced one: the list sizes, and
/// every list-decoding row with them, legitimately move.
#[test]
#[cfg_attr(
    feature = "soundness-bchks25-optimized",
    ignore = "ground truth is for the closed-form BCHKS25 degree bound"
)]
fn differential_ground_truth_table() {
    println!(
        "challenge_field_bits = {:.6}  base_field_order = {:.0}",
        challenge_field_bits::<KoalaBearPoseidon2Config>(),
        base_field_order::<KoalaBearPoseidon2Config>()
    );

    // The grinding the LogUp preset derives per regime. Pinned here because the rows below assert
    // the total, a minimum over the components: in ROW 5, the only row that takes the derived
    // value, WHIR binds it at 97.93 against LogUp's 100.64, so a wrong derivation would not move
    // the number that row checks.
    for (name, prox, expected_pow) in [
        ("UD", WhirProximityStrategy::UniqueDecoding, 18),
        ("LD{m:1}", WhirProximityStrategy::ListDecoding { m: 1 }, 18),
        ("LD{m:2}", WhirProximityStrategy::ListDecoding { m: 2 }, 19),
    ] {
        let l2 = SoundnessCalculator::whir_proximity_gap_security(
            prox.initial_round(),
            challenge_field_bits::<KoalaBearPoseidon2Config>(),
            L_SKIP + N_STACK,
            LOG_BLOWUP,
            W_STACK,
        )
        .log2_list_size;
        let p = log_up_security_params_koala_bear_100_bits(l2);
        let pre = SoundnessCalculator::logup_soundness(
            p.max_interaction_count,
            p.log_max_message_length,
            challenge_field_bits::<KoalaBearPoseidon2Config>(),
            l2,
        );
        println!(
            "{name}: log2_list_size={l2:.6} pre_pow_security={pre:.5} needed={:.5} -> pow_bits={}",
            100.0 - pre,
            p.pow_bits
        );
        assert_eq!(
            p.pow_bits, expected_pow,
            "{name}: derived pow_bits moved at log2(L_PCS) = {l2:.6}"
        );
    }

    run(
        "ROW 1  UD @ (folding 5, mu 15), pow 18",
        &shape(WhirProximityStrategy::UniqueDecoding, 5, 15, Some(18), 100),
        100.0899,
    );
    run(
        "ROW 2  LD{m:1} @ (16,18), pow 18",
        &shape(
            WhirProximityStrategy::ListDecoding { m: 1 },
            16,
            18,
            Some(18),
            100,
        ),
        100.3809,
    );
    run(
        "ROW 3  LD{m:1} @ (16,18), pow 19",
        &shape(
            WhirProximityStrategy::ListDecoding { m: 1 },
            16,
            18,
            Some(19),
            100,
        ),
        100.6563,
    );
    // Sensitivity check: 5 fewer WHIR queries (a target of 96 rather than 100 in
    // `WhirConfig::queries`) must drop the verdict below the target, i.e. the calculator is not
    // insensitive to the query schedule.
    run(
        "ROW 4  LD{m:1} @ (16,18), pow 18, 99 queries (query target 96)",
        &shape(
            WhirProximityStrategy::ListDecoding { m: 1 },
            16,
            18,
            Some(18),
            96,
        ),
        96.4113,
    );
    run(
        "ROW 5  LD{m:2} @ (16,18), derived pow",
        &shape(
            WhirProximityStrategy::ListDecoding { m: 2 },
            16,
            18,
            None,
            100,
        ),
        97.9300,
    );
    for fp in [16usize, 20, 24] {
        run(
            &format!("ROW 6  LD{{m:1}} @ (folding {fp}, mu 18), pow 18"),
            &shape(
                WhirProximityStrategy::ListDecoding { m: 1 },
                fp,
                18,
                Some(18),
                100,
            ),
            100.3809,
        );
    }
}
