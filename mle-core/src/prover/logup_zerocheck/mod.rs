//! LogUp-ZeroCheck: the combined constraint-satisfaction + interaction-balance phase.
//!
//! [`prove_zerocheck_and_logup`] is the single prover entry point. It runs two logically distinct
//! sub-protocols that share this module's state ([`LogupZerocheckColMajor`]) and transcript:
//!
//! 1. **LogUp fractional-sum GKR** — [`fractional_sumcheck`] reduces the sum of all interaction
//!    fractions `Σ p/q` (which must be zero for a balanced bus) over a GKR layered circuit to a
//!    single evaluation claim on the input-layer MLEs `p̂(ξ), q̂(ξ)`. Verified by
//!    [`verify_gkr`](crate::verifier::fractional_sumcheck_gkr::verify_gkr).
//! 2. **ZeroCheck batch sumcheck** — proves every AIR's constraint polynomial vanishes on the
//!    trace hypercube, batched across AIRs together with the LogUp numerator/denominator claims.
//!    Verified by
//!    [`verify_zerocheck_and_logup`](crate::verifier::batch_constraints::verify_zerocheck_and_logup).
//!
//! The two are merged into one entry because they share `mod.rs` / `col_major.rs` /
//! `evaluator.rs` and a single transcript pass; the GKR half lives in
//! [`fractional_sumcheck_gkr`], the ZeroCheck half in [`col_major`]/[`single`]/[`evaluator`].

use std::{cmp::max, iter::zip};

use itertools::Itertools;
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing, TwoAdicField};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
use p3_util::log2_strict_usize;
use tracing::{debug, info_span, instrument};

use crate::{
    poly::{
        eq_sharp_uni_poly, eq_uni_poly,
        matrix::{ColMajorMatrix, MatrixDimensions, MatrixView},
        ntt::SerialRadix2Dft,
        UnivariatePoly,
    },
    proof::{column_openings_by_rot, BatchConstraintProof, GkrProof},
    protocol::stacking::{calculate_n_logup, lifted_log_height, StackedColumn, StackedLayout},
    prover::{
        error::LogupZerocheckError,
        fractional_sumcheck_gkr::{fractional_sumcheck, Frac},
        sumcheck::sumcheck_round0_deg,
        DeviceMultiStarkProvingKey, ProverBackend, ProvingContext, ReferenceColMajorBackend,
    },
    FiatShamirTranscript, StarkProtocolConfig,
};

mod col_major;
/// Shared constraint-DAG evaluators used by both CPU LogUp-ZeroCheck backends.
///
/// Semi-internal: public for out-of-crate device backends, not a stable API.
pub mod evaluator;
pub mod fractional_sumcheck_gkr;
mod single;

pub use col_major::LogupZerocheckColMajor;
pub use single::*;

/// Output of [`prove_zerocheck_and_logup`]: the two sub-proofs plus the shared final evaluation
/// point. Returned identically by both CPU backends.
pub struct ZerocheckLogupProof<SC: StarkProtocolConfig> {
    /// LogUp fractional-sum GKR proof.
    pub gkr: GkrProof<SC>,
    /// Batched ZeroCheck + LogUp constraint proof.
    pub batch: BatchConstraintProof<SC>,
    /// Final sumcheck evaluation point `r` (length `n_max + 1`), consumed by the downstream
    /// stacked-opening reduction.
    pub eval_point: Vec<SC::EF>,
}

#[instrument(level = "info", skip_all)]
pub fn prove_zerocheck_and_logup<SC: StarkProtocolConfig, TS>(
    transcript: &mut TS,
    mpk: &DeviceMultiStarkProvingKey<ReferenceColMajorBackend<SC>>,
    ctx: &ProvingContext<ReferenceColMajorBackend<SC>>,
) -> Result<ZerocheckLogupProof<SC>, LogupZerocheckError>
where
    TS: FiatShamirTranscript<SC>,
    SC::F: TwoAdicField,
    SC::EF: TwoAdicField + ExtensionField<SC::F>,
    ReferenceColMajorBackend<SC>: ProverBackend<
        Val = SC::F,
        Matrix = ColMajorMatrix<SC::F>,
        OtherAirData = evaluator::InteractionEvalPlan<SC::F>,
    >,
{
    let l_skip = mpk.params.l_skip;
    let constraint_degree = mpk.max_constraint_degree;
    let num_traces = ctx.per_trace.len();

    // Traces are sorted
    let n_max = log2_strict_usize(ctx.per_trace[0].1.common_main.height()).saturating_sub(l_skip);
    // Gather interactions metadata, including interactions stacked layout which depends on trace
    // heights
    let mut total_interactions = 0u64;
    let interactions_meta: Vec<_> = ctx
        .per_trace
        .iter()
        .map(|(air_idx, trace_ctx)| {
            let pk = &mpk.per_air[*air_idx];

            let num_interactions = pk.vk.symbolic_constraints.interactions.len();
            let height = trace_ctx.common_main.height();
            let log_height = log2_strict_usize(height);
            let log_lifted_height = lifted_log_height(log_height, l_skip);
            total_interactions += (num_interactions as u64) << log_lifted_height;
            (num_interactions, log_lifted_height)
        })
        .collect();
    // Implicitly, the width of this stacking should be 1
    let n_logup = calculate_n_logup(l_skip, total_interactions);
    debug!(%n_logup);
    // There's no stride threshold for `interactions_layout` because there's no univariate skip for
    // GKR
    let interactions_layout = StackedLayout::new(0, l_skip + n_logup, interactions_meta)?;

    // Grind to increase soundness of random sampling for LogUp
    let logup_pow_witness = transcript.grind(mpk.params.logup.pow_bits);
    let alpha_logup = transcript.sample_ext();
    let beta_logup = transcript.sample_ext();
    debug!(%alpha_logup, %beta_logup);

    let mut prover =
        LogupZerocheckColMajor::new(mpk, ctx, n_logup, interactions_layout, beta_logup)?;
    // GKR
    // Compute logup input layer: these are the evaluations of \hat{p}, \hat{q} on the hypercube
    // `H_{l_skip + n_logup}`
    let has_interactions = !prover.interactions_layout.sorted_cols.is_empty();
    let gkr_input_evals = if !has_interactions {
        vec![]
    } else {
        // Per trace, a row major matrix of interaction evaluations
        // NOTE: these are the evaluations _without_ lifting
        // This can write directly to the stacked `evals` buffer to avoid the intermediate matrix.
        let unstacked_interaction_evals = prover
            .eval_helpers
            .par_iter()
            .enumerate()
            .map(|(trace_idx, helper)| {
                let trace_ctx = &ctx.per_trace[trace_idx].1;
                let mats = helper.view_mats(trace_ctx);
                let height = trace_ctx.common_main.height();
                (0..height)
                    .into_par_iter()
                    .map(|i| {
                        let mut row_parts = Vec::with_capacity(mats.len() + 1);
                        let is_first = SC::F::from_bool(i == 0);
                        let is_transition = SC::F::from_bool(i != height - 1);
                        let is_last = SC::F::from_bool(i == height - 1);
                        let sels = vec![is_first, is_transition, is_last];
                        row_parts.push(sels);
                        for (mat, is_rot) in &mats {
                            let offset = usize::from(*is_rot);
                            row_parts.push(
                                // SAFETY: %height ensures we never go out of bounds
                                (0..mat.width())
                                    .map(|j| unsafe {
                                        *mat.get_unchecked((i + offset) % height, j)
                                    })
                                    .collect_vec(),
                            );
                        }
                        helper.eval_interactions(&row_parts, &prover.beta_pows)
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let mut evals = vec![Frac::default(); 1 << (l_skip + n_logup)];
        for StackedColumn {
            mat_idx: trace_idx,
            src_col_idx: interaction_idx,
            slice: s,
        } in prover.interactions_layout.sorted_cols.iter().copied()
        {
            let pq_evals = &unstacked_interaction_evals[trace_idx];
            let height = pq_evals.len();
            debug_assert_eq!(s.col_idx, 0);
            // the interactions layout has internal striding threshold=0
            debug_assert_eq!(1 << s.log_height(), s.len(0));
            debug_assert_eq!(s.len(0) % height, 0);
            let norm_factor_denom = s.len(0) / height;
            let norm_factor = SC::F::from_usize(norm_factor_denom).inverse();
            // We need to fill `evals` with the logup evaluations on the lifted trace, which is
            // the same as cyclic repeating of the unlifted evaluations
            evals[s.row_idx..s.row_idx + s.len(0)]
                .chunks_exact_mut(height)
                .for_each(|evals| {
                    evals
                        .par_iter_mut()
                        .zip(pq_evals)
                        .for_each(|(pq_eval, evals_at_z)| {
                            let (mut numer, denom) = evals_at_z[interaction_idx];
                            numer *= norm_factor;
                            *pq_eval = Frac::new(numer.into(), denom);
                        });
                });
        }
        // Prevent division by zero:
        evals.par_iter_mut().for_each(|frac| frac.q += alpha_logup);
        evals
    };

    let (frac_sum_proof, mut xi) =
        fractional_sumcheck::<SC, _>(transcript, &gkr_input_evals, true)?;

    // Sample more for `\xi` in the edge case that some AIRs don't have interactions
    let n_global = max(n_max, n_logup);
    debug!(%n_global);
    while xi.len() != l_skip + n_global {
        xi.push(transcript.sample_ext());
    }
    debug!(?xi);
    prover.xi = xi;
    // we now have full \xi vector

    // begin batch sumcheck
    let mut sumcheck_round_polys = Vec::with_capacity(n_max);
    let mut r = Vec::with_capacity(n_max + 1);
    // batching randomness
    let lambda = transcript.sample_ext();
    debug!(%lambda);

    let sp_0_polys = prover.sumcheck_uni_round0_polys(ctx, lambda)?;
    let sp_0_deg = sumcheck_round0_deg(l_skip, constraint_degree);
    let s_deg = constraint_degree + 1;
    let s_0_deg = sumcheck_round0_deg(l_skip, s_deg);
    let large_uni_domain = (s_0_deg + 1).next_power_of_two();
    let dft = SerialRadix2Dft;
    let s_0_logup_polys = {
        let eq_sharp_uni = eq_sharp_uni_poly(&prover.xi[..l_skip]);
        let mut eq_coeffs = eq_sharp_uni.into_coeffs();
        eq_coeffs.resize(large_uni_domain, SC::EF::ZERO);
        let eq_evals = dft.dft(eq_coeffs);

        let width = 2 * num_traces;
        let mut sp_coeffs_mat = SC::EF::zero_vec(width * large_uni_domain);
        for (i, coeffs) in sp_0_polys[..2 * num_traces].iter().enumerate() {
            // NOTE: coeffs could have length longer than `sp_0_deg + 1` due to coset evaluation,
            // but trailing coefficients should be zero.
            for (j, &c_j) in coeffs.coeffs().iter().enumerate().take(sp_0_deg + 1) {
                // SAFETY:
                // - coeffs length is <= sp_0_deg + 1 <= s_0_deg < large_uni_domain
                // - sp_coeffs_mat allocated for width
                unsafe {
                    *sp_coeffs_mat.get_unchecked_mut(j * width + i) = c_j;
                }
            }
        }
        let mut s_evals = dft.dft_batch(RowMajorMatrix::new(sp_coeffs_mat, width));
        for (eq, row) in zip(eq_evals, s_evals.values.chunks_mut(width)) {
            for x in row {
                *x *= eq;
            }
        }
        dft.idft_batch(s_evals)
    };

    let skip_domain_size = SC::F::from_usize(1 << l_skip);
    // logup sum claims (sum_{\hat p}, sum_{\hat q}) per present AIR
    let (numerator_term_per_air, denominator_term_per_air): (Vec<_>, Vec<_>) = (0..num_traces)
        .map(|trace_idx| {
            let [sum_claim_p, sum_claim_q] = [0, 1].map(|is_denom| {
                // Compute sum over D of s_0(Z) to get the sum claim
                (0..=s_0_deg)
                    .step_by(1 << l_skip)
                    .map(|j| unsafe {
                        // SAFETY: matrix is 2 * num_trace x large_uni_domain, s_0_deg <
                        // large_uni_domain
                        *s_0_logup_polys
                            .values
                            .get_unchecked(j * 2 * num_traces + 2 * trace_idx + is_denom)
                    })
                    .sum::<SC::EF>()
                    * skip_domain_size
            });
            transcript.observe_ext(sum_claim_p);
            transcript.observe_ext(sum_claim_q);

            (sum_claim_p, sum_claim_q)
        })
        .unzip();

    let mu = transcript.sample_ext();
    debug!(%mu);
    let mu_pows = mu.powers().take(3 * num_traces).collect_vec();

    let s_0_zc_poly = {
        let eq_uni = eq_uni_poly::<SC::F, _>(l_skip, prover.xi[0]);
        let mut eq_coeffs = eq_uni.into_coeffs();
        eq_coeffs.resize(large_uni_domain, SC::EF::ZERO);
        let eq_evals = dft.dft(eq_coeffs);

        let mut sp_coeffs = SC::EF::zero_vec(large_uni_domain);
        let mus = &mu_pows[2 * num_traces..];
        let polys = &sp_0_polys[2 * num_traces..];
        for (j, batch_coeff) in sp_coeffs.iter_mut().enumerate().take(sp_0_deg + 1) {
            for (&mu, poly) in zip(mus, polys) {
                *batch_coeff += mu * *poly.coeffs().get(j).unwrap_or(&SC::EF::ZERO);
            }
        }
        let mut s_evals = dft.dft(sp_coeffs);
        for (eq, x) in zip(eq_evals, &mut s_evals) {
            *x *= eq;
        }
        dft.idft(s_evals)
    };

    // Algebraically batch
    let s_0_poly = UnivariatePoly::new(
        zip(
            s_0_logup_polys.values.chunks_exact(2 * num_traces),
            s_0_zc_poly,
        )
        .take(s_0_deg + 1)
        .map(|(logup_row, batched_zc)| {
            let coeff = batched_zc
                + zip(&mu_pows, logup_row)
                    .map(|(&mu_j, &x)| mu_j * x)
                    .sum::<SC::EF>();
            transcript.observe_ext(coeff);
            coeff
        })
        .collect(),
    );

    let r_0 = transcript.sample_ext();
    r.push(r_0);
    debug!(round = 0, r_round = %r_0);
    prover.prev_s_eval = s_0_poly.eval_at_point(r_0);
    debug!("s_0(r_0) = {}", prover.prev_s_eval);

    prover.fold_ple_evals(ctx, r_0);

    // Sumcheck rounds:
    // - each round the prover needs to compute univariate polynomial `s_round`. This poly is linear
    //   since we are taking MLE of `evals`.
    // - at end of each round, sample random `r_round` in `EF`
    //
    // `s_round` is degree `s_deg` so we evaluate it at `0, ..., =s_deg`. The prover skips
    // evaluation at `0` because the verifier can infer it from the previous round's
    // `s_{round-1}(r)` claim. The degree is constraint_degree + 1, where + 1 is from eq term
    let _mle_rounds_span =
        info_span!("prover.batch_constraints.mle_rounds", phase = "prover").entered();
    debug!(%s_deg);
    for round in 1..=n_max {
        let sp_round_evals = prover.sumcheck_polys_eval(round, r[round - 1])?;
        // From s'_T above, we can form s'_head(X) and s'_tail where s'_tail is constant
        // The desired polynomial s(X) for this round `j` is
        // s(X) = eq(\vec xi, \vec r_{j-1}) eq(xi_{}, X) s'_head(X) + s'_tail * X
        //
        // The head vs tail corresponds to the cutoff in front loaded batching where the coordinates
        // have been exhausted.
        //
        // In fact, we further need to split s'_head into s'_{head,zc} and s'_{head,logup} due to
        // different eq versus eq_sharp round 0 contributions.
        let tail_start = prover
            .n_per_trace
            .iter()
            .find_position(|&&n| round as isize > n)
            .map(|(i, _)| i)
            .unwrap_or(num_traces);
        let mut sp_head_zc = vec![SC::EF::ZERO; constraint_degree];
        let mut sp_head_logup = vec![SC::EF::ZERO; constraint_degree];
        let mut sp_tail = SC::EF::ZERO;
        for trace_idx in 0..num_traces {
            let zc_idx = 2 * num_traces + trace_idx;
            let numer_idx = 2 * trace_idx;
            let denom_idx = numer_idx + 1;
            if trace_idx < tail_start {
                for i in 0..constraint_degree {
                    sp_head_zc[i] += mu_pows[zc_idx] * sp_round_evals[zc_idx][i];
                    sp_head_logup[i] += mu_pows[numer_idx] * sp_round_evals[numer_idx][i]
                        + mu_pows[denom_idx] * sp_round_evals[denom_idx][i];
                }
            } else {
                sp_tail += mu_pows[zc_idx] * sp_round_evals[zc_idx][0]
                    + mu_pows[numer_idx] * sp_round_evals[numer_idx][0]
                    + mu_pows[denom_idx] * sp_round_evals[denom_idx][0];
            }
        }
        // With eq(xi,r) contributions
        let mut sp_head_evals = vec![SC::EF::ZERO; s_deg];
        for i in 0..constraint_degree {
            sp_head_evals[i + 1] = prover.eq_ns[round - 1] * sp_head_zc[i]
                + prover.eq_sharp_ns[round - 1] * sp_head_logup[i];
        }
        // We need to derive s'(0).
        // We use that s_j(0) + s_j(1) = s_{j-1}(r_{j-1})
        let xi_cur = prover.xi[l_skip + round - 1];
        {
            let eq_xi_0 = SC::EF::ONE - xi_cur;
            let eq_xi_1 = xi_cur;
            sp_head_evals[0] =
                (prover.prev_s_eval - eq_xi_1 * sp_head_evals[1] - sp_tail) * eq_xi_0.inverse();
        }
        // s' has degree s_deg - 1
        let sp_head = UnivariatePoly::lagrange_interpolate(
            &(0..s_deg).map(SC::F::from_usize).collect_vec(),
            &sp_head_evals,
        );
        // eq(xi, X) = (2 * xi - 1) * X + (1 - xi)
        // Compute s(X) = eq(xi, X) * s'_head(X) + s'_tail * X (s'_head now contains eq(..,r))
        // s(X) has degree s_deg
        let batch_s = {
            let mut coeffs = sp_head.into_coeffs();
            coeffs.push(SC::EF::ZERO);
            let b = SC::EF::ONE - xi_cur;
            let a = xi_cur - b;
            for i in (0..s_deg).rev() {
                coeffs[i + 1] = a * coeffs[i] + b * coeffs[i + 1];
            }
            coeffs[0] *= b;
            coeffs[1] += sp_tail;
            UnivariatePoly::new(coeffs)
        };
        let batch_s_evals = (1..=s_deg)
            .map(|i| batch_s.eval_at_point(SC::EF::from_usize(i)))
            .collect_vec();
        for &eval in &batch_s_evals {
            transcript.observe_ext(eval);
        }
        sumcheck_round_polys.push(batch_s_evals);

        let r_round = transcript.sample_ext();
        debug!(%round, %r_round);
        r.push(r_round);
        prover.prev_s_eval = batch_s.eval_at_point(r_round);

        prover.fold_mle_evals(round, r_round);
    }
    drop(_mle_rounds_span);
    if r.len() != n_max + 1 {
        return Err(LogupZerocheckError::RLenMismatch {
            r_len: r.len(),
            expected: n_max + 1,
        });
    }

    let column_openings = prover.extract_column_openings()?;

    // Observe common main openings first, and then preprocessed/cached
    for (helper, openings) in prover.eval_helpers.iter().zip(column_openings.iter()) {
        for (claim, claim_rot) in column_openings_by_rot(&openings[0], helper.needs_next) {
            transcript.observe_ext(claim);
            transcript.observe_ext(claim_rot);
        }
    }
    for (helper, openings) in prover.eval_helpers.iter().zip(column_openings.iter()) {
        for part in openings.iter().skip(1) {
            for (claim, claim_rot) in column_openings_by_rot(part, helper.needs_next) {
                transcript.observe_ext(claim);
                transcript.observe_ext(claim_rot);
            }
        }
    }

    let batch_constraint_proof = BatchConstraintProof::<SC> {
        numerator_term_per_air,
        denominator_term_per_air,
        univariate_round_coeffs: s_0_poly.into_coeffs(),
        sumcheck_round_polys,
        column_openings,
    };
    let gkr_proof = GkrProof::<SC> {
        logup_pow_witness,
        q0_claim: frac_sum_proof.fractional_sum.1,
        claims_per_layer: frac_sum_proof.claims_per_layer,
        sumcheck_polys: frac_sum_proof.sumcheck_polys,
    };
    Ok(ZerocheckLogupProof {
        gkr: gkr_proof,
        batch: batch_constraint_proof,
        eval_point: r,
    })
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;

    use crate::{
        config::koala_bear_poseidon2::{DuplexSponge, F},
        engine::koala_bear_poseidon2::KoalaBearPoseidon2RefEngine,
        test_utils::{test_system_params_small, FibFixture, InteractionsFixture11, TestFixture},
        StarkEngine,
    };

    type Engine = KoalaBearPoseidon2RefEngine<DuplexSponge>;

    /// A chip carrying LogUp interactions (1 sender + 1 receiver, balanced) runs through the full
    /// LogUp-ZeroCheck phase and the resulting proof verifies.
    #[test]
    fn interactions_chip_proves_and_verifies() {
        let engine = Engine::new(test_system_params_small(2, 5, 3));
        let (vk, proof) = InteractionsFixture11.keygen_and_prove(&engine);
        engine
            .verify(&vk, &proof)
            .expect("valid interaction proof must verify");
    }

    /// ZeroCheck rejects an invalid trace: tampering a public value breaks the boundary constraint,
    /// so the batch-constraint verification must fail.
    #[test]
    fn zerocheck_rejects_tampered_public_value() {
        let engine = Engine::new(test_system_params_small(2, 5, 3));
        let fixture = FibFixture::new(0, 1, 1 << 5);
        let (vk, mut proof) = fixture.keygen_and_prove(&engine);
        engine
            .verify(&vk, &proof)
            .expect("untampered fib proof must verify");

        // Corrupt the claimed Fibonacci output; the last-row boundary constraint no longer holds.
        proof.public_values[0][2] += F::ONE;
        assert!(
            engine.verify(&vk, &proof).is_err(),
            "tampered public value must be rejected"
        );
    }
}
