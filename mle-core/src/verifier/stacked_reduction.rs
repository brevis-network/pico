use std::iter::zip;

use itertools::Itertools;
use p3_field::{PrimeCharacteristicRing, TwoAdicField};
use thiserror::Error;
use tracing::{debug, instrument};

use crate::{
    poly::{
        eval_eq_mle, eval_eq_prism, eval_in_uni, eval_rot_kernel_prism, horner_eval,
        interpolate_quadratic_at_012,
    },
    proof::{column_openings_by_rot, StackingProof},
    protocol::stacking::{lambda_slots, StackedLayout},
    verifier::Pass,
    FiatShamirTranscript, StarkProtocolConfig,
};

#[derive(Error, Debug, PartialEq, Eq)]
pub enum StackedReductionError<EF: core::fmt::Debug + core::fmt::Display + PartialEq + Eq> {
    #[error("s_0 does not match s_0 polynomial evaluation sum: {s_0} != {s_0_sum_eval}")]
    S0Mismatch { s_0: EF, s_0_sum_eval: EF },

    #[error("s_n(u_n) does not match claimed q(u) sum: {claim} != {final_sum}")]
    FinalSumMismatch { claim: EF, final_sum: EF },
}

/// `has_prep_per_trace` must be per present trace in sorted AIR order.
///
/// When `merged_preprocessed` is true, all preprocessed matrices live in ONE multi-matrix
/// commitment at commit index 1 (matrix order = trace order restricted to preprocessed
/// AIRs), followed by the per-trace cached commitments; otherwise each preprocessed/cached
/// matrix is its own single-matrix commitment interleaved per trace.
#[allow(clippy::too_many_arguments)]
pub fn verify_stacked_reduction<SC: StarkProtocolConfig, TS: FiatShamirTranscript<SC>>(
    transcript: &mut TS,
    proof: &StackingProof<SC>,
    layouts: &[StackedLayout],
    need_rot_per_commit: &[Vec<bool>],
    merged_preprocessed: bool,
    has_prep_per_trace: &[bool],
    l_skip: usize,
    n_stack: usize,
    column_openings: &[Vec<Vec<SC::EF>>],
    r: &[SC::EF],
    omega_skip_pows: &[SC::F],
) -> Result<Vec<SC::EF>, StackedReductionError<SC::EF>>
where
    SC::EF: TwoAdicField,
{
    verify_stacked_reduction_inner(
        transcript,
        proof,
        layouts,
        need_rot_per_commit,
        merged_preprocessed,
        has_prep_per_trace,
        l_skip,
        n_stack,
        column_openings,
        r,
        omega_skip_pows,
        Pass::Verify,
    )
}

/// [`verify_stacked_reduction`] under an explicit [`Pass`].
///
/// Under [`Pass::TranscriptOnly`] the λ-slot assignment, the `t_claims` gather, the λ power table,
/// the `s_0` reduction and its comparison, both interpolations and the per-column prism evaluation
/// that builds `q_coeffs` are skipped; `layouts` is then read by nothing. Kept: every observation (including each stacking
/// opening `q_j`), the sampled λ and `u`, and the `n_stack` round count — so the returned `u` is
/// the real opening point a full verification would reach.
#[allow(clippy::too_many_arguments)]
#[instrument(name = "verify_stacked_reduction", level = "debug", skip_all)]
pub(crate) fn verify_stacked_reduction_inner<
    SC: StarkProtocolConfig,
    TS: FiatShamirTranscript<SC>,
>(
    transcript: &mut TS,
    proof: &StackingProof<SC>,
    layouts: &[StackedLayout],
    need_rot_per_commit: &[Vec<bool>],
    merged_preprocessed: bool,
    has_prep_per_trace: &[bool],
    l_skip: usize,
    n_stack: usize,
    column_openings: &[Vec<Vec<SC::EF>>],
    r: &[SC::EF],
    omega_skip_pows: &[SC::F],
    pass: Pass,
) -> Result<Vec<SC::EF>, StackedReductionError<SC::EF>>
where
    SC::EF: TwoAdicField,
{
    /*
     * SETUP
     *
     * We start by setting up for the rounds below. Most importantly, we need to ensure that the
     * order we process column_openings is the same as the stacked reduction prover. The prover
     * orders the claims per commit -> per column (as in layouts), but column_openings is per AIR
     * -> per part (common main, preprocessed, then cached) -> per column. Note that the verifier
     * needs to compute and pass in has_preprocessed, which is expected to be sorted in the same
     * way column_openings is (i.e. sorted by trace height).
     */

    // omega_order = 2^l_skip
    let omega_order = omega_skip_pows.len();

    // layouts and need_rot_per_commit both have length equal to the number of commitments
    debug_assert_eq!(layouts.len(), need_rot_per_commit.len());
    // Shared SSOT: the same per-column (eq, rot) λ exponents the prover assigned
    // (`prove_stacked_opening_reduction`), so the two sides cannot drift on the batching.
    // The gather observes nothing — `column_openings` was observed in full by
    // `verify_zerocheck_and_logup`; this only re-orders it into commitment order for `s_0`.
    let slots = if pass.checks() {
        lambda_slots(layouts.iter(), need_rot_per_commit)
    } else {
        vec![]
    };
    let t_claims = if pass.checks() {
        // t_claims_len = w_{\Scr T, stack}
        let t_claims_len: usize = slots.iter().map(|cols| cols.len()).sum();
        let mut t_claims = Vec::with_capacity(t_claims_len);

        // Proof shape asserts that column_openings.len() == num_traces and each parts.len() ==
        // vk.num_parts() common main columns (commit 0)
        for (trace_idx, parts) in column_openings.iter().enumerate() {
            let need_rot = need_rot_per_commit[0][trace_idx];
            t_claims.extend(column_openings_by_rot(&parts[0], need_rot));
        }

        let mut commit_idx = 1usize;
        if merged_preprocessed {
            // Merged preprocessed commitment (commit 1): claims follow the merged layout's
            // matrix order == trace order restricted to preprocessed traces.
            let need_rots = &need_rot_per_commit[1];
            let mut mat_idx = 0usize;
            for (trace_idx, parts) in column_openings.iter().enumerate() {
                if has_prep_per_trace[trace_idx] {
                    t_claims.extend(column_openings_by_rot(&parts[1], need_rots[mat_idx]));
                    mat_idx += 1;
                }
            }
            debug_assert_eq!(mat_idx, need_rots.len());
            commit_idx = 2;
        }

        // Remaining single-matrix commitments: per-air preprocessed (per-air mode only)
        // and cached columns, interleaved per trace.
        for (trace_idx, parts) in column_openings.iter().enumerate() {
            let skip = if merged_preprocessed && has_prep_per_trace[trace_idx] {
                2
            } else {
                1
            };
            for cols in parts.iter().skip(skip) {
                let need_rot = need_rot_per_commit[commit_idx][0];
                t_claims.extend(column_openings_by_rot(cols, need_rot));
                commit_idx += 1;
            }
        }

        // Both sides derive from the vkey column widths `verify_proof_shape` enforces earlier, so
        // this is unreachable here. Prover-side tests reach it directly but keep debug assertions
        // on.
        debug_assert_eq!(t_claims.len(), t_claims_len);
        t_claims
    } else {
        vec![]
    };
    debug!(?t_claims);

    let lambda = transcript.sample_ext();

    /*
     * INITIAL UNIVARIATE ROUND
     *
     * In this round we compute s_0 = sum_i (t_i * lambda^i) from the column opening claims t_i
     * and compare it to the s_1 polynomial in proof. If the polynomial was correctly computed,
     * then we should have s_0 == sum_{z in D} s_1(z).
     *
     * Note that we abuse the properties of multiplicative subgroup D to speed up the computation
     * of sum_{z in D} s_1(z). Suppose s_1(x) = a_0 + a_1 * x + ... a_k * x^k. Because we have
     * omega^{|D|} == 1, sum_{z in D} s_1(z) = |D| * (a_0 + a_{|D|} + ...).
     */
    // λ powers and `s_0` both index the slot assignment, which is empty under
    // `Pass::TranscriptOnly` — so they belong INSIDE the guard, not merely unused outside it.
    // `lambda_pows` outlives the block because `q_coeffs` below reads it.
    //
    // Prover and verifier both index `λ.powers()` with the shared slot assignment (`eq_exp`,
    // `rot_exp`); reserving `2` exponents per column matches the prover's `lambda_pows`.
    let mut lambda_pows = Vec::new();
    if pass.checks() {
        let n_lambda_pows = slots
            .iter()
            .flatten()
            .map(|s| s.rot_exp.unwrap_or(s.eq_exp) + 1)
            .max()
            .unwrap_or(0);
        lambda_pows = lambda.powers().take(n_lambda_pows).collect_vec();

        let s_0 = zip(&t_claims, slots.iter().flatten())
            .map(|(&(t_eq, t_rot), slot)| (t_eq + t_rot * lambda) * lambda_pows[slot.eq_exp])
            .sum::<SC::EF>();
        // Proof shape asserts that univariate_round_coeffs.len() == 2 * (2^l_skip - 1) + 1
        let s_0_sum_eval = proof
            .univariate_round_coeffs
            .iter()
            .step_by(omega_order)
            .copied()
            .sum::<SC::EF>()
            * SC::EF::from_usize(omega_order);

        if s_0 != s_0_sum_eval {
            return Err(StackedReductionError::S0Mismatch { s_0, s_0_sum_eval });
        }
    }

    for coeffs in &proof.univariate_round_coeffs {
        transcript.observe_ext(*coeffs);
    }

    let mut u = vec![SC::EF::ZERO; n_stack + 1];
    u[0] = transcript.sample_ext();
    debug!(round = 0, u_round = %u[0]);

    let mut claim = if pass.checks() {
        horner_eval(&proof.univariate_round_coeffs, u[0])
    } else {
        SC::EF::ZERO
    };

    /*
     * SUMCHECK ROUNDS 1 TO N
     *
     * We sample size n_stack vector u using the transcript, and run the verifier sumcheck for
     * rounds 1 to n_stack. We start by evaluating the univariate round polynomial at u_0, which
     * we store as s_0(u_0). We then evaluate s_j(0) = s_{j - 1}(u_{j - 1}) - s_j(1) for each j,
     * which we then use with s_j(1) and s_j(2) to interpolate s_j(u_j).
     */

    u.iter_mut().enumerate().skip(1).for_each(|(j, u_j)| {
        let s_j_1 = proof.sumcheck_round_polys[j - 1][0];
        let s_j_2 = proof.sumcheck_round_polys[j - 1][1];
        transcript.observe_ext(s_j_1);
        transcript.observe_ext(s_j_2);
        *u_j = transcript.sample_ext();
        if pass.checks() {
            let s_j_0 = claim - s_j_1;
            claim = interpolate_quadratic_at_012(&[s_j_0, s_j_1, s_j_2], *u_j);
        }
        debug!(round = %j, sum_claim = %claim);
    });

    /*
     * FINAL VERIFICATION
     *
     * Finally, to verify that the claims about t_i(r) were properly reduced we assert that the
     * final s_{n_stack}(u_{n_stack}) == sum_j (lambda^j * q_{j'}(u) * h(u, r, b_j)), where each
     * j maps to some (non-unique) j' and h(u, r, b_j) is either (a) eq(u_{n_j}, r_{n_j}) *
     * eq(u_{> n_j}, b_j) or (b) rot(u_{n_j}, r_{n_j}) * eq(u_{> n_j}, b_j).
     *
     * It is up to the verifier to compute each h(u, r, b_j). Let q_coeffs[j'] be the sum of all
     * lambda^j * h(u, r, b_j) such that j maps to j' - given claims q_{j'}(u), we thus want to
     * assert s_{n_stack}(u_{n_stack}) == sum_{j'} q_{j'}(u) * q_coeffs[j'].
     */

    // proof shape asserts that stacking_openings.len() == layouts.len() = number of commitments
    let mut q_coeffs = proof
        .stacking_openings
        .iter()
        .map(|vec| vec![SC::EF::ZERO; vec.len()])
        .collect_vec();

    // Skipped wholesale under `Pass::TranscriptOnly`: `q_coeffs` stays all-zero and only weights
    // the openings in `final_sum` below, which nothing then compares. The `q_j` OBSERVATIONS live
    // in the loop after this one and run on both passes.
    if pass.checks() {
        layouts
            .iter()
            .enumerate()
            .zip(q_coeffs.iter_mut())
            .for_each(|((commit_idx, layout), coeffs)| {
                let commit_slots = &slots[commit_idx];
                layout
                    .sorted_cols
                    .iter()
                    .zip(commit_slots)
                    .for_each(|(col, slot)| {
                        let s = col.slice;
                        let n = s.log_height() as isize - l_skip as isize;
                        let n_lift = n.max(0) as usize;
                        let b = (l_skip + n_lift..l_skip + n_stack)
                            .map(|j| SC::EF::from_bool((s.row_idx >> j) & 1 == 1))
                            .collect_vec();
                        let eq_mle = eval_eq_mle(&u[n_lift + 1..], &b);
                        let ind = eval_in_uni(l_skip, n, u[0]);
                        let (l, rs_n) = if n.is_negative() {
                            (
                                l_skip.wrapping_add_signed(n),
                                &[r[0].exp_power_of_2(-n as usize)] as &[_],
                            )
                        } else {
                            (l_skip, &r[..=n_lift])
                        };
                        let eq_prism = eval_eq_prism(l, &u[..=n_lift], rs_n);
                        let mut batched = lambda_pows[slot.eq_exp] * eq_prism;
                        if let Some(rot_exp) = slot.rot_exp {
                            let rot_kernel_prism = eval_rot_kernel_prism(l, &u[..=n_lift], rs_n);
                            batched += lambda_pows[rot_exp] * rot_kernel_prism;
                        }
                        coeffs[s.col_idx] += eq_mle * batched * ind;
                    });
            });
    }

    // `q_coeffs` mirrors `stacking_openings` shape on both passes, so this walks — and observes —
    // every opening in the same order regardless of `pass`.
    let final_sum = q_coeffs.iter().zip(proof.stacking_openings.iter()).fold(
        SC::EF::ZERO,
        |acc, (q_coeff_vec, q_j_vec)| {
            acc + q_coeff_vec.iter().zip(q_j_vec.iter()).fold(
                SC::EF::ZERO,
                |acc, (&q_coeff, &q_j)| {
                    transcript.observe_ext(q_j);
                    acc + (q_coeff * q_j)
                },
            )
        },
    );

    if pass.checks() && claim != final_sum {
        return Err(StackedReductionError::FinalSumMismatch { claim, final_sum });
    }

    Ok(u)
}
