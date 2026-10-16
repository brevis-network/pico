//! Stacked opening reduction

use std::{array::from_fn, collections::HashMap, iter::zip, mem::take};

use itertools::Itertools;
use p3_field::{ExtensionField, PrimeCharacteristicRing, TwoAdicField};
use p3_maybe_rayon::prelude::*;
use tracing::{debug, instrument};

use crate::{
    poly::{
        eval_eq_mle, eval_eq_uni, eval_eq_uni_at_one, eval_in_uni, evals_eq_hypercube_par,
        matrix::{ColMajorMatrix, ColMajorMatrixView, MatrixDimensions, MatrixView},
        UnivariatePoly,
    },
    proof::StackingProof,
    protocol::stacking::{lambda_slots, ColLambda, StackedSlice},
    prover::{
        stacked_pcs::StackedPcsData,
        sumcheck::{
            batch_fold_mle_evals, fold_mle_evals, fold_ple_evals, sumcheck_round0_deg,
            sumcheck_round_poly_evals, sumcheck_uni_round0_poly,
        },
        ProverBackend, ReferenceColMajorBackend, ReferenceDevice,
    },
    FiatShamirTranscript, StarkProtocolConfig,
};

/// Helper trait for proving the reduction of column opening claims and column rotation opening
/// claims to opening claims of column polynomials of the stacked matrix.
///
/// Returns the reduction proof and the random vector `u` of length `1 + n_stack`.
pub trait StackedReductionProver<'a, PB: ProverBackend, PD> {
    /// We only provide a view to the stacked `PcsData` per commitment because the WHIR prover will
    /// still use the PLE evaluations of the stacked matrices later. The order of
    /// `stacked_per_commit` is `common_main, preprocessed for trace_idx=0 (if any), cached_0 for
    /// trace_idx=0, ..., preprocessed for trace_idx=1 (if any), ...`.
    ///
    /// The `lambda` is the batching randomness for the batch sumcheck.
    fn new(
        device: &'a PD,
        stacked_per_commit: Vec<&'a PB::PcsData>,
        need_rot_per_commit: Vec<Vec<bool>>,
        r: &[PB::Challenge],
        lambda: PB::Challenge,
    ) -> Self;

    /// Return the `s_0` batched polynomial from univariate round 0 of sumcheck.
    fn batch_sumcheck_uni_round0_poly(&mut self) -> UnivariatePoly<PB::Challenge>;

    fn fold_ple_evals(&mut self, u_0: PB::Challenge);

    fn batch_sumcheck_poly_eval(
        &mut self,
        round: usize,
        u_prev: PB::Challenge,
    ) -> [PB::Challenge; 2];

    fn fold_mle_evals(&mut self, round: usize, u_round: PB::Challenge);

    fn into_stacked_openings(self) -> Vec<Vec<PB::Challenge>>;
}

/// Batch sumcheck to reduce trace openings, including rotations, to stacked matrix opening.
///
/// The `stacked_matrix, stacked_layout` should be the result of stacking the `traces` with
/// parameters `l_skip` and `n_stack`.
#[instrument(level = "info", skip_all)]
pub fn prove_stacked_opening_reduction<'a, SC, PB, PD, TS, SRP>(
    device: &'a PD,
    transcript: &mut TS,
    n_stack: usize,
    stacked_per_commit: Vec<&'a PB::PcsData>,
    need_rot_per_commit: Vec<Vec<bool>>,
    r: &[PB::Challenge],
) -> (StackingProof<SC>, Vec<PB::Challenge>)
where
    SC: StarkProtocolConfig,
    PB: ProverBackend<Val = SC::F, Challenge = SC::EF>,
    TS: FiatShamirTranscript<SC>,
    SRP: StackedReductionProver<'a, PB, PD>,
{
    // Batching randomness
    let lambda = transcript.sample_ext();

    let mut prover = SRP::new(device, stacked_per_commit, need_rot_per_commit, r, lambda);
    let s_0 = prover.batch_sumcheck_uni_round0_poly();
    for &coeff in s_0.coeffs() {
        transcript.observe_ext(coeff);
    }

    let mut u_vec = Vec::with_capacity(n_stack + 1);
    let u_0 = transcript.sample_ext();
    u_vec.push(u_0);
    debug!(round = 0, u_round = %u_0);

    prover.fold_ple_evals(u_0);
    // end round 0

    let mut sumcheck_round_polys = Vec::with_capacity(n_stack);

    #[allow(clippy::needless_range_loop)]
    for round in 1..=n_stack {
        let batch_s_evals = prover.batch_sumcheck_poly_eval(round, u_vec[round - 1]);

        for &eval in &batch_s_evals {
            transcript.observe_ext(eval);
        }
        sumcheck_round_polys.push(batch_s_evals);

        let u_round = transcript.sample_ext();
        u_vec.push(u_round);
        debug!(%round, %u_round);

        prover.fold_mle_evals(round, u_round);
    }
    let stacking_openings = prover.into_stacked_openings();
    for claims_for_com in &stacking_openings {
        for &claim in claims_for_com {
            transcript.observe_ext(claim);
        }
    }
    let proof = StackingProof::<SC> {
        univariate_round_coeffs: s_0.0,
        sumcheck_round_polys,
        stacking_openings,
    };
    (proof, u_vec)
}

pub struct StackedReductionRef<'a, SC: StarkProtocolConfig> {
    l_skip: usize,
    omega_skip: SC::F,

    r_0: SC::EF,
    lambda_pows: Vec<SC::EF>,
    eq_const: SC::EF,

    stacked_per_commit: Vec<&'a StackedPcsData<SC::F, SC::Digest>>,
    trace_views: Vec<TraceViewMeta>,
    ht_diff_idxs: Vec<usize>,

    eq_r_per_lht: HashMap<usize, ColMajorMatrix<SC::EF>>,

    // After round 0:
    k_rot_r_per_lht: HashMap<usize, ColMajorMatrix<SC::EF>>,
    q_evals: Vec<ColMajorMatrix<SC::EF>>,
    /// Stores eq(u[1+n_T..round-1], b_{T,j}[..round-n_T-1])
    eq_ub_per_trace: Vec<SC::EF>,
}

struct TraceViewMeta {
    com_idx: usize,
    slice: StackedSlice,
    /// λ-batching slots (`eq` and optional `rot`) for this column, from the shared
    /// [`lambda_slots`] SSOT so the prover and verifier assign the same exponents.
    lambda: ColLambda,
}

impl<'a, SC: StarkProtocolConfig>
    StackedReductionProver<'a, ReferenceColMajorBackend<SC>, ReferenceDevice<SC>>
    for StackedReductionRef<'a, SC>
where
    SC::F: TwoAdicField,
    SC::EF: TwoAdicField + ExtensionField<SC::F>,
    ReferenceColMajorBackend<SC>: ProverBackend<
        Val = SC::F,
        Challenge = SC::EF,
        PcsData = StackedPcsData<SC::F, SC::Digest>,
        Matrix = ColMajorMatrix<SC::F>,
    >,
{
    fn new(
        device: &ReferenceDevice<SC>,
        stacked_per_commit: Vec<&'a StackedPcsData<SC::F, SC::Digest>>,
        need_rot_per_commit: Vec<Vec<bool>>,
        r: &[SC::EF],
        lambda: SC::EF,
    ) -> Self {
        let l_skip = device.params().l_skip;
        let omega_skip = SC::F::two_adic_generator(l_skip);

        // Shared SSOT: assign each column its (eq, rot) λ exponents; the verifier walks the same
        // layouts identically (`verify_stacked_reduction`).
        let slots = lambda_slots(
            stacked_per_commit.iter().map(|d| &d.layout),
            &need_rot_per_commit,
        );
        let mut trace_views = Vec::new();
        for (com_idx, (d, commit_slots)) in zip(&stacked_per_commit, &slots).enumerate() {
            for (col, &lambda) in zip(&d.layout.sorted_cols, commit_slots) {
                trace_views.push(TraceViewMeta {
                    com_idx,
                    slice: col.slice,
                    lambda,
                });
            }
        }
        let n_lambda_pows = slots
            .iter()
            .flatten()
            .map(|s| s.rot_exp.unwrap_or(s.eq_exp) + 1)
            .max()
            .unwrap_or(0);
        let lambda_pows = lambda.powers().take(n_lambda_pows).collect_vec();

        let mut ht_diff_idxs = Vec::new();
        let mut eq_r_per_lht: HashMap<usize, ColMajorMatrix<SC::EF>> = HashMap::new();
        let mut last_height = 0;
        for (i, tv) in trace_views.iter().enumerate() {
            let n_lift = tv.slice.log_height().saturating_sub(l_skip);
            if i == 0 || tv.slice.log_height() != last_height {
                ht_diff_idxs.push(i);
                last_height = tv.slice.log_height();
            }
            eq_r_per_lht
                .entry(tv.slice.log_height())
                .or_insert_with(|| {
                    ColMajorMatrix::new(evals_eq_hypercube_par(&r[1..1 + n_lift]), 1)
                });
        }
        ht_diff_idxs.push(trace_views.len());

        let eq_const = eval_eq_uni_at_one(l_skip, r[0] * omega_skip);
        let eq_ub_per_trace = vec![SC::EF::ONE; trace_views.len()];

        Self {
            l_skip,
            omega_skip,
            r_0: r[0],
            lambda_pows,
            eq_const,
            stacked_per_commit,
            trace_views,
            ht_diff_idxs,
            eq_r_per_lht,
            q_evals: vec![],
            k_rot_r_per_lht: HashMap::new(),
            eq_ub_per_trace,
        }
    }

    fn batch_sumcheck_uni_round0_poly(&mut self) -> UnivariatePoly<SC::EF> {
        let l_skip = self.l_skip;
        let omega_skip = self.omega_skip;
        // +1 from eq term
        let s_0_deg = sumcheck_round0_deg(l_skip, 2);
        // We want to compute algebraic batching, via \lambda,
        // for each (T, j) pair of (trace, column) of the univariate polynomials
        // ```text
        // Z -> sum_{x in H_{n_stack}} q(Z,x) in_{D,n_T}(Z) eq_{D_{n_T}}((Z,x[..\tilde n_T]), r[..1+\tilde n_T]) eq(x[\tilde n_T..], b_{T,j})
        // Z -> sum_{x in H_{n_stack}} q(Z,x) in_{D,n_T}(Z) \kappa_{\rot, D_{n_T}}((Z,x[..\tilde n_T]), r[..1+\tilde n_T]) eq(x[\tilde n_T..], b_{T,j})
        // ```
        // where `b_{T,j}` is length `n_stack - n_T` binary encoding of `StackedSlice.row_idx >>
        // (l_skip
        // + n_T)`. Note that since x is in the hypercube, by definition of `eq` the above
        // simplifies to
        // ```text
        // Z -> sum_{x in H_{n_T}} q(Z,x,b_{T,j}) (in_{D,n_T}(Z) eq(Z,r_0)) eq(x[..\tilde n_T], r[1..1+\tilde n_T])
        // Z -> sum_{x in H_{n_T}} q(Z,x,b_{T,j}) in_{D,n_T}(Z) \kappa_rot((Z, x[..n_T]), (r_0, r[1..1+n_T]))
        // ```
        // where we also simplified the other `eq` term.
        // We further simplify the second using equation
        // ```text
        // \kappa_rot((Z, x[..n_T]), (r_0, r[1..1+n_T])) =
        // eq_D(Z,omega_D r_0) eq(x[..n_T], r[1..1+n_T]) + eq_D(Z,1)eq_D(omega_D r_0,1) ( kappa_rot(x[..n_T], r[1..1+n_T]) - eq(x[..n_T], r[1..1+n_T]) )
        // ```
        // We compute the last polynomial in our usual way, by considering `q(\vec Z, b_{T,j})` as a
        // prismalinear polynomial and using its evaluations on `D_{n_T}`.
        let s_0_polys: Vec<_> = self
            .ht_diff_idxs
            .par_windows(2)
            .flat_map(|window| {
                let t_window = &self.trace_views[window[0]..window[1]];
                let log_height = t_window[0].slice.log_height();
                let n = log_height as isize - l_skip as isize;
                let n_lift = n.max(0) as usize;
                let eq_rs = self.eq_r_per_lht.get(&log_height).unwrap().column(0);
                debug_assert_eq!(eq_rs.len(), 1 << n_lift);
                // Prepare the q subslice eval views
                let q_t_cols = t_window
                    .iter()
                    .map(|tv| {
                        debug_assert_eq!(tv.slice.log_height(), log_height);
                        let q = &self.stacked_per_commit[tv.com_idx].matrix;
                        let s = tv.slice;
                        let q_t_col = &q.column(s.col_idx)[s.row_idx..s.row_idx + s.len(l_skip)];
                        // NOTE: even if s.stride(l_skip) != 1, we use the full non-strided column
                        // subslice. The sumcheck will not depend on the values outside of the
                        // stride because of the `in_{D, n_T}` indicator below.
                        (ColMajorMatrixView::new(q_t_col, 1).into(), false)
                    })
                    .collect_vec();
                sumcheck_uni_round0_poly(l_skip, n_lift, 2, &q_t_cols, |z, x, evals| {
                    let eq_cube = eq_rs[x];
                    let (l, omega, r_uni) = if n.is_negative() {
                        (
                            l_skip.wrapping_add_signed(n),
                            omega_skip.exp_power_of_2(-n as usize),
                            self.r_0.exp_power_of_2(-n as usize),
                        )
                    } else {
                        (l_skip, omega_skip, self.r_0)
                    };
                    let ind = eval_in_uni(l_skip, n, z);
                    let eq_uni_r0 = eval_eq_uni(l, z.into(), r_uni);
                    let eq_uni_r0_rot = eval_eq_uni(l, z.into(), r_uni * omega);
                    // eq_uni_1, k_rot_cube are only used when n > 0
                    let eq_uni_1 = eval_eq_uni_at_one(l_skip, z);
                    let k_rot_cube = eq_rs[rot_prev(x, n_lift)];

                    let eq = eq_uni_r0 * eq_cube;
                    let k_rot =
                        eq_uni_r0_rot * eq_cube + self.eq_const * eq_uni_1 * (k_rot_cube - eq_cube);
                    zip(t_window, evals).fold([SC::EF::ZERO; 2], |mut acc, (tv, eval)| {
                        let q = eval[0];
                        acc[0] += self.lambda_pows[tv.lambda.eq_exp] * eq * q * ind;
                        if let Some(rot_exp) = tv.lambda.rot_exp {
                            acc[1] += self.lambda_pows[rot_exp] * k_rot * q * ind;
                        }
                        acc
                    })
                })
            })
            .collect();
        let s_0_coeffs = (0..=s_0_deg)
            .map(|i| {
                s_0_polys
                    .iter()
                    .map(|evals| evals.coeffs()[i])
                    .sum::<SC::EF>()
            })
            .collect_vec();
        UnivariatePoly::new(s_0_coeffs)
    }

    fn fold_ple_evals(&mut self, u_0: SC::EF) {
        let l_skip = self.l_skip;
        let r_0 = self.r_0;
        let omega_skip = self.omega_skip;
        self.q_evals = self
            .stacked_per_commit
            .iter()
            .map(|d| fold_ple_evals(l_skip, d.matrix.as_view().into(), false, u_0))
            .collect_vec();
        // fold PLEs into MLEs for \eq and \kappa_\rot, using u_0
        let eq_uni_u0r0 = eval_eq_uni(l_skip, u_0, r_0);
        let eq_uni_u0r0_rot = eval_eq_uni(l_skip, u_0, r_0 * omega_skip);
        let eq_uni_u01 = eval_eq_uni_at_one(l_skip, u_0);
        // \kappa_\rot(x, r) = eq(rot^{-1}(x), r)
        self.k_rot_r_per_lht = self
            .eq_r_per_lht
            .par_iter_mut()
            .map(|(&log_height, mat)| {
                let n = log_height as isize - l_skip as isize;
                let n_lift = n.max(0) as usize;
                debug_assert_eq!(mat.values.len(), 1 << n_lift);
                let ind = eval_in_uni(l_skip, n, u_0);
                let (eq_uni, eq_uni_rot) = if n.is_negative() {
                    let omega = omega_skip.exp_power_of_2(-n as usize);
                    let r = r_0.exp_power_of_2(-n as usize);
                    let l = l_skip.wrapping_add_signed(n);
                    (eval_eq_uni(l, u_0, r), eval_eq_uni(l, u_0, r * omega))
                } else {
                    (eq_uni_u0r0, eq_uni_u0r0_rot)
                };
                // folded \kappa_\rot evals
                let evals: Vec<_> = (0..1 << n_lift)
                    .into_par_iter()
                    .map(|x| {
                        let eq_cube = unsafe { *mat.get_unchecked(x, 0) };
                        let k_rot_cube = unsafe { *mat.get_unchecked(rot_prev(x, n_lift), 0) };
                        ind * (eq_uni_rot * eq_cube
                            + self.eq_const * eq_uni_u01 * (k_rot_cube - eq_cube))
                    })
                    .collect();
                // update \eq with the univariate factor:
                mat.values.par_iter_mut().for_each(|v| {
                    *v *= ind * eq_uni;
                });
                (log_height, ColMajorMatrix::new(evals, 1))
            })
            .collect();
    }

    fn batch_sumcheck_poly_eval(&mut self, round: usize, _u_prev: SC::EF) -> [SC::EF; 2] {
        let l_skip = self.l_skip;
        let s_deg = 2;
        // We want to compute algebraic batching, via \lambda,
        // for each (T, j) pair of (trace, column) of the univariate polynomials
        // ```
        // X -> sum_{y in H_{n_stack-round}} q(u[..round],X,y) eq((u[..round],X,y[..n_T-round]), r[..1+n_T]) eq(y[n_T-round..], b_{T,j})
        //      = sum_{y in H_{n_T-round}} q(u[..round],X,y,b_{T,j}) eq((u[..round],X,y), r[..1+n_T])
        // X -> sum_{y in H_{n_stack-round}} q(u[..round],X,y) \kappa_\rot((u[..round],X,y[..n_T]), r[..1+n_T]) eq(y[n_T..], b_{T,j})
        // ```
        // if `round <= n_T`. Otherwise we compute
        // ```
        // X -> sum_{y in H_{n_stack-round}} q(u[..round],X,y) eq((u[..1+n_T], r[..1+n_T]) eq((u[1+n_T..round],X,y[round..]), b_{T,j})
        //      = q(u[..round], X, b_{T,j}[round-n_T..]) eq((u[..1+n_T], r[..1+n_T]) eq((u[1+n_T..round],X), b_{T,j}[..round-n_T])
        // X -> sum_{y in H_{n_stack-round}} q(u[..round],X,y) \kappa_\rot(u[..1+n_T], r[..1+n_T]) eq((u[1+n_T..round],X,y[round..]), b_{T,j})
        // ```
        let s_evals: Vec<_> = self
            .ht_diff_idxs
            .par_windows(2)
            .flat_map(|window| {
                let t_views = &self.trace_views[window[0]..window[1]];
                let log_height = t_views[0].slice.log_height();
                let n_lift = log_height.saturating_sub(l_skip); // \tilde{n}_T
                let hypercube_dim = n_lift.saturating_sub(round);
                let eq_rs = self.eq_r_per_lht.get(&log_height).unwrap().column(0);
                let k_rot_rs = self.k_rot_r_per_lht.get(&log_height).unwrap().column(0);
                debug_assert_eq!(eq_rs.len(), 1 << n_lift.saturating_sub(round - 1));
                debug_assert_eq!(k_rot_rs.len(), 1 << n_lift.saturating_sub(round - 1));
                // Prepare the q subslice eval views
                let t_cols = t_views
                    .iter()
                    .map(|tv| {
                        debug_assert_eq!(tv.slice.log_height(), log_height);
                        // q(u[..round], X, b_{T,j}[round-\tilde n_T..])
                        // q_evals has been folded already
                        let q = &self.q_evals[tv.com_idx];
                        let s = tv.slice;
                        let row_start = if round <= n_lift {
                            // round >= 1 so n_lift >= 1
                            (s.row_idx >> log_height) << (hypercube_dim + 1)
                        } else {
                            (s.row_idx >> (l_skip + round)) << 1
                        };
                        let t_col =
                            &q.column(s.col_idx)[row_start..row_start + (2 << hypercube_dim)];
                        ColMajorMatrixView::new(t_col, 1)
                    })
                    .collect_vec();
                sumcheck_round_poly_evals(hypercube_dim + 1, s_deg, &t_cols, |x, y, evals| {
                    evals
                        .iter()
                        .enumerate()
                        .fold([SC::EF::ZERO; 2], |mut acc, (i, eval)| {
                            let t_idx = window[0] + i;
                            let tv = &self.trace_views[t_idx];
                            let q = eval[0];
                            let mut eq_ub = self.eq_ub_per_trace[t_idx];
                            let (eq, k_rot) = if round > n_lift {
                                // Extra contribution of eq(X, b_{T,j}[round-n_T-1])
                                let b = (tv.slice.row_idx >> (l_skip + round - 1)) & 1;
                                eq_ub *= eval_eq_mle(&[x], &[SC::F::from_bool(b == 1)]);
                                debug_assert_eq!(y, 0);
                                (eq_rs[0] * eq_ub, k_rot_rs[0] * eq_ub)
                            } else {
                                // linearly interpolate eq(-, r[..1+n_T]), \kappa_\rot(-,
                                // r[..1+n_T])
                                let eq_r =
                                    eq_rs[y << 1] * (SC::EF::ONE - x) + eq_rs[(y << 1) + 1] * x;
                                let k_rot_r = k_rot_rs[y << 1] * (SC::EF::ONE - x)
                                    + k_rot_rs[(y << 1) + 1] * x;
                                (eq_r * eq_ub, k_rot_r * eq_ub)
                            };
                            acc[0] += self.lambda_pows[tv.lambda.eq_exp] * q * eq;
                            if let Some(rot_exp) = tv.lambda.rot_exp {
                                acc[1] += self.lambda_pows[rot_exp] * q * k_rot;
                            }
                            acc
                        })
                })
            })
            .collect();
        from_fn(|i| s_evals.iter().map(|evals| evals[i]).sum::<SC::EF>())
    }

    fn fold_mle_evals(&mut self, round: usize, u_round: SC::EF) {
        let l_skip = self.l_skip;
        self.q_evals = batch_fold_mle_evals(take(&mut self.q_evals), u_round);
        self.eq_r_per_lht = take(&mut self.eq_r_per_lht)
            .into_par_iter()
            .map(|(lht, mat)| (lht, fold_mle_evals(mat, u_round)))
            .collect();
        self.k_rot_r_per_lht = take(&mut self.k_rot_r_per_lht)
            .into_par_iter()
            .map(|(lht, mat)| (lht, fold_mle_evals(mat, u_round)))
            .collect();
        for (tv, eq_ub) in zip(&self.trace_views, &mut self.eq_ub_per_trace) {
            let s = tv.slice;
            let n_lift = s.log_height().saturating_sub(l_skip);
            if round > n_lift {
                // Folding above did nothing, and we update the eq(u[1+n_T..=round],
                // b_{T,j}[..=round-n_T-1]) value
                let b = (s.row_idx >> (l_skip + round - 1)) & 1;
                *eq_ub *= eval_eq_mle(&[u_round], &[SC::F::from_bool(b == 1)]);
            }
        }
    }

    fn into_stacked_openings(self) -> Vec<Vec<SC::EF>> {
        self.q_evals
            .into_iter()
            .map(|q| {
                debug_assert_eq!(q.height(), 1);
                q.values
            })
            .collect()
    }
}

/// `x_int` is the integer representation of point on H_n.
fn rot_prev(x_int: usize, n: usize) -> usize {
    debug_assert!(x_int < (1 << n));
    if x_int == 0 {
        (1 << n) - 1
    } else {
        x_int - 1
    }
}

#[cfg(test)]
mod tests {
    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::{
        config::koala_bear_poseidon2::{
            default_duplex_sponge, DuplexSponge, KoalaBearPoseidon2Config as SC, EF, F,
        },
        poly::Ple,
        prover::{stacked_pcs::stacked_commit, ReferenceDevice},
        test_utils::test_system_params_small,
        verifier::stacked_reduction::{verify_stacked_reduction, StackedReductionError},
    };

    const L_SKIP: usize = 2;
    const N_STACK: usize = 2;

    /// A deterministic but non-trivial extension-field point of length `1 + N_STACK`, sampled from
    /// a sponge so its coordinates carry extension components (and avoid the univariate subgroup).
    fn sample_point(seed: u32) -> Vec<EF> {
        let mut t = default_duplex_sponge();
        FiatShamirTranscript::<SC>::observe(&mut t, F::from_u32(seed));
        (0..=N_STACK)
            .map(|_| FiatShamirTranscript::<SC>::sample_ext(&mut t))
            .collect()
    }

    /// A single full-height trace (`2^(l_skip+n_stack)` rows, `width` columns) whose stacked columns
    /// are exactly the trace columns (stride 1, no lifting) — the cleanest setting to check the
    /// reduction against naive prismalinear evaluation.
    fn full_height_trace(width: usize) -> ColMajorMatrix<F> {
        let height = 1 << (L_SKIP + N_STACK);
        let values = (0..width * height)
            .map(|i| F::from_u32((i as u32) * 3 + 1))
            .collect();
        ColMajorMatrix::new(values, width)
    }

    /// Naive prismalinear evaluation of one column (in evaluation form) at `(point[0], point[1..])`.
    fn naive_col_eval(col: &[F], point: &[EF]) -> EF {
        Ple::from_evaluations(L_SKIP, col).eval_at_point(L_SKIP, point[0], &point[1..])
    }

    fn setup() -> (ReferenceDevice<SC>, SC) {
        let params = test_system_params_small(L_SKIP, N_STACK, 2);
        let config = SC::default_from_params(params);
        (ReferenceDevice::new(config.clone()), config)
    }

    /// Prove the reduction over a freshly committed stacked matrix, then check:
    /// 1. the prover's stacking openings equal the naive PLE evaluation of each stacked column at
    ///    the sumcheck point `u`, and
    /// 2. the verifier accepts the proof against the naive column-opening claims at `r` and recovers
    ///    the same `u`.
    fn prove_and_verify(width: usize) -> (StackingProof<SC>, Vec<EF>) {
        let (device, config) = setup();
        let trace = full_height_trace(width);
        let (_root, data) = stacked_commit(
            config.hasher(),
            L_SKIP,
            N_STACK,
            config.params().log_blowup,
            config.params().k_whir(),
            &[&trace],
        )
        .unwrap();

        let r = sample_point(1);
        let need_rot = vec![vec![false]];

        let mut prover_ts = default_duplex_sponge();
        let (proof, u) = prove_stacked_opening_reduction::<
            SC,
            ReferenceColMajorBackend<SC>,
            ReferenceDevice<SC>,
            DuplexSponge,
            StackedReductionRef<SC>,
        >(
            &device,
            &mut prover_ts,
            N_STACK,
            vec![&data],
            need_rot.clone(),
            &r,
        );
        assert_eq!(u.len(), N_STACK + 1);

        // (1) Naive cross-check: stacking_openings[commit][col] == q_col(u).
        assert_eq!(proof.stacking_openings.len(), 1);
        assert_eq!(proof.stacking_openings[0].len(), width);
        for (col, &opening) in proof.stacking_openings[0].iter().enumerate() {
            let naive = naive_col_eval(data.matrix.column(col), &u);
            assert_eq!(opening, naive, "stacking opening mismatch at column {col}");
        }

        // (2) Round-trip: naive column claims t_j = col_j(r), fed to the verifier, must verify and
        // return the same u. The single full-height trace has one commit, one part (common main).
        let column_openings: Vec<Vec<Vec<EF>>> = vec![vec![(0..width)
            .map(|j| naive_col_eval(trace.column(j), &r))
            .collect()]];
        let omega = F::two_adic_generator(L_SKIP);
        let omega_skip_pows: Vec<F> = omega.powers().take(1 << L_SKIP).collect();

        let mut verifier_ts = default_duplex_sponge();
        let u_verified = verify_stacked_reduction::<SC, DuplexSponge>(
            &mut verifier_ts,
            &proof,
            std::slice::from_ref(&data.layout),
            &need_rot,
            false,
            &[],
            L_SKIP,
            N_STACK,
            &column_openings,
            &r,
            &omega_skip_pows,
        )
        .expect("valid stacked-reduction proof must verify");
        assert_eq!(u_verified, u, "verifier recovered a different point");

        (proof, u)
    }

    #[test]
    fn single_column_reduction_round_trips() {
        prove_and_verify(1);
    }

    /// Multiple columns exercise the λ-batched combination of claims ("多列 claim 正确合一").
    #[test]
    fn multi_column_reduction_round_trips() {
        prove_and_verify(3);
    }

    /// Tampering a stacking opening breaks the final sumcheck consistency check.
    #[test]
    fn tampered_stacking_opening_is_rejected() {
        let (mut proof, _u) = prove_and_verify(2);
        proof.stacking_openings[0][0] += EF::ONE;

        let (_device, config) = setup();
        let trace = full_height_trace(2);
        let (_root, data) = stacked_commit(
            config.hasher(),
            L_SKIP,
            N_STACK,
            config.params().log_blowup,
            config.params().k_whir(),
            &[&trace],
        )
        .unwrap();
        let r = sample_point(1);
        let column_openings: Vec<Vec<Vec<EF>>> = vec![vec![(0..2)
            .map(|j| naive_col_eval(trace.column(j), &r))
            .collect()]];
        let omega = F::two_adic_generator(L_SKIP);
        let omega_skip_pows: Vec<F> = omega.powers().take(1 << L_SKIP).collect();

        let mut verifier_ts = default_duplex_sponge();
        let result = verify_stacked_reduction::<SC, DuplexSponge>(
            &mut verifier_ts,
            &proof,
            std::slice::from_ref(&data.layout),
            &[vec![false]],
            false,
            &[],
            L_SKIP,
            N_STACK,
            &column_openings,
            &r,
            &omega_skip_pows,
        );
        assert!(matches!(
            result,
            Err(StackedReductionError::FinalSumMismatch { .. })
        ));
    }
}
