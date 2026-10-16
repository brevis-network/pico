use std::{
    cmp::max,
    iter::{self, zip},
    mem::take,
};

use itertools::Itertools;
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing, TwoAdicField};
use p3_maybe_rayon::prelude::*;
use p3_util::log2_strict_usize;

use crate::{
    air::symbolic::{symbolic_variable::Entry, SymbolicExpressionNode},
    parizip,
    poly::{
        eval_eq_mle, eval_eq_sharp_uni, eval_eq_uni, evals_eq_hypercubes,
        matrix::{ColMajorMatrix, MatrixDimensions, StridedColMajorMatrixView},
        UnivariatePoly,
    },
    protocol::stacking::StackedLayout,
    prover::{
        error::LogupZerocheckError,
        logup_zerocheck::{evaluator::InteractionEvalPlan, ColMajorEvalHelper},
        sumcheck::{
            batch_fold_mle_evals, batch_fold_ple_evals, fold_ple_evals, sumcheck_round0_deg,
            sumcheck_round_poly_evals, sumcheck_uni_round0_poly,
        },
        DeviceMultiStarkProvingKey, ProverBackend, ProvingContext, ReferenceColMajorBackend,
    },
    StarkProtocolConfig,
};

pub struct LogupZerocheckColMajor<'a, SC: StarkProtocolConfig> {
    pub beta_pows: Vec<SC::EF>,

    pub l_skip: usize,
    pub n_logup: usize,
    pub n_max: usize,

    pub omega_skip: SC::F,
    pub omega_skip_pows: Vec<SC::F>,

    pub interactions_layout: StackedLayout,
    pub(crate) eval_helpers: Vec<ColMajorEvalHelper<'a, SC::F>>,
    /// Max constraint degree across constraints and interactions
    pub constraint_degree: usize,
    pub n_per_trace: Vec<isize>,
    max_num_constraints: usize,

    // Available after GKR:
    pub xi: Vec<SC::EF>,
    lambda_pows: Vec<SC::EF>,
    // T -> segment tree of eq(xi[j..1+n_T]) for j=1..=n_T in _reverse_ layout
    eq_xi_per_trace: Vec<Vec<SC::EF>>,
    eq_3b_per_trace: Vec<Vec<SC::EF>>,
    sels_per_trace_base: Vec<ColMajorMatrix<SC::F>>,
    // After univariate round 0:
    pub mat_evals_per_trace: Vec<Vec<ColMajorMatrix<SC::EF>>>,
    pub sels_per_trace: Vec<ColMajorMatrix<SC::EF>>,
    // Stores \hat{f}(\vec r_n) * r_{n+1} .. r_{round-1} for polys f that are "done" in the batch
    // sumcheck
    pub(crate) zerocheck_tilde_evals: Vec<SC::EF>,
    pub(crate) logup_tilde_evals: Vec<[SC::EF; 2]>,

    // In round `j`, contains `s_{j-1}(r_{j-1})`
    pub(crate) prev_s_eval: SC::EF,
    pub(crate) eq_ns: Vec<SC::EF>,
    pub(crate) eq_sharp_ns: Vec<SC::EF>,
}

impl<'a, SC: StarkProtocolConfig> LogupZerocheckColMajor<'a, SC>
where
    SC::F: TwoAdicField,
    SC::EF: TwoAdicField + ExtensionField<SC::F>,
    ReferenceColMajorBackend<SC>: ProverBackend<
        Val = SC::F,
        Matrix = ColMajorMatrix<SC::F>,
        OtherAirData = InteractionEvalPlan<SC::F>,
    >,
{
    pub fn new(
        pk: &'a DeviceMultiStarkProvingKey<ReferenceColMajorBackend<SC>>,
        ctx: &ProvingContext<ReferenceColMajorBackend<SC>>,
        n_logup: usize,
        interactions_layout: StackedLayout,
        beta_logup: SC::EF,
    ) -> Result<Self, LogupZerocheckError> {
        let l_skip = pk.params.l_skip;
        let omega_skip = SC::F::two_adic_generator(l_skip);
        let omega_skip_pows = omega_skip.powers().take(1 << l_skip).collect_vec();
        let num_airs_present = ctx.per_trace.len();

        let constraint_degree = pk.max_constraint_degree;
        let max_interaction_length = ctx
            .per_trace
            .iter()
            .flat_map(|(air_idx, _)| {
                pk.per_air[*air_idx]
                    .vk
                    .symbolic_constraints
                    .interactions
                    .iter()
                    .map(|i| i.message.len())
            })
            .max()
            .unwrap_or(0);
        let beta_pows = beta_logup
            .powers()
            .take(max_interaction_length + 1)
            .collect_vec();

        let n_per_trace: Vec<isize> = ctx
            .common_main_traces()
            .map(|(_, t)| log2_strict_usize(t.height()) as isize - l_skip as isize)
            .collect_vec();
        let n_max: usize = n_per_trace[0].max(0) as usize;

        let eval_helpers: Vec<ColMajorEvalHelper<SC::F>> = ctx
            .per_trace
            .iter()
            .map(|(air_idx, trace_ctx)| {
                let pk = &pk.per_air[*air_idx];
                let constraints = &pk.vk.symbolic_constraints.constraints;
                let public_values = trace_ctx.public_values.clone();
                let preprocessed_trace: Option<StridedColMajorMatrixView<'_, SC::F>> = pk
                    .preprocessed_data
                    .as_ref()
                    .map(|cd| cd.trace.as_view().into());
                let partitioned_main_trace: Vec<StridedColMajorMatrixView<'_, SC::F>> = trace_ctx
                    .cached_mains
                    .iter()
                    .map(|cd| cd.trace.as_view().into())
                    .chain(iter::once(trace_ctx.common_main.as_view().into()))
                    .collect_vec();
                let constraint_degree = pk.vk.max_constraint_degree;
                // Scan constraints to see if we need `next` row and also check index bounds
                // so we don't need to check them per row.
                let mut rotation = 0;
                for node in &constraints.nodes {
                    if let SymbolicExpressionNode::Variable(var) = node {
                        match var.entry {
                            Entry::Preprocessed { offset } => {
                                rotation = max(rotation, offset);
                                let width = preprocessed_trace.as_ref().unwrap().width();
                                if var.index >= width {
                                    return Err(
                                        LogupZerocheckError::PreprocessedIndexOutOfBounds {
                                            index: var.index,
                                            width,
                                        },
                                    );
                                }
                            }
                            Entry::Main { part_index, offset } => {
                                rotation = max(rotation, offset);
                                let width = partitioned_main_trace[part_index].width();
                                if var.index >= width {
                                    return Err(
                                        LogupZerocheckError::MainPartitionIndexOutOfBounds {
                                            part_index,
                                            col_index: var.index,
                                            width,
                                        },
                                    );
                                }
                            }
                            Entry::Public => {
                                if var.index >= public_values.len() {
                                    return Err(LogupZerocheckError::PublicValueIndexOutOfBounds {
                                        index: var.index,
                                        len: public_values.len(),
                                    });
                                }
                            }
                        }
                    }
                }
                let needs_next = pk.vk.params.need_rot;
                debug_assert_eq!(needs_next, rotation > 0);
                Ok(ColMajorEvalHelper {
                    constraints_dag: &pk.vk.symbolic_constraints.constraints,
                    interactions: &pk.other_data,
                    public_values,
                    preprocessed_trace,
                    needs_next,
                    constraint_degree,
                })
            })
            .collect::<Result<_, _>>()?; // end of preparation / loading of constraints
        let max_num_constraints = pk
            .per_air
            .iter()
            .map(|pk| pk.vk.symbolic_constraints.constraints.constraint_idx.len())
            .max()
            .unwrap_or(0);

        let zerocheck_tilde_evals = vec![SC::EF::ZERO; num_airs_present];
        let logup_tilde_evals = vec![[SC::EF::ZERO; 2]; num_airs_present];
        Ok(Self {
            beta_pows,
            l_skip,
            n_logup,
            n_max,
            omega_skip,
            omega_skip_pows,
            interactions_layout,
            constraint_degree,
            max_num_constraints,
            n_per_trace,
            eval_helpers,
            xi: vec![],
            lambda_pows: vec![],
            sels_per_trace_base: vec![],
            eq_xi_per_trace: vec![],
            eq_3b_per_trace: vec![],
            mat_evals_per_trace: vec![],
            sels_per_trace: vec![],
            zerocheck_tilde_evals,
            logup_tilde_evals,
            prev_s_eval: SC::EF::ZERO,
            eq_ns: Vec::with_capacity(n_max + 1),
            eq_sharp_ns: Vec::with_capacity(n_max + 1),
        })
    }

    /// Returns the `s_0` polynomials in coefficient form. There should be exactly `num_airs_present
    /// \* 3` polynomials, in the order `(s_0)_{p,T}, (s_0)_{q,T}, (s_0)_{zerocheck,T}` per trace
    /// `T`. This is computed _before_ sampling batching randomness `mu` because the result is
    /// used to observe the sum claims `sum_{p,T}, sum_{q,T}`. The `s_0` polynomials could be
    /// returned in either coefficient or evaluation form, but we return them all in coefficient
    /// form for uniformity and debugging since this interpolation is inexpensive.
    pub fn sumcheck_uni_round0_polys(
        &mut self,
        ctx: &ProvingContext<ReferenceColMajorBackend<SC>>,
        lambda: SC::EF,
    ) -> Result<Vec<UnivariatePoly<SC::EF>>, LogupZerocheckError> {
        let n_logup = self.n_logup;
        let l_skip = self.l_skip;
        let xi = &self.xi;
        self.lambda_pows = lambda.powers().take(self.max_num_constraints).collect_vec();

        // For each trace, for each interaction \hat\sigma, the eq(ξ_3,b_{T,\hat\sigma}) term.
        // This is some weight per interaction that does not depend on the row.
        self.eq_3b_per_trace = self
            .eval_helpers
            .par_iter()
            .zip(&self.n_per_trace)
            .enumerate()
            .map(
                |(trace_idx, (helper, &n))| -> Result<Vec<SC::EF>, LogupZerocheckError> {
                    // Everything for logup is done with respect to lifted traces
                    // Note: `n_lift = \tilde{n}`
                    let n_lift = n.max(0) as usize;
                    if helper.interactions.is_empty() {
                        return Ok(vec![]);
                    }
                    let mut b_vec = vec![SC::F::ZERO; n_logup - n_lift];
                    (0..helper.interactions.len())
                        .map(|i| {
                            // This lookup is linear; cache by trace and interaction index if it
                            // becomes visible in profiles.
                            let stacked_idx = self
                                .interactions_layout
                                .get(trace_idx, i)
                                .ok_or(LogupZerocheckError::InteractionsLayoutMissing {
                                    trace_idx,
                                    interaction_idx: i,
                                })?
                                .row_idx;
                            debug_assert!(stacked_idx.trailing_zeros() as usize >= n_lift + l_skip);
                            let mut b_int = stacked_idx >> (l_skip + n_lift);
                            for b in &mut b_vec {
                                *b = SC::F::from_bool(b_int & 1 == 1);
                                b_int >>= 1;
                            }
                            Ok(eval_eq_mle(&xi[l_skip + n_lift..l_skip + n_logup], &b_vec))
                        })
                        .collect()
                },
            )
            .collect::<Result<Vec<_>, _>>()?;

        // This can be shared by unique n values: n -> eq_n(xi, -).
        // NOTE: this is evaluations of `x -> eq_{H_{\tilde n}}(x, \xi[l_skip..l_skip + \tilde n])`
        // on hypercube `H_{\tilde n}`. We store the univariate component eq_D separately as
        // an optimization.
        self.eq_xi_per_trace = self
            .n_per_trace
            .par_iter()
            .map(|&n| {
                let n_lift = n.max(0) as usize;
                // The eq_xi and eq_sharp computations can likely share the hyperprism
                // eq(xi, -) evaluations used by zerocheck.
                evals_eq_hypercubes(n_lift, xi[l_skip..l_skip + n_lift].iter().rev())
            })
            .collect();

        // For each trace, create selectors as a 3-column matrix of _the lifts of_ [is_first,
        // is_transition, is_last]
        //
        // These selectors can be computed from their formulas during interpolation instead of
        // being materialized here.
        self.sels_per_trace_base = self
            .n_per_trace
            .iter()
            .map(|&n| {
                let log_height = l_skip.checked_add_signed(n).unwrap();
                let height = 1 << log_height;
                let lifted_height = height.max(1 << l_skip);
                let mut mat = SC::F::zero_vec(3 * lifted_height);
                mat[lifted_height..2 * lifted_height].fill(SC::F::ONE);
                for i in (0..lifted_height).step_by(height) {
                    mat[i] = SC::F::ONE; // is_first
                    mat[lifted_height + i + height - 1] = SC::F::ZERO; // is_transition
                    mat[2 * lifted_height + i + height - 1] = SC::F::ONE; // is_last
                }
                ColMajorMatrix::new(mat, 3)
            })
            .collect_vec();

        let sp_0_zerochecks = self
            .eval_helpers
            .par_iter()
            .enumerate()
            .map(|(trace_idx, helper)| {
                let trace_ctx = &ctx.per_trace[trace_idx].1;
                let n_lift = log2_strict_usize(trace_ctx.height()).saturating_sub(l_skip);
                let mats = &helper.view_mats(trace_ctx);
                let eq_xi = &self.eq_xi_per_trace[trace_idx][(1 << n_lift) - 1..(2 << n_lift) - 1];
                let sels = self.sels_per_trace_base[trace_idx].as_view();
                let mut parts = vec![(sels.into(), false)];
                parts.extend_from_slice(mats);
                // s'_0 has degree dependent on this AIR's constraint degree
                // s'_0(Z) is a univariate polynomial which vanishes on D (zerocheck). Hence q(Z) =
                // s'_0(Z) / Z_D(Z) = s'_0(Z) / (Z^{2^l_skip} - 1) is a polynomial of degree d *
                // (2^l_skip - 1) - 2^l_skip = (d - 1) * 2^l_skip - d We can obtain
                // q(Z) by interpolating evaluations on (d - 1) * 2^l_skip points. For computation
                // efficiency, we choose these to be (d - 1) cosets of D. To avoid divide by zero,
                // we avoid the coset equal to the subgroup D itself.
                let constraint_deg = helper.constraint_degree as usize;
                if constraint_deg == 0 {
                    return UnivariatePoly(vec![]);
                }
                let num_cosets = constraint_deg - 1;
                let [q] = sumcheck_uni_round0_poly(
                    l_skip,
                    n_lift,
                    num_cosets,
                    &parts,
                    |z, x, row_parts| {
                        let eq = eq_xi[x];
                        let constraint_eval = helper.acc_constraints(row_parts, &self.lambda_pows);
                        let zerofier = z.exp_power_of_2(l_skip) - SC::F::ONE;
                        [eq * constraint_eval * zerofier.inverse()]
                    },
                );
                // sp_0 = (Z^{2^l_skip} - 1) * q
                let sp_0_deg = sumcheck_round0_deg(l_skip, constraint_deg);
                let coeffs = (0..=sp_0_deg)
                    .map(|i| {
                        let mut c = -*q.coeffs().get(i).unwrap_or(&SC::EF::ZERO);
                        if i >= 1 << l_skip {
                            c += q.coeffs()[i - (1 << l_skip)];
                        }
                        c
                    })
                    .collect_vec();
                debug_assert_eq!(
                    coeffs.iter().step_by(1 << l_skip).copied().sum::<SC::EF>(),
                    SC::EF::ZERO,
                    "Zerocheck sum is not zero for air_id: {}",
                    ctx.per_trace[trace_idx].0
                );
                UnivariatePoly(coeffs)
            })
            .collect::<Vec<_>>();
        // Reminder: sum claims for zerocheck are zero, per AIR

        // We interpolate each logup round 0 sumcheck poly because we need to use it to compute
        // sum_{\hat{p}, T, I}, sum_{\hat{q}, T, I} per trace.
        let sp_0_logups = self
            .eval_helpers
            .par_iter()
            .enumerate()
            .flat_map(|(trace_idx, helper)| {
                if helper.interactions.is_empty() {
                    return [(); 2].map(|_| UnivariatePoly::new(vec![]));
                }
                let trace_ctx = &ctx.per_trace[trace_idx].1;
                let log_height = log2_strict_usize(trace_ctx.height());
                let n_lift = log_height.saturating_sub(l_skip);
                let mats = &helper.view_mats(trace_ctx);
                let eq_xi = &self.eq_xi_per_trace[trace_idx][(1 << n_lift) - 1..(2 << n_lift) - 1];
                let eq_3bs = &self.eq_3b_per_trace[trace_idx];
                let sels = self.sels_per_trace_base[trace_idx].as_view();
                let mut parts = vec![(sels.into(), false)];
                parts.extend_from_slice(mats);
                let norm_factor_denom = 1 << l_skip.saturating_sub(log_height);
                let norm_factor = SC::F::from_usize(norm_factor_denom).inverse();

                // degree is constraint_degree + 1 due to eq term
                let [mut numer, denom] = sumcheck_uni_round0_poly(
                    l_skip,
                    n_lift,
                    helper.constraint_degree as usize,
                    &parts,
                    |_z, x, row_parts| {
                        let eq = eq_xi[x];
                        let [numer, denom] =
                            helper.acc_interactions(row_parts, &self.beta_pows, eq_3bs);
                        [eq * numer, eq * denom]
                    },
                );
                for p in numer.coeffs_mut() {
                    *p *= norm_factor;
                }
                [numer, denom]
            })
            .collect::<Vec<_>>();

        Ok(sp_0_logups.into_iter().chain(sp_0_zerochecks).collect())
    }

    /// After univariate sumcheck round 0, fold prismalinear evaluations using randomness `r_0`.
    /// Folding _could_ directly mutate inplace the trace matrices in `ctx` as they will not be
    /// needed after this.
    pub fn fold_ple_evals(
        &mut self,
        ctx: &ProvingContext<ReferenceColMajorBackend<SC>>,
        r_0: SC::EF,
    ) {
        let l_skip = self.l_skip;
        // "Fold" all PLE evaluations by interpolating and evaluating at `r_0`.
        // NOTE: after this folding, \hat{T} and \hat{T_{rot}} will be treated as completely
        // distinct matrices.
        self.mat_evals_per_trace = self
            .eval_helpers
            .par_iter()
            .zip(ctx.per_trace.par_iter())
            .map(|(helper, (_, trace_ctx))| {
                let mats = helper.view_mats(trace_ctx);
                mats.into_par_iter()
                    .map(|(mat, is_rot)| fold_ple_evals(l_skip, mat, is_rot, r_0))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        self.sels_per_trace =
            batch_fold_ple_evals(l_skip, take(&mut self.sels_per_trace_base), false, r_0);
        let eq_r0 = eval_eq_uni(l_skip, self.xi[0], r_0);
        let eq_sharp_r0 = eval_eq_sharp_uni(&self.omega_skip_pows, &self.xi[..l_skip], r_0);
        self.eq_ns.push(eq_r0);
        self.eq_sharp_ns.push(eq_sharp_r0);
        self.eq_xi_per_trace.iter_mut().for_each(|eq| {
            // trim the back (which corresponds to r_{j-1}) because we don't need it anymore
            if eq.len() > 1 {
                eq.truncate(eq.len() / 2);
            }
        });
    }

    /// Returns length `3 * num_airs_present` polynomials, each polynomial either evaluated at
    /// `1,...,deg(s')` or at `1` if a linear term (terms in front-loaded sumcheck that have reached
    /// exhaustion)
    pub fn sumcheck_polys_eval(
        &mut self,
        round: usize,
        r_prev: SC::EF,
    ) -> Result<Vec<Vec<SC::EF>>, LogupZerocheckError> {
        // sp = s'
        let sp_deg = self.constraint_degree;
        let eq_r_acc = *self
            .eq_ns
            .last()
            .ok_or(LogupZerocheckError::EqNsEmpty { round })?;
        let eq_sharp_r_acc = *self
            .eq_sharp_ns
            .last()
            .ok_or(LogupZerocheckError::EqSharpNsEmpty { round })?;
        let sp_zerocheck_evals: Vec<Vec<SC::EF>> = parizip!(
            &self.eval_helpers,
            &mut self.zerocheck_tilde_evals,
            &self.n_per_trace,
            &self.mat_evals_per_trace,
            &self.sels_per_trace,
            &self.eq_xi_per_trace
        )
        .map(|(helper, tilde_eval, &n, mats, sels, eq_xi_tree)| {
            let n_lift = n.max(0) as usize;
            if round > n_lift {
                if round == n_lift + 1 {
                    // Evaluate \hat{f}(\vec r_n)
                    let parts = iter::once(sels)
                        .chain(mats)
                        .map(|mat| mat.columns().map(|c| c[0]).collect_vec())
                        .collect_vec();
                    // eq(xi, \vect r_{round-1})
                    *tilde_eval = eq_r_acc * helper.acc_constraints(&parts, &self.lambda_pows);
                } else {
                    *tilde_eval *= r_prev;
                };
                vec![*tilde_eval]
            } else {
                let log_num_y = n_lift - round;
                let num_y = 1 << log_num_y;
                let eq_xi = &eq_xi_tree[num_y - 1..];
                let parts = iter::once(sels)
                    .chain(mats)
                    .map(|m| m.as_view())
                    .collect_vec();
                let [s] =
                    sumcheck_round_poly_evals(log_num_y + 1, sp_deg, &parts, |_x, y, row_parts| {
                        let eq = eq_xi[y];
                        let constraint_eval = helper.acc_constraints(row_parts, &self.lambda_pows);
                        [eq * constraint_eval]
                    });
                s
            }
        })
        .collect();

        let sp_logup_evals: Vec<Vec<SC::EF>> = parizip!(
            &self.eval_helpers,
            &mut self.logup_tilde_evals,
            &self.n_per_trace,
            &self.mat_evals_per_trace,
            &self.sels_per_trace,
            &self.eq_xi_per_trace,
            &self.eq_3b_per_trace
        )
        .flat_map(|(helper, tilde_eval, &n, mats, sels, eq_xi_tree, eq_3bs)| {
            if helper.interactions.is_empty() {
                return [vec![SC::EF::ZERO; sp_deg], vec![SC::EF::ZERO; sp_deg]];
            }
            let n_lift = n.max(0) as usize;
            let norm_factor_denom = 1 << (-n).max(0);
            let norm_factor = SC::F::from_usize(norm_factor_denom).inverse();
            if round > n_lift {
                if round == n_lift + 1 {
                    // Evaluate \hat{f}(\vec r_n)
                    let parts = iter::once(sels)
                        .chain(mats)
                        .map(|mat| mat.columns().map(|c| c[0]).collect_vec())
                        .collect_vec();
                    *tilde_eval = helper
                        .acc_interactions(&parts, &self.beta_pows, eq_3bs)
                        .map(|x| eq_sharp_r_acc * x);
                    tilde_eval[0] *= norm_factor;
                } else {
                    for x in tilde_eval.iter_mut() {
                        *x *= r_prev;
                    }
                };
                tilde_eval.map(|tilde_eval| vec![tilde_eval])
            } else {
                let parts = iter::once(sels)
                    .chain(mats)
                    .map(|m| m.as_view())
                    .collect_vec();
                let log_num_y = n_lift - round;
                let num_y = 1 << log_num_y;
                let eq_xi = &eq_xi_tree[num_y - 1..];
                let [mut numer, denom] =
                    sumcheck_round_poly_evals(log_num_y + 1, sp_deg, &parts, |_x, y, row_parts| {
                        let eq = eq_xi[y];
                        helper
                            .acc_interactions(row_parts, &self.beta_pows, eq_3bs)
                            .map(|eval| eq * eval)
                    });
                for p in &mut numer {
                    *p *= norm_factor;
                }
                [numer, denom]
            }
        })
        .collect();

        Ok(sp_logup_evals
            .into_iter()
            .chain(sp_zerocheck_evals)
            .collect())
    }

    pub fn fold_mle_evals(&mut self, round: usize, r_round: SC::EF) {
        self.mat_evals_per_trace = take(&mut self.mat_evals_per_trace)
            .into_iter()
            .map(|mats| batch_fold_mle_evals(mats, r_round))
            .collect_vec();
        self.sels_per_trace = batch_fold_mle_evals(take(&mut self.sels_per_trace), r_round);
        self.eq_xi_per_trace.par_iter_mut().for_each(|eq| {
            // trim the back (which corresponds to r_{j-1}) because we don't need it anymore
            if eq.len() > 1 {
                eq.truncate(eq.len() / 2);
            }
        });
        let xi = self.xi[self.l_skip + round - 1];
        let eq_r = eval_eq_mle(&[xi], &[r_round]);
        self.eq_ns.push(self.eq_ns[round - 1] * eq_r);
        self.eq_sharp_ns.push(self.eq_sharp_ns[round - 1] * eq_r);

        #[allow(unused_variables)]
        #[cfg(debug_assertions)]
        if tracing::enabled!(tracing::Level::DEBUG) && round == self.n_max {
            use itertools::izip;

            for (trace_idx, (helper, &n, mats, sels, eq_xi)) in izip!(
                &self.eval_helpers,
                &self.n_per_trace,
                &self.mat_evals_per_trace,
                &self.sels_per_trace,
                &self.eq_xi_per_trace
            )
            .enumerate()
            {
                let parts = iter::once(sels)
                    .chain(mats)
                    .map(|mat| mat.columns().map(|c| c[0]).collect_vec())
                    .collect_vec();
                let expr = helper.acc_constraints(&parts, &self.lambda_pows);
                tracing::debug!(%trace_idx, %expr, "constraints_eval");
            }

            for (trace_idx, (helper, &n, mats, sels, eq_3bs)) in izip!(
                &self.eval_helpers,
                &self.n_per_trace,
                &self.mat_evals_per_trace,
                &self.sels_per_trace,
                &self.eq_3b_per_trace
            )
            .enumerate()
            {
                if helper.interactions.is_empty() {
                    continue;
                }
                let parts = iter::once(sels)
                    .chain(mats)
                    .map(|mat| mat.columns().map(|c| c[0]).collect_vec())
                    .collect_vec();
                let [num, denom] = helper.acc_interactions(&parts, &self.beta_pows, eq_3bs);

                tracing::debug!(%trace_idx, %num, %denom, "interactions_eval");
            }
        }
    }

    /// Drains the accumulated per-trace matrix evaluations into the column openings.
    /// Takes `&mut self` (not `self`) because the caller still needs `eval_helpers` afterward.
    pub fn extract_column_openings(
        &mut self,
    ) -> Result<Vec<Vec<Vec<SC::EF>>>, LogupZerocheckError> {
        let num_airs_present = self.mat_evals_per_trace.len();
        let mut column_openings = Vec::with_capacity(num_airs_present);
        // At the end, we've folded all MLEs so they only have one row equal to evaluation at `\vec
        // r`.
        for (helper, mut mat_evals) in self
            .eval_helpers
            .iter()
            .zip(take(&mut self.mat_evals_per_trace))
        {
            // For column openings, we pop common_main (and common_main_rot when present) and put it
            // at the front.
            let openings_of_air: Vec<Vec<SC::EF>> = if helper.needs_next {
                let common_main_rot = mat_evals
                    .pop()
                    .ok_or(LogupZerocheckError::MatEvalsPopNone)?;
                let common_main = mat_evals
                    .pop()
                    .ok_or(LogupZerocheckError::MatEvalsPopNone)?;
                iter::once(&[common_main, common_main_rot])
                    .chain(mat_evals.as_chunks::<2>().0)
                    .map(|pair| {
                        zip(pair[0].columns(), pair[1].columns())
                            .flat_map(|(claim, claim_rot)| {
                                debug_assert_eq!(claim.len(), 1);
                                debug_assert_eq!(claim_rot.len(), 1);
                                [claim[0], claim_rot[0]]
                            })
                            .collect_vec()
                    })
                    .collect_vec()
            } else {
                let common_main = mat_evals
                    .pop()
                    .ok_or(LogupZerocheckError::MatEvalsPopNone)?;
                iter::once(common_main)
                    .chain(mat_evals)
                    .map(|mat| {
                        mat.columns()
                            .map(|claim| {
                                debug_assert_eq!(claim.len(), 1);
                                claim[0]
                            })
                            .collect_vec()
                    })
                    .collect_vec()
            };
            column_openings.push(openings_of_air);
        }
        Ok(column_openings)
    }
}
