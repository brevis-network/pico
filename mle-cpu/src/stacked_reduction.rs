//! Stacked opening reduction for the CPU backend ([CpuBackend]).
//!
//! A standalone, row-major-optimized stacked-reduction prover over [`CpuStackedPcsData`]. Despite
//! the shared protocol it does *not* delegate to the reference prover
//! ([`StackedReductionRef`](pico_mle_core::prover::stacked_reduction::StackedReductionRef)) — the two
//! are independent implementations of the same reduction.

use std::{collections::HashMap, iter::zip, mem::take};

use itertools::Itertools;
use p3_field::{
    batch_multiplicative_inverse, ExtensionField, Field, PrimeCharacteristicRing, TwoAdicField,
};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
use pico_mle_core::{
    poly::{
        eval_eq_mle, eval_eq_uni, eval_eq_uni_at_one, eval_in_uni, evals_eq_hypercube_par,
        matrix::{ColMajorMatrix, ColMajorMatrixView, MatrixDimensions},
        ntt::TwiddleDft,
        UnivariatePoly,
    },
    protocol::stacking::{lambda_slots, ColLambda, StackedSlice},
    prover::{
        stacked_reduction::StackedReductionProver,
        sumcheck::{batch_fold_mle_evals, sumcheck_round0_deg, sumcheck_round_poly_evals},
        ProverBackend,
    },
    StarkProtocolConfig,
};

use crate::{backend::CpuBackend, device::CpuDevice, pcs_data::CpuStackedPcsData};

/// Optimized PLE fold: precompute barycentric weights once, then evaluate each element
/// as an inline dot product. Eliminates the 5.5M per-element Vec allocations in the
/// reference `fold_ple_evals` which calls `interpolate_coset_with_precomputation` per element.
fn fold_ple_evals_cpu<F, EF>(l_skip: usize, mat: &ColMajorMatrix<F>, r: EF) -> ColMajorMatrix<EF>
where
    F: TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
{
    let height = mat.height();
    let n = 1usize << l_skip;
    let lifted_height = height.max(n);
    let width = mat.width();
    let new_height = lifted_height >> l_skip;

    // Precompute barycentric interpolation weights (shared across all elements):
    // col_scale[i] = omega^i / (r - omega^i)
    let omega = F::two_adic_generator(l_skip);
    let omega_pows: Vec<F> = omega.powers().take(n).collect();
    let denoms: Vec<EF> = omega_pows.iter().map(|&w| r - EF::from(w)).collect();
    let inv_denoms = batch_multiplicative_inverse(&denoms);
    let col_scale: Vec<EF> = omega_pows
        .iter()
        .zip(&inv_denoms)
        .map(|(&w, &inv_d)| inv_d * w)
        .collect();

    // scaling_factor = (r^N - 1) / N  where N = 2^l_skip, shift = 1
    let r_pow_n = r.exp_power_of_2(l_skip);
    let vanishing = r_pow_n - EF::ONE;
    let mut n_ef = EF::ONE;
    for _ in 0..l_skip {
        n_ef += n_ef;
    }
    let scaling_factor = vanishing * n_ef.inverse();

    // For each (column j, hypercube point x): dot product of 16 base field evals with col_scale,
    // then multiply by scaling_factor. Zero allocations per element.
    let values: Vec<EF> = mat
        .values
        .par_chunks_exact(height)
        .flat_map(|col| {
            (0..new_height)
                .into_par_iter()
                .map(|x| {
                    let base = x << l_skip;
                    let mut sum = EF::ZERO;
                    for z in 0..n {
                        // col-major: col[base + z] is contiguous (cache-friendly)
                        let f_z = col[(base + z) % height];
                        sum += col_scale[z] * f_z;
                    }
                    sum * scaling_factor
                })
                .collect::<Vec<_>>()
        })
        .collect();
    ColMajorMatrix::new(values, width)
}

pub struct StackedReductionCpu<'a, SC: StarkProtocolConfig> {
    l_skip: usize,
    omega_skip: SC::F,

    r_0: SC::EF,
    lambda_pows: Vec<SC::EF>,
    eq_const: SC::EF,

    stacked_per_commit: Vec<&'a CpuStackedPcsData<SC::F, SC::Digest>>,
    trace_views: Vec<TraceViewMeta>,
    ht_diff_idxs: Vec<usize>,

    eq_r_per_lht: HashMap<usize, Vec<SC::EF>>,

    // After round 0:
    k_rot_r_per_lht: HashMap<usize, Vec<SC::EF>>,
    q_evals: Vec<ColMajorMatrix<SC::EF>>,
    eq_ub_per_trace: Vec<SC::EF>,
}

struct TraceViewMeta {
    com_idx: usize,
    slice: StackedSlice,
    /// λ-batching slots (`eq` and optional `rot`) for this column, taken from the shared
    /// [`lambda_slots`] SSOT so the CPU prover, the reference prover, and the verifier all assign
    /// the same exponents and cannot drift.
    lambda: ColLambda,
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

fn fold_eval_map<EF>(
    evals_per_lht: HashMap<usize, Vec<EF>>,
    one_minus_r: EF,
    r: EF,
) -> HashMap<usize, Vec<EF>>
where
    EF: Field + Send,
{
    evals_per_lht
        .into_par_iter()
        .map(|(lht, v)| {
            if v.len() <= 1 {
                return (lht, v);
            }
            let folded: Vec<EF> = v
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| pair[0] * one_minus_r + pair[1] * r)
                .collect();
            (lht, folded)
        })
        .collect()
}

impl<'a, SC: StarkProtocolConfig> StackedReductionProver<'a, CpuBackend<SC>, CpuDevice<SC>>
    for StackedReductionCpu<'a, SC>
where
    SC::F: TwoAdicField,
    SC::EF: TwoAdicField + ExtensionField<SC::F>,
    CpuBackend<SC>: ProverBackend<
        Val = SC::F,
        Challenge = SC::EF,
        PcsData = CpuStackedPcsData<SC::F, SC::Digest>,
    >,
{
    fn new(
        device: &CpuDevice<SC>,
        stacked_per_commit: Vec<&'a CpuStackedPcsData<SC::F, SC::Digest>>,
        need_rot_per_commit: Vec<Vec<bool>>,
        r: &[SC::EF],
        lambda: SC::EF,
    ) -> Self {
        let l_skip = device.params().l_skip;
        let omega_skip = SC::F::two_adic_generator(l_skip);

        // Shared SSOT: assign each column its (eq, rot) λ exponents. The reference prover
        // (`StackedReductionRef::new`) and the verifier (`verify_stacked_reduction`) walk the same
        // layouts with the same helper, so all three assign identical exponents.
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
        let mut eq_r_per_lht: HashMap<usize, Vec<SC::EF>> = HashMap::new();
        let mut last_height = 0;
        for (i, tv) in trace_views.iter().enumerate() {
            let n_lift = tv.slice.log_height().saturating_sub(l_skip);
            if i == 0 || tv.slice.log_height() != last_height {
                ht_diff_idxs.push(i);
                last_height = tv.slice.log_height();
            }
            eq_r_per_lht
                .entry(tv.slice.log_height())
                .or_insert_with(|| evals_eq_hypercube_par(&r[1..1 + n_lift]));
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
        let _span = tracing::info_span!("stacked_round0").entered();
        let l_skip = self.l_skip;
        let omega_skip = self.omega_skip;
        let r_0 = self.r_0;
        let eq_const = self.eq_const;
        let n_skip = 1usize << l_skip;
        let d = 2usize;
        let d_n = d << l_skip;
        let s_0_deg = sumcheck_round0_deg(l_skip, d);
        let g = SC::F::GENERATOR;
        let coset_shifts: Vec<SC::F> = g.powers().skip(1).take(d).collect_vec();
        let twiddles = TwiddleDft::new(l_skip);

        // Extract all self-field references before parallel iteration to satisfy borrow checker
        let ht_diff_idxs = &self.ht_diff_idxs;
        let trace_views = &self.trace_views;
        let stacked_per_commit = &self.stacked_per_commit;
        let eq_r_per_lht = &self.eq_r_per_lht;
        let lambda_pows = &self.lambda_pows;

        let s_0_polys: Vec<[UnivariatePoly<SC::EF>; 2]> = ht_diff_idxs
            .par_windows(2)
            .map(|window| {
                let t_window = &trace_views[window[0]..window[1]];
                let log_height = t_window[0].slice.log_height();
                let n = log_height as isize - l_skip as isize;
                let n_lift = n.max(0) as usize;
                let eq_rs = eq_r_per_lht.get(&log_height).unwrap().as_slice();
                debug_assert_eq!(eq_rs.len(), 1 << n_lift);

                // Collect column data references (each trace view is a single column)
                let q_cols: Vec<&[SC::F]> = t_window
                    .iter()
                    .map(|tv| {
                        debug_assert_eq!(tv.slice.log_height(), log_height);
                        let q = &stacked_per_commit[tv.com_idx].matrix;
                        let s = tv.slice;
                        &q.column(s.col_idx)[s.row_idx..s.row_idx + s.len(l_skip)]
                    })
                    .collect();

                // Precompute z-dependent scalars (d_n values, independent of x)
                let omega_pows: Vec<SC::F> = omega_skip.powers().take(n_skip).collect();
                let (l, omega_l, r_uni) = if n.is_negative() {
                    (
                        l_skip.wrapping_add_signed(n),
                        omega_skip.exp_power_of_2(-n as usize),
                        r_0.exp_power_of_2(-n as usize),
                    )
                } else {
                    (l_skip, omega_skip, r_0)
                };
                // pre_z[rm_idx] = (pre_eq, pre_rot, pre_1) where rm_idx = z_idx * d + c_idx
                let mut pre_z = Vec::with_capacity(d_n);
                for &omega_z in &omega_pows {
                    for &shift in &coset_shifts {
                        let z_val: SC::F = shift * omega_z;
                        let ind = eval_in_uni(l_skip, n, z_val);
                        let eq_r0: SC::EF = eval_eq_uni(l, z_val.into(), r_uni);
                        let eq_r0_rot: SC::EF = eval_eq_uni(l, z_val.into(), r_uni * omega_l);
                        let eq_1: SC::F = eval_eq_uni_at_one(l_skip, z_val);
                        pre_z.push((eq_r0 * ind, eq_r0_rot * ind, eq_const * eq_1 * ind));
                    }
                }

                // Pre-extract lambda weights per trace
                let lambda_eqs: Vec<SC::EF> = t_window
                    .iter()
                    .map(|tv| lambda_pows[tv.lambda.eq_exp])
                    .collect();
                let lambda_rots: Vec<Option<SC::EF>> = t_window
                    .iter()
                    .map(|tv| tv.lambda.rot_exp.map(|idx| lambda_pows[idx]))
                    .collect();
                let num_traces = q_cols.len();

                // Parallel fold-reduce over x-points in H_{n_lift}.
                // Each thread reuses its own DFT and weighted-sum buffers.
                type Acc<F, EF> = (Vec<[EF; 2]>, Vec<F>, Vec<F>, Vec<EF>, Vec<EF>);
                let (evals, _, _, _, _): Acc<SC::F, SC::EF> =
                    (0..1usize << n_lift).into_par_iter().par_fold_reduce(
                        || -> Acc<SC::F, SC::EF> {
                            (
                                vec![[SC::EF::ZERO; 2]; d_n],
                                vec![SC::F::ZERO; n_skip],
                                vec![SC::F::ZERO; n_skip],
                                vec![SC::EF::ZERO; d_n],
                                vec![SC::EF::ZERO; d_n],
                            )
                        },
                        |(mut result, mut coeffs, mut coset, mut w_eq, mut w_rot), x| {
                            // Zero out per-x weighted sums
                            for v in w_eq.iter_mut() {
                                *v = SC::EF::ZERO;
                            }
                            for v in w_rot.iter_mut() {
                                *v = SC::EF::ZERO;
                            }

                            // Phase 1: For each trace, iDFT + coset DFTs, accumulate weighted sums
                            for t in 0..num_traces {
                                let col = q_cols[t];
                                let height = col.len();

                                // Read n_skip evaluations from column at block x
                                for z in 0..n_skip {
                                    coeffs[z] = col[((x << l_skip) + z) % height];
                                }
                                twiddles.idft_inplace(&mut coeffs);

                                let le = lambda_eqs[t];
                                let lr = lambda_rots[t];
                                for (c_idx, &shift) in coset_shifts.iter().enumerate() {
                                    coset.copy_from_slice(&coeffs);
                                    twiddles.coset_dft_inplace(&mut coset, shift);

                                    for (z_idx, &q) in coset.iter().enumerate() {
                                        let rm_idx = z_idx * d + c_idx;
                                        w_eq[rm_idx] += le * q;
                                        if let Some(lr) = lr {
                                            w_rot[rm_idx] += lr * q;
                                        }
                                    }
                                }
                            }

                            // Phase 2: Multiply weighted sums by precomputed z-scalars and
                            // x-dependent eq evaluations
                            let eq_cube = eq_rs[x];
                            let k_rot_cube = eq_rs[rot_prev(x, n_lift)];
                            let delta = k_rot_cube - eq_cube;

                            for rm_idx in 0..d_n {
                                let (pe, pr, p1) = pre_z[rm_idx];
                                result[rm_idx][0] += (pe * eq_cube) * w_eq[rm_idx];
                                result[rm_idx][1] += (pr * eq_cube + p1 * delta) * w_rot[rm_idx];
                            }
                            (result, coeffs, coset, w_eq, w_rot)
                        },
                        |(mut a_result, a1, a2, a3, a4), (b_result, _, _, _, _)| {
                            for (ai, bi) in a_result.iter_mut().zip(b_result.iter()) {
                                ai[0] += bi[0];
                                ai[1] += bi[1];
                            }
                            (a_result, a1, a2, a3, a4)
                        },
                    );

                // Convert accumulated coset evaluations to polynomial coefficients
                std::array::from_fn(|wd| {
                    let values: Vec<SC::EF> = evals.iter().map(|v| v[wd]).collect();
                    UnivariatePoly::from_geometric_cosets_evals_idft(
                        RowMajorMatrix::new(values, d),
                        g,
                        g,
                    )
                })
            })
            .collect();

        let s_0_coeffs = (0..=s_0_deg)
            .map(|i| {
                s_0_polys
                    .iter()
                    .flat_map(|ps| ps.iter())
                    .map(|p| p.coeffs().get(i).copied().unwrap_or(SC::EF::ZERO))
                    .sum::<SC::EF>()
            })
            .collect_vec();
        UnivariatePoly::new(s_0_coeffs)
    }

    fn fold_ple_evals(&mut self, u_0: SC::EF) {
        let _span = tracing::info_span!("stacked_fold_ple").entered();
        let l_skip = self.l_skip;
        let r_0 = self.r_0;
        let omega_skip = self.omega_skip;
        self.q_evals = self
            .stacked_per_commit
            .iter()
            .map(|d| fold_ple_evals_cpu(l_skip, &d.matrix, u_0))
            .collect_vec();
        let eq_uni_u0r0 = eval_eq_uni(l_skip, u_0, r_0);
        let eq_uni_u0r0_rot = eval_eq_uni(l_skip, u_0, r_0 * omega_skip);
        let eq_uni_u01 = eval_eq_uni_at_one(l_skip, u_0);
        self.k_rot_r_per_lht = self
            .eq_r_per_lht
            .par_iter_mut()
            .map(|(&log_height, eq_vec)| {
                let n = log_height as isize - l_skip as isize;
                let n_lift = n.max(0) as usize;
                debug_assert_eq!(eq_vec.len(), 1 << n_lift);
                let ind = eval_in_uni(l_skip, n, u_0);
                let (eq_uni, eq_uni_rot) = if n.is_negative() {
                    let omega = omega_skip.exp_power_of_2(-n as usize);
                    let r = r_0.exp_power_of_2(-n as usize);
                    let l = l_skip.wrapping_add_signed(n);
                    (eval_eq_uni(l, u_0, r), eval_eq_uni(l, u_0, r * omega))
                } else {
                    (eq_uni_u0r0, eq_uni_u0r0_rot)
                };
                let k_rot_evals: Vec<_> = (0..1 << n_lift)
                    .into_par_iter()
                    .map(|x| {
                        let eq_cube = eq_vec[x];
                        let k_rot_cube = eq_vec[rot_prev(x, n_lift)];
                        ind * (eq_uni_rot * eq_cube
                            + self.eq_const * eq_uni_u01 * (k_rot_cube - eq_cube))
                    })
                    .collect();
                eq_vec.par_iter_mut().for_each(|v| {
                    *v *= ind * eq_uni;
                });
                (log_height, k_rot_evals)
            })
            .collect();
    }

    fn batch_sumcheck_poly_eval(&mut self, round: usize, _u_prev: SC::EF) -> [SC::EF; 2] {
        let _span = tracing::info_span!("stacked_round_eval").entered();
        let l_skip = self.l_skip;
        let s_deg = 2;
        let s_evals: Vec<_> = self
            .ht_diff_idxs
            .par_windows(2)
            .flat_map(|window| {
                let t_views = &self.trace_views[window[0]..window[1]];
                let log_height = t_views[0].slice.log_height();
                let n_lift = log_height.saturating_sub(l_skip);
                let hypercube_dim = n_lift.saturating_sub(round);
                let eq_rs = self.eq_r_per_lht.get(&log_height).unwrap().as_slice();
                let k_rot_rs = self.k_rot_r_per_lht.get(&log_height).unwrap().as_slice();
                debug_assert_eq!(eq_rs.len(), 1 << n_lift.saturating_sub(round - 1));
                debug_assert_eq!(k_rot_rs.len(), 1 << n_lift.saturating_sub(round - 1));
                let t_cols = t_views
                    .iter()
                    .map(|tv| {
                        debug_assert_eq!(tv.slice.log_height(), log_height);
                        let q = &self.q_evals[tv.com_idx];
                        let s = tv.slice;
                        let row_start = if round <= n_lift {
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
                                let b = (tv.slice.row_idx >> (l_skip + round - 1)) & 1;
                                eq_ub *= eval_eq_mle(&[x], &[SC::F::from_bool(b == 1)]);
                                debug_assert_eq!(y, 0);
                                (eq_rs[0] * eq_ub, k_rot_rs[0] * eq_ub)
                            } else {
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
        std::array::from_fn(|i| s_evals.iter().map(|evals| evals[i]).sum::<SC::EF>())
    }

    fn fold_mle_evals(&mut self, round: usize, u_round: SC::EF) {
        let _span = tracing::info_span!("stacked_fold_mle").entered();
        let l_skip = self.l_skip;
        self.q_evals = batch_fold_mle_evals(take(&mut self.q_evals), u_round);
        let one_minus_r = SC::EF::ONE - u_round;
        self.eq_r_per_lht = fold_eval_map(take(&mut self.eq_r_per_lht), one_minus_r, u_round);
        self.k_rot_r_per_lht = fold_eval_map(take(&mut self.k_rot_r_per_lht), one_minus_r, u_round);
        for (tv, eq_ub) in zip(&self.trace_views, &mut self.eq_ub_per_trace) {
            let s = tv.slice;
            let n_lift = s.log_height().saturating_sub(l_skip);
            if round > n_lift {
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

#[cfg(test)]
mod tests {
    use pico_mle_core::{
        config::koala_bear_poseidon2::{
            default_duplex_sponge, DuplexSponge, KoalaBearPoseidon2Config as SC, EF, F,
        },
        prover::{
            stacked_pcs::stacked_commit,
            stacked_reduction::{prove_stacked_opening_reduction, StackedReductionRef},
            DeviceDataTransporter, ReferenceColMajorBackend, ReferenceDevice,
        },
        test_utils::test_system_params_small,
        FiatShamirTranscript, StarkEngine,
    };

    use super::*;
    use crate::KoalaBearPoseidon2CpuEngine;

    const L_SKIP: usize = 2;
    const N_STACK: usize = 2;

    /// Column-major trace of `width` columns and `2^log_height` rows, seeded by `seed` so distinct
    /// traces hold distinct data.
    fn trace(width: usize, log_height: usize, seed: u32) -> ColMajorMatrix<F> {
        let height = 1usize << log_height;
        let values = (0..(width * height) as u32)
            .map(|i| F::from_u32(i * 7 + seed))
            .collect();
        ColMajorMatrix::new(values, width)
    }

    /// A deterministic reduction point `r` of length `1 + N_STACK`, sampled from a sponge so its
    /// coordinates carry extension components.
    fn sample_point(seed: u32) -> Vec<EF> {
        let mut t = default_duplex_sponge();
        FiatShamirTranscript::<SC>::observe(&mut t, F::from_u32(seed));
        (0..=N_STACK)
            .map(|_| FiatShamirTranscript::<SC>::sample_ext(&mut t))
            .collect()
    }

    /// The optimized CPU reducer ([`StackedReductionCpu`]) and the reference reducer
    /// ([`StackedReductionRef`]) must assign every column the same λ-batching exponents and, as a
    /// result, emit byte-identical stacking proofs. This fixture stresses the exact case the shared
    /// [`lambda_slots`] SSOT protects: rotation and non-rotation columns interleaved across two
    /// commitments of mixed height, with a non-rot matrix ordered *before* a rot matrix — so a
    /// "skip the rot slot when unused" divergence would shift every later column's exponent and be
    /// caught here, not silently at the verifier.
    #[test]
    fn cpu_reducer_matches_reference_lambda_slots_and_proof() {
        let params = test_system_params_small(L_SKIP, N_STACK, 2);
        let engine: KoalaBearPoseidon2CpuEngine = StarkEngine::new(params.clone());
        let config = engine.config();
        let cpu_device = engine.device();
        let ref_device = ReferenceDevice::<SC>::new(config.clone());

        // Commit 0 stacks a full-height (width 2) and a half-height (width 1) trace; commit 1 a
        // single full-height (width 2) trace. `need_rot` mixes true/false and places the non-rot
        // matrix (0) before the rot matrix (1) within commit 0.
        let commit_traces: Vec<Vec<ColMajorMatrix<F>>> = vec![
            vec![
                trace(2, L_SKIP + N_STACK, 1),
                trace(1, L_SKIP + N_STACK - 1, 101),
            ],
            vec![trace(2, L_SKIP + N_STACK, 500)],
        ];
        let need_rot: Vec<Vec<bool>> = vec![vec![false, true], vec![true]];

        // Commit each group with the reference PCS, then transport to the CPU device (identical
        // layout + values), so both reducers see exactly the same input.
        let ref_datas = commit_traces
            .iter()
            .map(|traces| {
                let refs = traces.iter().collect_vec();
                stacked_commit(
                    config.hasher(),
                    params.l_skip,
                    params.n_stack,
                    params.log_blowup,
                    params.k_whir(),
                    &refs,
                )
                .unwrap()
                .1
            })
            .collect_vec();
        let cpu_datas = ref_datas
            .iter()
            .map(|d| cpu_device.transport_pcs_data_to_device(d))
            .collect_vec();

        let r = sample_point(7);

        // (1) Slot assignment. The CPU reducer stores exactly the shared `lambda_slots` walk; the
        // reference reducer builds its own `trace_views` from the same helper (its fields are
        // private to `mle-core`), so pinning the CPU side to `lambda_slots` pins CPU↔reference slot
        // parity. `lambda` here is arbitrary — the exponents do not depend on it.
        let lambda = EF::from_u32(0x0012_3457);
        let cpu_prover = <StackedReductionCpu<SC> as StackedReductionProver<
            CpuBackend<SC>,
            CpuDevice<SC>,
        >>::new(
            cpu_device,
            cpu_datas.iter().collect(),
            need_rot.clone(),
            &r,
            lambda,
        );
        let expected: Vec<ColLambda> = lambda_slots(ref_datas.iter().map(|d| &d.layout), &need_rot)
            .into_iter()
            .flatten()
            .collect();
        assert_eq!(cpu_prover.trace_views.len(), expected.len());
        for (i, (tv, exp)) in cpu_prover.trace_views.iter().zip(&expected).enumerate() {
            assert_eq!(tv.lambda, *exp, "λ slot mismatch at column {i}");
            // Every column reserves two consecutive exponents, so eq exponents are 0, 2, 4, …
            // regardless of which columns actually use their rotation slot.
            assert_eq!(tv.lambda.eq_exp, 2 * i, "eq exponent not 2·{i}");
        }
        // The mix must actually exercise both slot kinds.
        assert!(cpu_prover
            .trace_views
            .iter()
            .any(|tv| tv.lambda.rot_exp.is_some()));
        assert!(cpu_prover
            .trace_views
            .iter()
            .any(|tv| tv.lambda.rot_exp.is_none()));
        drop(cpu_prover);

        // (2) End-to-end parity. Identical fresh transcripts ⇒ identical sampled λ ⇒ the two
        // independent implementations must return a byte-identical stacking proof and reduction
        // point. A λ-slot divergence would perturb the batched round-0 polynomial and fail here.
        let mut ref_ts = default_duplex_sponge();
        let (ref_proof, ref_u) = prove_stacked_opening_reduction::<
            SC,
            ReferenceColMajorBackend<SC>,
            ReferenceDevice<SC>,
            DuplexSponge,
            StackedReductionRef<SC>,
        >(
            &ref_device,
            &mut ref_ts,
            N_STACK,
            ref_datas.iter().collect(),
            need_rot.clone(),
            &r,
        );

        let mut cpu_ts = default_duplex_sponge();
        let (cpu_proof, cpu_u) = prove_stacked_opening_reduction::<
            SC,
            CpuBackend<SC>,
            CpuDevice<SC>,
            DuplexSponge,
            StackedReductionCpu<SC>,
        >(
            cpu_device,
            &mut cpu_ts,
            N_STACK,
            cpu_datas.iter().collect(),
            need_rot,
            &r,
        );

        assert_eq!(cpu_u, ref_u, "reducers recovered different sumcheck points");
        assert_eq!(
            cpu_proof, ref_proof,
            "CPU and reference stacking proofs diverge"
        );
    }
}
