use std::array::from_fn;

use cfg_if::cfg_if;
use itertools::Itertools;
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{batch_multiplicative_inverse, ExtensionField, Field, TwoAdicField};
use p3_interpolation::interpolate_coset_with_precomputation;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
use tracing::{instrument, trace};

use crate::poly::{
    matrix::{
        ColMajorMatrix, ColMajorMatrixView, MatrixDimensions, MatrixView, StridedColMajorMatrixView,
    },
    ntt::SerialRadix2Dft,
    UnivariatePoly,
};

/// The univariate skip round 0: we want to compute the univariate polynomial `s(Z) = sum_{x \in
/// H_n} \hat{f}(Z, x)`. For this function, assume that `\hat{f}(\vec z) = \hat\eps(\vec z)
/// W(\hat{T}_0(\vec z), .., \hat{T}_{m-1}(\vec z))` for a sequence of `\hat{T}_i` where each
/// `\hat{T}_i` consists of a collection of prismalinear polynomials in `n + 1` variables, with
/// degree `< 2^{l_skip}` in the first variable.
///
/// The `mats` consists of the evaluations of `\hat{T}_i` on the hyperprism `D_n`, where evaluations
/// of each `\hat{T}_i` are in column-major order.
/// For round 0, we also provide a boolean `is_rotation` indicating whether the matrix should be
/// accessed at a cyclic offset of 1 (aka rotation).
///
/// `eps` is a single column vector of evaluations on `D_n`, except valued in extension field.
///
/// Let `W` be degree `d` in each variable. Then `s` is degree `<= d * (2^{l_skip} - 1)`, so it can
/// be interpolated using `d * (2^{l_skip} - 1) + 1` points.
///
/// This function returns `s` in **coefficient** form.
///
/// If `n > 0`, then all `mats` should have the same height equal to `2^{l_skip + n}`.
/// If `n = 0`, then all `mats` should have height `<= 2^{l_skip}` and they will be univariate
/// lifted to height `2^l_skip`.
#[instrument(level = "trace", skip_all)]
pub fn sumcheck_uni_round0_poly<F, EF, FN, const WD: usize>(
    l_skip: usize,
    n: usize,
    d: usize,
    mats: &[(StridedColMajorMatrixView<F>, bool)],
    w: FN,
) -> [UnivariatePoly<EF>; WD]
where
    F: TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
    FN: Fn(
            F,         /* Z */
            usize,     /* x_int */
            &[Vec<F>], /* mats eval at (Z, bin(x_int)) */
        ) -> [EF; WD]
        + Sync,
{
    if d == 0 {
        return from_fn(|_| UnivariatePoly(vec![]));
    }
    #[cfg(debug_assertions)]
    if n > 0 {
        for (m, _) in mats.iter() {
            assert_eq!(m.height(), 1 << (l_skip + n));
        }
    } else {
        for (m, _) in mats.iter() {
            assert!(
                m.height() <= 1 << l_skip,
                "mat height {} > 2^{l_skip}",
                m.height()
            );
        }
    }
    let g = F::GENERATOR;
    let omega_skip = F::two_adic_generator(l_skip);
    // skip 1 to avoid divide by zero in zerocheck
    let coset_shifts = g.powers().skip(1).take(d).collect_vec();

    // Map-Reduce
    // Map: for each x in H_n, compute
    // ```
    // [W(\hat{T}_0(z, x), ..., \hat{T}_{m-1}(z, x)) for z in `g_i D` for `d` cosets of `D`.
    // ```
    // We choose to iterate over x first to avoid multiple memory accesses to `\hat{T}`s
    let evals = (0..1 << n).into_par_iter().map(|x| {
        let dft = SerialRadix2Dft;
        // For fixed `x`, `Z -> \hat{T}_i(Z, x)` is a polynomial of degree `<2^l_skip` and we
        // have evaluations on the univariate skip domain `D = <ω_skip>` and we want to get
        // evaluations on the larger domain `L`.
        //
        // For now, we apply iDFT on D and then DFT on L.
        // A Chirp-Z transform over L would avoid this iDFT-then-DFT round trip.
        let mats_at_zs = mats
            .iter()
            .map(|(mat, is_rot)| {
                let height = mat.height();
                let offset = usize::from(*is_rot);
                (0..mat.width())
                    .map(|col_idx| {
                        // SAFETY: col_idx < width
                        // Note that the % height is necessary even when `offset = 0` because we may
                        // have `height < 2^{l_skip + n}` in the case where we are taking the lifts
                        // of `mats`
                        let col_x = ((x << l_skip)..(x + 1) << l_skip)
                            .map(|i| unsafe { *mat.get_unchecked((i + offset) % height, col_idx) })
                            .collect_vec();
                        let coeffs = dft.idft(col_x);
                        coset_shifts
                            .iter()
                            .flat_map(|&shift| dft.coset_dft(coeffs.clone(), shift))
                            .collect_vec()
                    })
                    .collect_vec()
            })
            .collect_vec();
        // Apply W(..) to `{\hat{T}_i(z, x)}` for each z in g_i D
        omega_skip
            .powers()
            .take(1 << l_skip)
            .enumerate()
            .flat_map(|(z_idx, z)| {
                coset_shifts
                    .iter()
                    .enumerate()
                    .map(|(coset_idx, &shift)| {
                        let z_int = (coset_idx << l_skip) + z_idx;
                        let row_z_x = mats_at_zs
                            .iter()
                            .map(|mat_at_zs| {
                                mat_at_zs
                                    .iter()
                                    .map(|col_at_zs| col_at_zs[z_int])
                                    .collect_vec()
                            })
                            .collect_vec();
                        w(shift * z, x, &row_z_x)
                    })
                    .collect_vec()
            })
            .collect_vec()
    });
    // Reduce: sum over H_n
    let hypercube_sum = |mut acc: Vec<[EF; WD]>, x| {
        for (acc, x) in acc.iter_mut().zip(x) {
            for (acc_i, x_i) in acc.iter_mut().zip(x) {
                *acc_i += x_i;
            }
        }
        acc
    };
    cfg_if! {
        if #[cfg(feature = "parallel")] {
            let evals = evals.reduce(
                || vec![[EF::ZERO; WD]; d << l_skip],
                hypercube_sum
            );
        } else {
            let evals = evals.collect_vec();
            let evals = evals.into_iter().fold(
                vec![[EF::ZERO; WD]; d << l_skip],
                hypercube_sum
            );
        }
    }
    from_fn(|i| {
        let values = evals.iter().map(|x| x[i]).collect_vec();
        UnivariatePoly::from_geometric_cosets_evals_idft(RowMajorMatrix::new(values, d), g, g)
    })
}

pub const fn sumcheck_round0_deg(l_skip: usize, d: usize) -> usize {
    d * ((1 << l_skip) - 1)
}

/// `mat` is a matrix of the evaluations on hyperprism D_n of a prismalinear extensions of the
/// columns. We "fold" it by evaluating the prismalinear polynomials at `r` in the univariate
/// variable `Z`.
///
/// If `n < 0`, then we evaluate `mat` at `r^{-n}`, which is equivalent to folding the lift of
/// `mat`.
#[instrument(level = "trace", skip_all)]
pub fn fold_ple_evals<F, EF>(
    l_skip: usize,
    mat: StridedColMajorMatrixView<F>,
    is_rot: bool,
    r: EF,
) -> ColMajorMatrix<EF>
where
    F: TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
{
    let height = mat.height();
    let lifted_height = height.max(1 << l_skip);
    let width = mat.width();

    let omega = F::two_adic_generator(l_skip);
    let omega_pows = omega.powers().take(1 << l_skip).collect_vec();
    let denoms = omega_pows
        .iter()
        .map(|&x_i| r - EF::from(x_i))
        .collect_vec();
    let inv_denoms = batch_multiplicative_inverse(&denoms);

    let offset = usize::from(is_rot);
    let new_height = lifted_height >> l_skip;
    let values = (0..width * new_height)
        .into_par_iter()
        .map(|idx| {
            // `values` needs to be column-major
            let x = idx % new_height;
            let j = idx / new_height;
            // SAFETY: j < width and we mod by height so row_idx < height
            // Note that the `% height` is also necessary to handle lifting of `mats`
            let uni_evals = (0..1 << l_skip)
                .map(|z| unsafe { *mat.get_unchecked(((x << l_skip) + z + offset) % height, j) })
                .collect_vec();
            interpolate_coset_with_precomputation(
                &RowMajorMatrix::new_col(uni_evals),
                F::ONE,
                r,
                &omega_pows,
                &inv_denoms,
            )[0]
        })
        .collect::<Vec<_>>();
    ColMajorMatrix::new(values, width)
}

pub fn batch_fold_ple_evals<F, EF>(
    l_skip: usize,
    mats: Vec<ColMajorMatrix<F>>,
    is_rot: bool,
    r: EF,
) -> Vec<ColMajorMatrix<EF>>
where
    F: TwoAdicField,
    EF: ExtensionField<F> + TwoAdicField,
{
    mats.into_par_iter()
        .map(|mat| fold_ple_evals(l_skip, mat.as_view().into(), is_rot, r))
        .collect()
}

/// For a sumcheck round, we want to compute the univariate polynomial `s(X) = sum_{y \in H_{n-1}}
/// \hat{f}(X, y)`. For this function, assume that `\hat{f}(\vec x) = W(\hat{T}_0(\vec x), ..,
/// \hat{T}_{m-1}(\vec x))` for a sequence of `\hat{T}_i` where each `\hat{T}_i` consists of a
/// collection of MLE polynomials in `n` variables.
///
/// The `mats` consists of the evaluations of `\hat{T}_i` on the hypercube `H_n`, where evaluations
/// of each `\hat{T}_i` are in column-major order.
///
/// Let `W` be degree `d` in each variable. Then `s` is degree `d`, so it can be interpolated using
/// `d + 1` points. This function returns the evaluations of `s` at `{1, ..., d}`. The evaluation at
/// `0` is omitted because our use of sumcheck always leaves the verifier to infer the evaluation at
/// `0` from the previous round's claim.
///
/// The generic `WF` is a closure `{\hat{T}_i(X, y)}_i -> W(\hat{T}_0(X, y), .., \hat{T}_{m-1}(X,
/// y))`.
///
/// This function should **not** be used for the univariate skip round.
#[instrument(level = "trace", skip_all)]
pub fn sumcheck_round_poly_evals<F, FN, const WD: usize>(
    n: usize,
    d: usize,
    mats: &[ColMajorMatrixView<F>],
    w: FN,
) -> [Vec<F>; WD]
where
    F: Field,
    FN: Fn(
            F,         /* X */
            usize,     /* y_int */
            &[Vec<F>], /* mats eval at (X, bin(y_int)) */
        ) -> [F; WD]
        + Sync,
{
    debug_assert!(mats.iter().all(|mat| mat.height() == 1 << n));
    if n == 0 {
        // Sum is trivial, s(X) is constant
        let evals = mats.iter().map(|row| row.values.to_vec()).collect_vec();
        return w(F::ONE, 0, &evals).map(|x| vec![x; d]);
    }
    let hypercube_dim = n - 1;
    // \hat{f}(x, \vec y) where \vec y is point on hypercube H_{n-1}
    let f_hat = |x: usize, y: usize| {
        let x = F::from_usize(x);
        let row_x_y = mats
            .iter()
            .map(|mat| {
                mat.columns()
                    .map(|col| {
                        let t_0 = col[y << 1];
                        let t_1 = col[(y << 1) | 1];
                        // Evaluate \hat{t}(x, \vec y) by linear interpolation since
                        // \hat{t} is MLE
                        t_0 + (t_1 - t_0) * x
                    })
                    .collect_vec()
            })
            .collect_vec();
        w(x, y, &row_x_y)
    };
    trace!(sum_claim = ?{(0..1 << n)
        .map(|x| f_hat(x & 1, x >> 1))
        .fold([F::ZERO; WD], |mut acc, x| {
            for (acc_i, x_i) in acc.iter_mut().zip(x) {
                *acc_i += x_i;
            }
            acc
        })
    }, "sumcheck_round");
    // Map-Reduce
    // Map: for each y in H_{n-1}, compute
    // ```
    // [W(\hat{T}_0(x, y), ..., \hat{T}_{m-1}(x, y)) for x in {1,...,d}]
    // ```
    // We choose to iterate over y first to avoid multiple memory accesses to `\hat{T}`s
    let evals = (0..1 << hypercube_dim)
        .into_par_iter()
        .map(|y| (1..=d).map(|x| f_hat(x, y)).collect_vec());
    // Reduce: sum over H_{n-1}
    let hypercube_sum = |mut acc: Vec<[F; WD]>, x| {
        for (acc, x) in acc.iter_mut().zip(x) {
            for (acc_i, x_i) in acc.iter_mut().zip(x) {
                *acc_i += x_i;
            }
        }
        acc
    };
    cfg_if! {
        if #[cfg(feature = "parallel")] {
            let evals = evals.reduce(
                || vec![[F::ZERO; WD]; d],
                hypercube_sum
            );
        } else {
            let evals = evals.collect_vec();
            let evals = evals.into_iter().fold(
                vec![[F::ZERO; WD]; d],
                hypercube_sum
            );
        }
    }
    from_fn(|i| evals.iter().map(|eval| eval[i]).collect_vec())
}

#[instrument(level = "trace", skip_all)]
pub fn fold_mle_evals<EF: Field>(mat: ColMajorMatrix<EF>, r: EF) -> ColMajorMatrix<EF> {
    let height = mat.height();
    if height <= 1 {
        return mat;
    }
    let width = mat.width();
    let values = mat
        .values
        .par_chunks_exact(height)
        .flat_map(|t| {
            t.par_chunks_exact(2).map(|t_01| {
                let t_0 = t_01[0];
                let t_1 = t_01[1];
                t_0 + (t_1 - t_0) * r
            })
        })
        .collect::<Vec<_>>();
    ColMajorMatrix::new(values, width)
}

pub fn batch_fold_mle_evals<EF: Field>(
    mats: Vec<ColMajorMatrix<EF>>,
    r: EF,
) -> Vec<ColMajorMatrix<EF>> {
    mats.into_par_iter()
        .map(|mat| fold_mle_evals(mat, r))
        .collect()
}

/// Unit tests plus the reference sumcheck oracles (`sumcheck_multilinear` /
/// `sumcheck_prismalinear`) they exercise. The oracles and their proof types are
/// `pub` so other test modules can reuse them via
/// `crate::prover::sumcheck::tests::*`.
#[cfg(test)]
pub mod tests {
    use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
    use p3_util::log2_strict_usize;
    use rand::{rngs::StdRng, RngExt, SeedableRng};
    use tracing::debug;

    use super::*;
    use crate::{
        config::koala_bear_poseidon2::{
            default_duplex_sponge, DuplexSponge, KoalaBearPoseidon2Config as SC, EF, F,
        },
        prover::error::SumcheckError,
        FiatShamirTranscript, StarkProtocolConfig,
    };

    /// In-place column-major fold on `H_n`: writes the folded values into the first `height/2`
    /// slots of each `height`-stride chunk without compacting the buffer. Test-only — the
    /// production fold path uses [`fold_mle_evals`] / [`batch_fold_mle_evals`]; this variant exists
    /// solely as a third implementation for [`fold_variants_agree`] to cross-check against.
    fn fold_mle_evals_inplace<EF: Field>(mat: &mut ColMajorMatrix<EF>, r: EF) {
        let height = mat.height();
        if height <= 1 {
            return;
        }
        mat.values.par_chunks_exact_mut(height).for_each(|t| {
            for y in 0..height / 2 {
                let t_0 = t[y << 1];
                let t_1 = t[(y << 1) + 1];
                t[y] = t_0 + (t_1 - t_0) * r;
            }
        });
    }

    pub struct SumcheckCubeProof<EF> {
        /// Note: the sum claim is always observed as an element of the extension field.
        pub sum_claim: EF,
        /// For each `round`, we have univariate polynomial `s_round`. We store evaluations at `{1,
        /// ..., deg(s_round)}` where evaluation at `0` is left for the verifier to infer from the
        /// previous round claim.
        pub round_polys_eval: Vec<Vec<EF>>,
        /// Final evaluation claim of the polynomial at the random vector `r`
        pub eval_claim: EF,
    }

    pub struct SumcheckPrismProof<EF> {
        pub sum_claim: EF,
        /// The univariate polynomial `s_0` in coefficient form.
        pub s_0: UnivariatePoly<EF>,
        /// for each hypercube `round`, the evaluations of univariate polynomial `s_round` at `{1, ...,
        /// deg(s_round)}`. See [SumcheckCubeProof] for details.
        pub round_polys_eval: Vec<Vec<EF>>,
        /// Final evaluation claim of the polynomial at the random vector `r`
        pub eval_claim: EF,
    }

    /// "Plain" sumcheck on a multilinear polynomial
    ///
    /// The slice `evals` contains the evaluations of a multilinear polynomial on boolean hypercube.
    /// The length of `evals` should equal `2^n` where `n` is hypercube dimension.
    ///
    /// Returns the sumcheck proof containing all prover messages and the random evaluation point.
    // The transcript is fixed to EF, while the input evaluations may be either base-field or
    // extension-field elements.
    //
    // Test-only reference oracle: the production prover never calls this directly.
    #[allow(clippy::type_complexity)]
    pub fn sumcheck_multilinear<SC: StarkProtocolConfig, F: Field, TS: FiatShamirTranscript<SC>>(
        transcript: &mut TS,
        evals: &[F],
    ) -> Result<(SumcheckCubeProof<SC::EF>, Vec<SC::EF>), SumcheckError>
    where
        SC::EF: ExtensionField<F>,
    {
        let n = log2_strict_usize(evals.len());
        let mut round_polys_eval = Vec::with_capacity(n);
        let mut r = Vec::with_capacity(n);

        // Working copy of evaluations that gets folded after each round.
        // The first round can be specialized when F is the base field.
        let mut current_evals =
            ColMajorMatrix::new(evals.iter().map(|&x| SC::EF::from(x)).collect(), 1);
        let sum_claim: SC::EF = evals.iter().fold(F::ZERO, |acc, &x| acc + x).into();
        transcript.observe_ext(sum_claim);

        // Sumcheck rounds:
        // - each round the prover needs to compute univariate polynomial `s_round`. This poly is linear
        //   since we are taking MLE of `evals`.
        // - at end of each round, sample random `r_round` in `EF`
        for round in 0..n {
            let [s] = sumcheck_round_poly_evals(
                n - round,
                1,
                &[current_evals.as_view()],
                |_x, _y, evals| [evals[0][0]],
            );

            if s.len() != 1 {
                return Err(SumcheckError::MultilinearRoundPolyLen { len: s.len() });
            }
            transcript.observe_ext(s[0]);
            round_polys_eval.push(s);

            let r_round = transcript.sample_ext();
            debug!(%round, %r_round);
            r.push(r_round);

            current_evals = fold_mle_evals(current_evals, r_round);
        }

        // After all rounds, current_evals should have exactly one element
        if current_evals.values.len() != 1 {
            return Err(SumcheckError::MultilinearFinalEvalLen {
                len: current_evals.values.len(),
            });
        }
        let eval_claim = current_evals.values[0];

        // Add final evaluation to transcript
        transcript.observe_ext(eval_claim);

        Ok((
            SumcheckCubeProof {
                sum_claim,
                round_polys_eval,
                eval_claim,
            },
            r,
        ))
    }

    /// "Plain" sumcheck on a prismalinear polynomial with Gruen's univariate skip.
    ///
    /// The slice `evals` contains the evaluations of a prismalinear polynomial on the hyperprism.
    /// The length of `evals` should equal `2^{l_skip + n}` where `l_skip` is the univariate skip
    /// parameter and `n` is hypercube dimension.
    /// Indexing is such that `evals[x * 2^{l_skip} + i]` is the evaluation of `f(omega_D^i, x)` where
    /// `omega_D` is a fixed generator of the univariate skip domain `D` (which is a subgroup of
    /// `F^*`).
    ///
    /// Returns the sumcheck proof containing all prover messages and the random evaluation point.
    // The transcript is fixed to EF, while the input evaluations may be either base-field or
    // extension-field elements. For simplicity, `sum_claim` and `s_0` are observed as EF values;
    // a more compact encoding could observe base-field values when applicable.
    //
    // Test-only reference oracle: the production prover never calls this directly.
    #[allow(clippy::type_complexity)]
    pub fn sumcheck_prismalinear<SC: StarkProtocolConfig, F, TS: FiatShamirTranscript<SC>>(
        transcript: &mut TS,
        l_skip: usize,
        evals: &[F],
    ) -> Result<(SumcheckPrismProof<SC::EF>, Vec<SC::EF>), SumcheckError>
    where
        F: TwoAdicField,
        SC::EF: ExtensionField<F> + TwoAdicField,
    {
        let prism_dim = log2_strict_usize(evals.len());
        if prism_dim < l_skip {
            return Err(SumcheckError::PrismalinearDimTooSmall { prism_dim, l_skip });
        }
        let n = prism_dim - l_skip;

        let mut round_polys_eval = Vec::with_capacity(n);
        let mut r = Vec::with_capacity(n + 1);

        let sum_claim: SC::EF = evals.iter().copied().sum::<F>().into();
        transcript.observe_ext(sum_claim);
        let current_evals = ColMajorMatrix::new(evals.to_vec(), 1);
        let [s_0] = sumcheck_uni_round0_poly(
            l_skip,
            n,
            1,
            &[(current_evals.as_view().into(), false)],
            |_z, _x, evals| [evals[0][0]],
        );
        let s_0_ext = UnivariatePoly::new(
            s_0.0
                .into_iter()
                .map(|x| {
                    let ext = SC::EF::from(x);
                    transcript.observe_ext(ext);
                    ext
                })
                .collect(),
        );

        let r_0 = transcript.sample_ext();
        debug!(round = 0, r_round = %r_0);
        r.push(r_0);

        // After sampling r_0, we need to evaluate the prismalinear polynomial at (r_0, x) for each x in
        // hypercube. For each x in the hypercube, we have evaluations f(z, x) for z in the
        // univariate skip domain D. We interpolate these to get a univariate polynomial and evaluate
        // at r_0.
        let mut current_evals = fold_ple_evals(l_skip, current_evals.as_view().into(), false, r_0);
        debug_assert_eq!(current_evals.height(), 1 << n);

        // Sumcheck rounds:
        // - each round the prover needs to compute univariate polynomial `s_round`. This poly is linear
        //   since we are taking MLE of `evals`.
        // - at end of each round, sample random `r_round` in `EF`
        for round in 1..=n {
            debug!(
                cur_sum = %current_evals
                    .values
                    .iter()
                    .fold(SC::EF::ZERO, |acc, x| acc + *x)
            );
            let [s] = sumcheck_round_poly_evals(
                n + 1 - round,
                1,
                &[current_evals.as_view()],
                |_x, _y, evals| [evals[0][0]],
            );
            if s.len() != 1 {
                return Err(SumcheckError::PrismalinearRoundPolyLen { len: s.len() });
            }
            transcript.observe_ext(s[0]);
            round_polys_eval.push(s);

            let r_round = transcript.sample_ext();
            debug!(%round, %r_round);
            r.push(r_round);

            current_evals = fold_mle_evals(current_evals, r_round);
        }

        if r.len() != n + 1 {
            return Err(SumcheckError::PrismalinearRLen {
                r_len: r.len(),
                expected: n + 1,
            });
        }
        // After all rounds, current_evals should have exactly one element
        if current_evals.values.len() != 1 {
            return Err(SumcheckError::PrismalinearFinalEvalLen {
                len: current_evals.values.len(),
            });
        }
        let eval_claim = current_evals.values[0];

        // Add final evaluation to transcript
        transcript.observe_ext(eval_claim);

        Ok((
            SumcheckPrismProof {
                sum_claim,
                s_0: s_0_ext,
                round_polys_eval,
                eval_claim,
            },
            r,
        ))
    }

    fn f(x: u32) -> F {
        F::from_u32(x)
    }

    /// A uniformly random extension-field element (all `D` base limbs random).
    fn rand_ef(rng: &mut StdRng) -> EF {
        EF::from_basis_coefficients_fn(|_| f(rng.random()))
    }

    /// Independent, definitional multilinear-extension oracle:
    /// `MLE(r) = sum_b evals[b] * prod_i chi(b_i, r_i)` with `chi(0,r)=1-r`, `chi(1,r)=r`,
    /// where `b_i` is bit `i` of `b` and `r[i]` binds bit `i` (low bit first — matches
    /// [`fold_mle_evals`]). Deliberately not implemented via pair-folding and not routed through
    /// any `poly::eq` helper, so the round-trip assertions compare folding against the closed form,
    /// not fold-against-fold.
    fn eval_mle_closed_form<T: Into<EF> + Copy>(evals: &[T], r: &[EF]) -> EF {
        let n = r.len();
        assert_eq!(evals.len(), 1 << n);
        (0..1usize << n)
            .map(|b| {
                let mut w: EF = evals[b].into();
                for (i, &ri) in r.iter().enumerate() {
                    w *= if (b >> i) & 1 == 1 { ri } else { EF::ONE - ri };
                }
                w
            })
            .sum()
    }

    // ---------------------------------------------------------------------------------------------
    // Folding primitives
    // ---------------------------------------------------------------------------------------------

    /// `fold_mle_evals` is exactly the per-variable partial evaluation in variable 0
    /// (`out[k] = in[2k] + (in[2k+1]-in[2k])*r`), column by column.
    #[test]
    fn fold_mle_evals_is_partial_eval() {
        let mut rng = StdRng::seed_from_u64(1);
        let height = 8usize;
        let width = 3usize;
        let values = (0..height * width).map(|_| rand_ef(&mut rng)).collect_vec();
        let mat = ColMajorMatrix::new(values.clone(), width);
        let r = rand_ef(&mut rng);

        let folded = fold_mle_evals(mat, r);
        assert_eq!(folded.height(), height / 2);
        assert_eq!(folded.width(), width);
        for j in 0..width {
            for k in 0..height / 2 {
                let t0 = values[j * height + 2 * k];
                let t1 = values[j * height + 2 * k + 1];
                assert_eq!(folded.values[j * (height / 2) + k], t0 + (t1 - t0) * r);
            }
        }
    }

    /// Folding a single column all the way down equals the closed-form MLE at `r`.
    #[test]
    fn fold_mle_evals_full_reduction_matches_closed_form_mle() {
        let mut rng = StdRng::seed_from_u64(2);
        let n = 5usize;
        let evals = (0..1usize << n).map(|_| rand_ef(&mut rng)).collect_vec();
        let r = (0..n).map(|_| rand_ef(&mut rng)).collect_vec();

        let mut mat = ColMajorMatrix::new(evals.clone(), 1);
        for &ri in &r {
            mat = fold_mle_evals(mat, ri);
        }
        assert_eq!(mat.values.len(), 1);
        assert_eq!(mat.values[0], eval_mle_closed_form(&evals, &r));
    }

    /// `batch_fold_mle_evals` == mapping `fold_mle_evals` over each matrix.
    #[test]
    fn batch_fold_mle_evals_matches_fold() {
        let mut rng = StdRng::seed_from_u64(3);
        let mats = (0..3)
            .map(|_| {
                let h = 8usize;
                let w = 2usize;
                ColMajorMatrix::new((0..h * w).map(|_| rand_ef(&mut rng)).collect_vec(), w)
            })
            .collect_vec();
        let r = rand_ef(&mut rng);

        let batched = batch_fold_mle_evals(mats.clone(), r);
        for (mat, b) in mats.into_iter().zip(batched) {
            assert_eq!(fold_mle_evals(mat, r).values, b.values);
        }
    }

    /// All three fold variants agree. Note [`fold_mle_evals_inplace`] writes the folded values
    /// into the first `height/2` slots of each `height`-stride chunk and does not compact the
    /// buffer (`sumcheck.rs` `fold_mle_evals_inplace`), so we extract `[j*height .. j*height+h/2)`.
    #[test]
    fn fold_variants_agree() {
        let mut rng = StdRng::seed_from_u64(4);
        let height = 8usize;
        let width = 3usize;
        let mat = ColMajorMatrix::new(
            (0..height * width).map(|_| rand_ef(&mut rng)).collect_vec(),
            width,
        );
        let r = rand_ef(&mut rng);

        let a = fold_mle_evals(mat.clone(), r);
        let b = batch_fold_mle_evals(vec![mat.clone()], r);
        assert_eq!(a.values, b[0].values);

        let mut c = mat;
        fold_mle_evals_inplace(&mut c, r);
        for j in 0..width {
            for k in 0..height / 2 {
                assert_eq!(c.values[j * height + k], a.values[j * (height / 2) + k]);
            }
        }
    }

    // ---------------------------------------------------------------------------------------------
    // sumcheck_round_poly_evals (col-major), mirroring the row-major coverage
    // ---------------------------------------------------------------------------------------------

    /// `s(0)+s(1) == claimed sum` for the identity combiner on a random column.
    #[test]
    fn round_poly_s0_plus_s1_eq_claim() {
        let mut rng = StdRng::seed_from_u64(10);
        let n = 4usize;
        let col = (0..1usize << n).map(|_| f(rng.random())).collect_vec();
        let mat = ColMajorMatrix::new(col.clone(), 1);
        let [s] =
            sumcheck_round_poly_evals::<F, _, 1>(n, 1, &[mat.as_view()], |_x, _y, e| [e[0][0]]);
        // s is degree 1 -> evals at {1}; s(1) = sum over odd-indexed entries.
        let s1 = s[0];
        let s0: F = col.iter().step_by(2).copied().sum();
        let claim: F = col.iter().copied().sum();
        assert_eq!(s0 + s1, claim);
        // and s(1) is the sum over the odd half:
        let odd_sum: F = col.iter().skip(1).step_by(2).copied().sum();
        assert_eq!(s1, odd_sum);
    }

    /// Degree-2 combiner exercises the `{1,..,d}` evaluation grid.
    /// For `[a,b]`, `s(X)=a*(1-X)+b*X` so `s(1)=b`, and squaring gives `[b^2, (2b-a)^2]`.
    #[test]
    fn round_poly_degree2_squaring() {
        let a = f(5);
        let b = f(11);
        let mat = ColMajorMatrix::new(vec![a, b], 1);
        let [s] = sumcheck_round_poly_evals::<F, _, 1>(1, 2, &[mat.as_view()], |_x, _y, e| {
            [e[0][0] * e[0][0]]
        });
        assert_eq!(s.len(), 2);
        assert_eq!(s[0], b * b);
        let s_at_2 = a * (F::ONE - f(2)) + b * f(2);
        assert_eq!(s[1], s_at_2 * s_at_2);
    }

    /// `n=0` (trivial sum) and multi-part combiner.
    #[test]
    fn round_poly_n0_and_multi_part() {
        let mat = ColMajorMatrix::new(vec![f(42)], 1);
        let [s] =
            sumcheck_round_poly_evals::<F, _, 1>(0, 1, &[mat.as_view()], |_x, _y, e| [e[0][0]]);
        assert_eq!(s[0], f(42));

        let m1 = ColMajorMatrix::new(vec![f(10), f(20)], 1);
        let m2 = ColMajorMatrix::new(vec![f(3), f(7)], 1);
        let [s] = sumcheck_round_poly_evals::<F, _, 1>(
            1,
            1,
            &[m1.as_view(), m2.as_view()],
            |_x, _y, e| [e[0][0] + e[1][0]],
        );
        assert_eq!(s[0], f(20) + f(7));
    }

    // ---------------------------------------------------------------------------------------------
    // Univariate-skip round-0 primitive
    // ---------------------------------------------------------------------------------------------

    /// `sumcheck_round0_deg` is the degree bound, and the *actual* round-0 poly respects it (and
    /// saturates it for random input). Replaces a tautological "formula == formula" check.
    #[test]
    fn uni_round0_poly_degree() {
        let mut rng = StdRng::seed_from_u64(20);
        let (l_skip, n) = (2usize, 2usize);
        let mat = ColMajorMatrix::new(
            (0..1usize << (l_skip + n))
                .map(|_| f(rng.random()))
                .collect_vec(),
            1,
        );
        let [s0] = sumcheck_uni_round0_poly::<F, F, _, 1>(
            l_skip,
            n,
            1,
            &[(mat.as_view().into(), false)],
            |_z, _x, e| [e[0][0]],
        );
        let mut len = s0.coeffs().len();
        while len > 0 && s0.coeffs()[len - 1] == F::ZERO {
            len -= 1;
        }
        let deg = len.saturating_sub(1);
        let bound = sumcheck_round0_deg(l_skip, 1);
        assert_eq!(bound, (1 << l_skip) - 1);
        assert!(deg <= bound, "deg {deg} exceeds bound {bound}");
        assert_eq!(deg, bound, "random input should saturate the degree bound");
    }

    /// The round-0 poly summed over the univariate skip domain `D = {omega^i}` equals the
    /// hyperprism sum (the round-0 sumcheck identity).
    #[test]
    fn uni_round0_poly_skip_domain_sum() {
        let mut rng = StdRng::seed_from_u64(21);
        let (l_skip, n) = (2usize, 2usize);
        let evals = (0..1usize << (l_skip + n))
            .map(|_| f(rng.random()))
            .collect_vec();
        let mat = ColMajorMatrix::new(evals.clone(), 1);
        let [s0] = sumcheck_uni_round0_poly::<F, F, _, 1>(
            l_skip,
            n,
            1,
            &[(mat.as_view().into(), false)],
            |_z, _x, e| [e[0][0]],
        );
        let omega = F::two_adic_generator(l_skip);
        let d_sum: F = (0..1usize << l_skip)
            .map(|i| s0.eval_at_point::<F>(omega.exp_u64(i as u64)))
            .sum();
        assert_eq!(d_sum, evals.iter().copied().sum::<F>());
    }

    /// `fold_ple_evals` matches an independent Lagrange interpolation of each per-`x` slice on
    /// `{omega^i}`, evaluated at `r` — covering both `is_rot=false` and `is_rot=true`.
    #[test]
    fn fold_ple_evals_matches_lagrange() {
        let mut rng = StdRng::seed_from_u64(22);
        let (l_skip, n) = (2usize, 2usize);
        let h = 1usize << (l_skip + n);
        let evals = (0..h).map(|_| f(rng.random())).collect_vec();
        let mat = ColMajorMatrix::new(evals.clone(), 1);
        let omega = F::two_adic_generator(l_skip);
        let omega_pows = omega.powers().take(1 << l_skip).collect_vec();
        let r = rand_ef(&mut rng);

        for is_rot in [false, true] {
            let folded = fold_ple_evals(l_skip, mat.as_view().into(), is_rot, r);
            assert_eq!(folded.height(), 1 << n);
            let offset = usize::from(is_rot);
            for x in 0..1usize << n {
                let slice = (0..1usize << l_skip)
                    .map(|z| EF::from(evals[((x << l_skip) + z + offset) % h]))
                    .collect_vec();
                let expected = UnivariatePoly::lagrange_interpolate(&omega_pows, &slice)
                    .eval_at_point::<EF>(r);
                assert_eq!(folded.values[x], expected, "is_rot={is_rot} x={x}");
            }
        }
    }

    /// Production round-0 path: `is_rot=true` AND degree `d=2` (squaring combiner), checked at
    /// random points against `s(zeta) = sum_x T0(zeta,x)^2`, where `T0(zeta,x)` is the Lagrange
    /// interpolation of the *rotated* per-`x` slice. This exercises the cyclic-offset logic and the
    /// multi-coset iDFT->DFT path that production (rotation + higher degree) actually uses.
    #[test]
    fn uni_round0_poly_rotation_degree2() {
        let mut rng = StdRng::seed_from_u64(23);
        let (l_skip, n) = (2usize, 2usize);
        let h = 1usize << (l_skip + n);
        let evals = (0..h).map(|_| f(rng.random())).collect_vec();
        let mat = ColMajorMatrix::new(evals.clone(), 1);
        let [s] = sumcheck_uni_round0_poly::<F, F, _, 1>(
            l_skip,
            n,
            2,
            &[(mat.as_view().into(), true)],
            |_z, _x, rows| [rows[0][0] * rows[0][0]],
        );
        // `from_geometric_cosets_evals_idft` returns an untrimmed coeff vec (one slot per coset
        // evaluation); the true degree is `d*(2^l_skip - 1)`, so trim trailing zeros first.
        let mut len = s.coeffs().len();
        while len > 0 && s.coeffs()[len - 1] == F::ZERO {
            len -= 1;
        }
        assert!(
            len.saturating_sub(1) <= sumcheck_round0_deg(l_skip, 2),
            "deg {} exceeds bound {}",
            len.saturating_sub(1),
            sumcheck_round0_deg(l_skip, 2)
        );

        let omega = F::two_adic_generator(l_skip);
        let omega_pows = omega.powers().take(1 << l_skip).collect_vec();
        let rotated = (0..h).map(|k| evals[(k + 1) % h]).collect_vec();
        // `s` has degree <= sumcheck_round0_deg(2,2) = 6; pin it at 9 (> deg) distinct points so a
        // incorrect `s` from the multi-coset path cannot coincide with the oracle on the test set.
        let points = (1u32..=9).map(|i| f(i * 1009 + 1)).collect_vec();
        for zeta in points {
            let mut expected = F::ZERO;
            for x in 0..1usize << n {
                let slice = (0..1usize << l_skip)
                    .map(|z| rotated[(x << l_skip) + z])
                    .collect_vec();
                let t0 = UnivariatePoly::lagrange_interpolate(&omega_pows, &slice)
                    .eval_at_point::<F>(zeta);
                expected += t0 * t0;
            }
            assert_eq!(s.eval_at_point::<F>(zeta), expected, "zeta={zeta:?}");
        }
    }

    /// `batch_fold_ple_evals` == mapping `fold_ple_evals`.
    #[test]
    fn batch_fold_ple_evals_matches_fold() {
        let mut rng = StdRng::seed_from_u64(24);
        let (l_skip, n) = (2usize, 1usize);
        let h = 1usize << (l_skip + n);
        let mats = (0..3)
            .map(|_| ColMajorMatrix::new((0..h).map(|_| f(rng.random())).collect_vec(), 1))
            .collect_vec();
        let r = rand_ef(&mut rng);
        let batched = batch_fold_ple_evals(l_skip, mats.clone(), false, r);
        for (mat, b) in mats.into_iter().zip(batched) {
            let single = fold_ple_evals(l_skip, mat.as_view().into(), false, r);
            assert_eq!(single.values, b.values);
        }
    }

    // ---------------------------------------------------------------------------------------------
    // Full round-trips: prover -> test-local verifier -> external oracle, plus negative tests
    // ---------------------------------------------------------------------------------------------

    /// Per-check outcome of the test-local cube verifier, so negative tests can assert which
    /// check rejects.
    #[derive(Debug)]
    struct CubeVerification {
        challenges: Vec<EF>,
        /// final folded claim from the round polynomials.
        round_claim: EF,
        sum_claim_ok: bool,
        final_eval_ok: bool,
        oracle_eval_ok: bool,
    }

    impl CubeVerification {
        fn ok(&self) -> bool {
            self.sum_claim_ok && self.final_eval_ok && self.oracle_eval_ok
        }
    }

    /// Test-local verifier for [`SumcheckCubeProof`]. Replays the real transcript exactly as the
    /// prover wrote it, derives its own challenges, and runs the full sumcheck check. Mirrors
    /// the stacked-reduction verifier convention:
    /// `s(0)=claim-s(1)`, linear interpolation, observe-then-sample.
    fn verify_cube_proof(proof: &SumcheckCubeProof<EF>, evals: &[F]) -> CubeVerification {
        let n = log2_strict_usize(evals.len());
        let rejected = CubeVerification {
            challenges: vec![],
            round_claim: EF::ZERO,
            sum_claim_ok: false,
            final_eval_ok: false,
            oracle_eval_ok: false,
        };
        if proof.round_polys_eval.len() != n || proof.round_polys_eval.iter().any(|r| r.len() != 1)
        {
            return rejected;
        }
        let mut verifier_transcript = default_duplex_sponge();
        FiatShamirTranscript::<SC>::observe_ext(&mut verifier_transcript, proof.sum_claim);
        let mut claim = proof.sum_claim;
        let mut challenges = Vec::with_capacity(n);
        for round in &proof.round_polys_eval {
            let s1 = round[0];
            FiatShamirTranscript::<SC>::observe_ext(&mut verifier_transcript, s1);
            let s0 = claim - s1;
            let challenge = FiatShamirTranscript::<SC>::sample_ext(&mut verifier_transcript);
            challenges.push(challenge);
            claim = s0 + (s1 - s0) * challenge;
        }
        FiatShamirTranscript::<SC>::observe_ext(&mut verifier_transcript, proof.eval_claim);

        let sum_claim_ok = proof.sum_claim == evals.iter().copied().map(EF::from).sum::<EF>();
        let final_eval_ok = claim == proof.eval_claim;
        let oracle_eval_ok = proof.eval_claim == eval_mle_closed_form(evals, &challenges);
        CubeVerification {
            challenges,
            round_claim: claim,
            sum_claim_ok,
            final_eval_ok,
            oracle_eval_ok,
        }
    }

    /// Convenience wrapper: `Some(challenges)` iff the proof fully verifies.
    fn verified_cube_challenges(proof: &SumcheckCubeProof<EF>, evals: &[F]) -> Option<Vec<EF>> {
        let verification = verify_cube_proof(proof, evals);
        verification.ok().then_some(verification.challenges)
    }

    #[test]
    fn sumcheck_multilinear_round_trip() {
        let mut rng = StdRng::seed_from_u64(30);
        let n = 4usize;
        let evals = (0..1usize << n).map(|_| f(rng.random())).collect_vec();

        let mut prover_transcript = default_duplex_sponge();
        let (proof, r) =
            sumcheck_multilinear::<SC, F, DuplexSponge>(&mut prover_transcript, &evals).unwrap();

        let verified_challenges =
            verified_cube_challenges(&proof, &evals).expect("honest proof must verify");
        // Challenges are transcript-deterministic: prover and verifier agree.
        assert_eq!(verified_challenges, r);
    }

    /// Edge case `n = 0` (single evaluation, zero sumcheck rounds).
    #[test]
    fn sumcheck_multilinear_round_trip_n0() {
        let evals = vec![f(7)];
        let mut prover_transcript = default_duplex_sponge();
        let (proof, r) =
            sumcheck_multilinear::<SC, F, DuplexSponge>(&mut prover_transcript, &evals).unwrap();
        assert!(r.is_empty());
        assert!(proof.round_polys_eval.is_empty());
        let verified_challenges =
            verified_cube_challenges(&proof, &evals).expect("n=0 cube must verify");
        assert!(verified_challenges.is_empty());
    }

    #[test]
    fn sumcheck_multilinear_rejects_tampering() {
        let mut rng = StdRng::seed_from_u64(31);
        let n = 4usize;
        let evals = (0..1usize << n).map(|_| f(rng.random())).collect_vec();
        let mut prover_transcript = default_duplex_sponge();
        let (proof, _r) =
            sumcheck_multilinear::<SC, F, DuplexSponge>(&mut prover_transcript, &evals).unwrap();
        assert!(verify_cube_proof(&proof, &evals).ok());

        // Each tamper of a transcript-observed value is rejected (Fiat-Shamir cascade). `sum_claim`
        // and `eval_claim` tampers additionally trip their own check, which we assert explicitly.
        let mut tampered = clone_cube_proof(&proof);
        tampered.round_polys_eval[1][0] += EF::ONE;
        assert!(
            !verify_cube_proof(&tampered, &evals).ok(),
            "tampered round poly accepted"
        );

        let mut tampered = clone_cube_proof(&proof);
        tampered.sum_claim += EF::ONE;
        let verification = verify_cube_proof(&tampered, &evals);
        assert!(
            !verification.ok() && !verification.sum_claim_ok,
            "tampered sum_claim accepted"
        );

        let mut tampered = clone_cube_proof(&proof);
        tampered.eval_claim += EF::ONE;
        assert!(
            !verify_cube_proof(&tampered, &evals).ok(),
            "tampered eval_claim accepted"
        );

        // Isolate `final_ok` (the sumcheck-recursion check mirroring production
        // `verifier/stacked_reduction.rs`): tamper a round poly, then patch `eval_claim` (observed
        // last, so it does not perturb the replayed challenges) to the replayed oracle value so
        // `oracle_ok` passes — leaving `final_ok` as the only failure. Proves the check is
        // load-bearing and not masked by `oracle_ok`.
        let mut tampered = clone_cube_proof(&proof);
        tampered.round_polys_eval[2][0] += EF::ONE;
        let replayed = verify_cube_proof(&tampered, &evals);
        tampered.eval_claim = eval_mle_closed_form(&evals, &replayed.challenges);
        let patched = verify_cube_proof(&tampered, &evals);
        assert!(
            patched.sum_claim_ok && patched.oracle_eval_ok && !patched.final_eval_ok,
            "final_ok not isolated: {patched:?}"
        );

        // Isolate `oracle_ok` (the eval-binding to the real MLE): patch `eval_claim` to the
        // replayed recursion result so `final_ok` passes — leaving `oracle_ok` the sole failure.
        let mut tampered = clone_cube_proof(&proof);
        tampered.round_polys_eval[2][0] += EF::ONE;
        let replayed = verify_cube_proof(&tampered, &evals);
        tampered.eval_claim = replayed.round_claim;
        let patched = verify_cube_proof(&tampered, &evals);
        assert!(
            patched.sum_claim_ok && patched.final_eval_ok && !patched.oracle_eval_ok,
            "oracle_ok not isolated: {patched:?}"
        );
    }

    fn clone_cube_proof(p: &SumcheckCubeProof<EF>) -> SumcheckCubeProof<EF> {
        SumcheckCubeProof {
            sum_claim: p.sum_claim,
            round_polys_eval: p.round_polys_eval.clone(),
            eval_claim: p.eval_claim,
        }
    }

    /// Per-check outcome of the test-local prism verifier. `domain_sum_ok` is the round-0
    /// skip-domain identity; `oracle_eval` is the independently recomputed final claim.
    #[derive(Debug)]
    struct PrismVerification {
        challenges: Vec<EF>,
        round_claim: EF,
        oracle_eval: EF,
        domain_sum_ok: bool,
        sum_claim_ok: bool,
        final_eval_ok: bool,
        oracle_eval_ok: bool,
    }

    impl PrismVerification {
        fn ok(&self) -> bool {
            self.domain_sum_ok && self.sum_claim_ok && self.final_eval_ok && self.oracle_eval_ok
        }
    }

    /// Test-local verifier for [`SumcheckPrismProof`] (univariate skip). Round 0 observes the
    /// `s_0` coeffs, checks the skip-domain `D`-sum against the claimed sum, then folds via
    /// `s_0(r_0)`; subsequent rounds match the cube verifier. The independent `eval_claim` oracle
    /// folds round 0 with Lagrange interpolation, instead of `fold_ple_evals`, then applies
    /// the closed-form MLE evaluator.
    fn verify_prism_proof(
        proof: &SumcheckPrismProof<EF>,
        l_skip: usize,
        evals: &[F],
    ) -> PrismVerification {
        let prism_dim = log2_strict_usize(evals.len());
        let rejected = PrismVerification {
            challenges: vec![],
            round_claim: EF::ZERO,
            oracle_eval: EF::ZERO,
            domain_sum_ok: false,
            sum_claim_ok: false,
            final_eval_ok: false,
            oracle_eval_ok: false,
        };
        if prism_dim < l_skip {
            return rejected;
        }
        let n = prism_dim - l_skip;
        if proof.round_polys_eval.len() != n || proof.round_polys_eval.iter().any(|r| r.len() != 1)
        {
            return rejected;
        }
        let mut verifier_transcript = default_duplex_sponge();
        FiatShamirTranscript::<SC>::observe_ext(&mut verifier_transcript, proof.sum_claim);
        for &c in proof.s_0.coeffs() {
            FiatShamirTranscript::<SC>::observe_ext(&mut verifier_transcript, c);
        }
        let r0 = FiatShamirTranscript::<SC>::sample_ext(&mut verifier_transcript);

        let omega = F::two_adic_generator(l_skip);
        let d_sum: EF = (0..1usize << l_skip)
            .map(|i| {
                proof
                    .s_0
                    .eval_at_point::<EF>(EF::from(omega.exp_u64(i as u64)))
            })
            .sum();

        let mut claim = proof.s_0.eval_at_point::<EF>(r0);
        let mut challenges = vec![r0];
        for round in &proof.round_polys_eval {
            let s1 = round[0];
            FiatShamirTranscript::<SC>::observe_ext(&mut verifier_transcript, s1);
            let s0 = claim - s1;
            let challenge = FiatShamirTranscript::<SC>::sample_ext(&mut verifier_transcript);
            challenges.push(challenge);
            claim = s0 + (s1 - s0) * challenge;
        }
        FiatShamirTranscript::<SC>::observe_ext(&mut verifier_transcript, proof.eval_claim);

        // Independent oracle: fold round 0 per-`x` via Lagrange on {omega^i}, then closed-form MLE.
        let omega_pows = omega.powers().take(1 << l_skip).collect_vec();
        let folded = (0..1usize << n)
            .map(|x| {
                let slice = (0..1usize << l_skip)
                    .map(|z| EF::from(evals[(x << l_skip) + z]))
                    .collect_vec();
                UnivariatePoly::lagrange_interpolate(&omega_pows, &slice).eval_at_point::<EF>(r0)
            })
            .collect_vec();
        let oracle_eval = eval_mle_closed_form(&folded, &challenges[1..]);

        let domain_sum_ok = d_sum == proof.sum_claim;
        let sum_claim_ok = proof.sum_claim == evals.iter().copied().map(EF::from).sum::<EF>();
        let final_eval_ok = claim == proof.eval_claim;
        let oracle_eval_ok = proof.eval_claim == oracle_eval;
        PrismVerification {
            challenges,
            round_claim: claim,
            oracle_eval,
            domain_sum_ok,
            sum_claim_ok,
            final_eval_ok,
            oracle_eval_ok,
        }
    }

    /// Convenience wrapper: `Some(challenges)` iff the proof fully verifies.
    fn verified_prism_challenges(
        proof: &SumcheckPrismProof<EF>,
        l_skip: usize,
        evals: &[F],
    ) -> Option<Vec<EF>> {
        let verification = verify_prism_proof(proof, l_skip, evals);
        verification.ok().then_some(verification.challenges)
    }

    #[test]
    fn sumcheck_prismalinear_round_trip() {
        let mut rng = StdRng::seed_from_u64(40);
        let (l_skip, n) = (2usize, 3usize);
        let evals = (0..1usize << (l_skip + n))
            .map(|_| f(rng.random()))
            .collect_vec();

        let mut prover_transcript = default_duplex_sponge();
        let (proof, r) =
            sumcheck_prismalinear::<SC, F, DuplexSponge>(&mut prover_transcript, l_skip, &evals)
                .unwrap();
        assert_eq!(r.len(), n + 1);

        let verified_challenges = verified_prism_challenges(&proof, l_skip, &evals)
            .expect("honest prism proof must verify");
        assert_eq!(verified_challenges, r);
    }

    /// Edge case `n = 0`: pure univariate skip, no hypercube rounds.
    #[test]
    fn sumcheck_prismalinear_round_trip_n0() {
        let mut rng = StdRng::seed_from_u64(42);
        let l_skip = 2usize;
        let evals = (0..1usize << l_skip).map(|_| f(rng.random())).collect_vec();
        let mut prover_transcript = default_duplex_sponge();
        let (proof, r) =
            sumcheck_prismalinear::<SC, F, DuplexSponge>(&mut prover_transcript, l_skip, &evals)
                .unwrap();
        assert_eq!(r.len(), 1);
        assert!(proof.round_polys_eval.is_empty());
        let verified_challenges =
            verified_prism_challenges(&proof, l_skip, &evals).expect("n=0 prism must verify");
        assert_eq!(verified_challenges, r);
    }

    #[test]
    fn sumcheck_prismalinear_rejects_tampering() {
        let mut rng = StdRng::seed_from_u64(41);
        let (l_skip, n) = (2usize, 3usize);
        let evals = (0..1usize << (l_skip + n))
            .map(|_| f(rng.random()))
            .collect_vec();
        let mut prover_transcript = default_duplex_sponge();
        let (proof, _r) =
            sumcheck_prismalinear::<SC, F, DuplexSponge>(&mut prover_transcript, l_skip, &evals)
                .unwrap();
        assert!(verify_prism_proof(&proof, l_skip, &evals).ok());

        // Tamper the round-0 univariate poly: rejected, and it trips the skip-domain `D`-sum check.
        let mut tampered = clone_prism_proof(&proof);
        tampered.s_0.coeffs_mut()[0] += EF::ONE;
        let verification = verify_prism_proof(&tampered, l_skip, &evals);
        assert!(
            !verification.ok() && !verification.domain_sum_ok,
            "tampered s_0 accepted"
        );

        // Tamper a hypercube round polynomial.
        let mut tampered = clone_prism_proof(&proof);
        tampered.round_polys_eval[0][0] += EF::ONE;
        assert!(
            !verify_prism_proof(&tampered, l_skip, &evals).ok(),
            "tampered round poly accepted"
        );

        // Tamper the sum claim.
        let mut tampered = clone_prism_proof(&proof);
        tampered.sum_claim += EF::ONE;
        let verification = verify_prism_proof(&tampered, l_skip, &evals);
        assert!(
            !verification.ok() && !verification.sum_claim_ok,
            "tampered sum_claim accepted"
        );

        // Tamper the final eval claim.
        let mut tampered = clone_prism_proof(&proof);
        tampered.eval_claim += EF::ONE;
        assert!(
            !verify_prism_proof(&tampered, l_skip, &evals).ok(),
            "tampered eval_claim accepted"
        );

        // Isolate `final_ok`: tamper a hypercube round poly (`r_0`/`folded` precede the hypercube
        // rounds and are unchanged), then patch `eval_claim` to the replayed oracle value so
        // `oracle_ok` passes — `final_ok` is the sole failure.
        let mut tampered = clone_prism_proof(&proof);
        tampered.round_polys_eval[1][0] += EF::ONE;
        let replayed = verify_prism_proof(&tampered, l_skip, &evals);
        tampered.eval_claim = replayed.oracle_eval;
        let patched = verify_prism_proof(&tampered, l_skip, &evals);
        assert!(
            patched.domain_sum_ok
                && patched.sum_claim_ok
                && patched.oracle_eval_ok
                && !patched.final_eval_ok,
            "final_ok not isolated: {patched:?}"
        );

        // Isolate `oracle_ok`: patch `eval_claim` to the replayed recursion result so `final_ok`
        // passes — `oracle_ok` is the sole failure.
        let mut tampered = clone_prism_proof(&proof);
        tampered.round_polys_eval[1][0] += EF::ONE;
        let replayed = verify_prism_proof(&tampered, l_skip, &evals);
        tampered.eval_claim = replayed.round_claim;
        let patched = verify_prism_proof(&tampered, l_skip, &evals);
        assert!(
            patched.domain_sum_ok
                && patched.sum_claim_ok
                && patched.final_eval_ok
                && !patched.oracle_eval_ok,
            "oracle_ok not isolated: {patched:?}"
        );
    }

    fn clone_prism_proof(p: &SumcheckPrismProof<EF>) -> SumcheckPrismProof<EF> {
        SumcheckPrismProof {
            sum_claim: p.sum_claim,
            s_0: UnivariatePoly::new(p.s_0.coeffs().to_vec()),
            round_polys_eval: p.round_polys_eval.clone(),
            eval_claim: p.eval_claim,
        }
    }
}
