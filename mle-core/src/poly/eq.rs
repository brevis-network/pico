//! Equality / Möbius / rotation kernels on the hypercube and hyperprism.
//!
//! Two flavors of the hypercube `eq` kernel live here, disambiguated by suffix:
//! - [`evals_eq_hypercube_serial`] — single-threaded reference, used by the univariate
//!   ("sharp") kernels and verifier-facing code.
//! - [`evals_eq_hypercube_par`] — rayon-parallel, used by WHIR / stacked-PCS / LogUp.

use core::ops::Sub;
use std::{iter::zip, ops::Mul};

use itertools::Itertools;
use p3_field::{ExtensionField, Field, TwoAdicField};
use p3_maybe_rayon::prelude::*;
use p3_util::log2_strict_usize;

use super::univariate::{Squarable, UnivariatePoly};

pub fn eval_eq_mle<F1, F2, F3>(x: &[F1], y: &[F2]) -> F3
where
    F1: Field,
    F2: Field,
    F3: Field,
    F1: Mul<F2, Output = F3>,
    F3: Sub<F1, Output = F3>,
    F3: Sub<F2, Output = F3>,
{
    debug_assert_eq!(x.len(), y.len());
    zip(x, y).fold(F3::ONE, |acc, (&x_i, &y_i)| {
        acc * (F3::ONE - y_i - x_i + (x_i * y_i).double())
    })
}

/// Evaluate `mobius_eq_poly(u_tilde)` at an arbitrary point `x`.
///
/// ```text
/// mobius_eq_poly(u_tilde)(x) = ∏_i ((1 - 2*u_tilde_i) * (1 - x_i) + u_tilde_i * x_i)
/// ```
pub fn eval_mobius_eq_mle<F: Field>(u: &[F], x: &[F]) -> F {
    debug_assert_eq!(u.len(), x.len());
    zip(u, x).fold(F::ONE, |acc, (&u_i, &x_i)| {
        let w0 = F::ONE - u_i.double();
        acc * (w0 * (F::ONE - x_i) + u_i * x_i)
    })
}

/// Evaluate the MLE defined by its hypercube evaluations at an arbitrary point, in place.
///
/// `evals` has length `2^n` and contains `f(b)` for each `b ∈ {0,1}^n`.
/// Returns `f(x)` where `x = x[0..n]`.
pub fn eval_mle_evals_at_point<F: Field>(evals: &mut [F], x: &[F]) -> F {
    debug_assert_eq!(evals.len(), 1 << x.len());
    let mut len = evals.len();
    for &xj in x.iter().rev() {
        len >>= 1;
        let (lo, hi) = evals.split_at_mut(len);
        for i in 0..len {
            lo[i] = lo[i] * (F::ONE - xj) + hi[i] * xj;
        }
    }
    evals[0]
}

/// Let D be univariate skip domain, the subgroup of `F^*` of order `l_skip`.
///
/// Computes the polynomial ```text
///     eq_D(X, Y) = \sum_{z_1 \in D} \prod_{z_2 \in D, z_2 != z_1} (X - z_1)(Y - z_2) / (z_1 -
/// z_2)^2 ```
pub fn eval_eq_uni<F: Field>(l_skip: usize, x: F, y: F) -> F {
    let mut res = F::ONE;
    for (x_pow, y_pow) in zip(x.exp_powers_of_2(), y.exp_powers_of_2()).take(l_skip) {
        res = (x_pow + y_pow) * res + (x_pow - F::ONE) * (y_pow - F::ONE);
    }
    res * F::ONE.halve().exp_u64(l_skip as u64)
}

/// Let D be univariate skip domain, the subgroup of `F^*` of order `l_skip`.
///
/// Computes the polynomial eq_D(X, 1); see `eval_eq_uni`.
pub fn eval_eq_uni_at_one<F: Field>(l_skip: usize, x: F) -> F {
    let mut res = F::ONE;
    for x_pow in x.exp_powers_of_2().take(l_skip) {
        res *= x_pow + F::ONE;
    }
    res * F::ONE.halve().exp_u64(l_skip as u64)
}

/// Returns `eq_D(x, Z)` as a polynomial in `Z` in coefficient form.
/// Derived from `eq_D(x, Z)` being the Lagrange basis at `x`, which is the character sum over the
/// roots of unity.
///
/// If z in D, then `eq_D(x, z) = 1/N sum_{k=1}^N (x/z)^k = 1/N sum_{k=1}^N x^k
/// z^{N-k}`.
pub fn eq_uni_poly<F, EF>(l_skip: usize, x: EF) -> UnivariatePoly<EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    let n_inv = F::ONE.halve().exp_u64(l_skip as u64);
    let mut coeffs = x
        .powers()
        .skip(1)
        .take(1 << l_skip)
        .map(|x_pow| x_pow * n_inv)
        .collect_vec();
    coeffs.reverse();
    coeffs[0] = n_inv.into();
    UnivariatePoly::new(coeffs)
}

pub fn eval_in_uni<F: Field>(l_skip: usize, n: isize, z: F) -> F {
    debug_assert!(n >= -(l_skip as isize));
    if n.is_negative() {
        eval_eq_uni_at_one(
            n.unsigned_abs(),
            z.exp_power_of_2(l_skip.wrapping_add_signed(n)),
        )
    } else {
        F::ONE
    }
}

pub fn eval_eq_prism<F: Field>(l_skip: usize, x: &[F], y: &[F]) -> F {
    eval_eq_uni(l_skip, x[0], y[0]) * eval_eq_mle(&x[1..], &y[1..])
}

pub fn evals_eq_hypercube_serial<F: Field>(x: &[F]) -> Vec<F> {
    let n = x.len();
    let mut out = F::zero_vec(1 << n);
    fill_eq_hypercube_evals_serial(&mut out, x);
    out
}

/// Length of `xi_1` should be `l_skip`.
pub fn eval_eq_sharp_uni<F, EF>(omega_skip_pows: &[F], xi_1: &[EF], z: EF) -> EF
where
    F: Field,
    EF: ExtensionField<F>,
{
    let l_skip = xi_1.len();
    debug_assert_eq!(omega_skip_pows.len(), 1 << l_skip);

    let mut res = EF::ZERO;
    let eq_xi_evals = evals_eq_hypercube_serial(xi_1);
    for (&omega_pow, eq_xi_eval) in omega_skip_pows.iter().zip(eq_xi_evals) {
        res += eval_eq_uni(l_skip, z, omega_pow.into()) * eq_xi_eval;
    }
    #[cfg(debug_assertions)]
    {
        let coeffs = (0..(1 << l_skip))
            .map(|k| {
                let mut c = EF::ONE;
                #[allow(clippy::needless_range_loop)]
                for i in 0..l_skip {
                    let idx = (k << i) % (1 << l_skip);
                    c *= EF::ONE - xi_1[i]
                        + xi_1[i] * omega_skip_pows[((1 << l_skip) - idx) % (1 << l_skip)];
                }
                c
            })
            .collect_vec();
        let mut rpow = EF::ONE;
        let mut other = EF::ZERO;
        for c in coeffs {
            other += rpow * c;
            rpow *= z;
        }
        other *= EF::TWO.inverse().exp_u64(l_skip as u64);
        debug_assert_eq!(other, res);
    }
    res
}

/// `\kappa_\rot(x, y)` should equal `\delta_{x,rot(y)}` on the hyperprism.
pub fn eval_rot_kernel_prism<F: TwoAdicField>(l_skip: usize, x: &[F], y: &[F]) -> F {
    let omega = F::two_adic_generator(l_skip);

    let (eq_cube, rot_cube) = eval_eq_rot_cube(&x[1..], &y[1..]);
    // If not at boundary of D, just rotate in D, don't change cube coordinates. Otherwise at
    // boundary, rotate the cube
    eval_eq_uni(l_skip, x[0], y[0] * omega) * eq_cube
        + eval_eq_uni_at_one(l_skip, x[0])
            * eval_eq_uni_at_one(l_skip, y[0] * omega)
            * (rot_cube - eq_cube)
}

/// MLE of cyclic rotation kernel on hypercube
pub fn eval_eq_rot_cube<F: Field>(x: &[F], y: &[F]) -> (F, F) {
    let n = x.len();
    debug_assert_eq!(n, y.len());
    // Recursive formula: rot(x, y) = x[0] * (1 - y[0]) * eq(x[1..], y[1..]) + (1 - x[0]) y[0] *
    // rot(x[1..], y[1..])
    let mut rot = F::ONE;
    let mut eq = F::ONE;
    for i in (0..n).rev() {
        rot = x[i] * (F::ONE - y[i]) * eq + (F::ONE - x[i]) * y[i] * rot;
        eq *= x[i] * y[i] + (F::ONE - x[i]) * (F::ONE - y[i]);
    }
    (eq, rot)
}

/// Given vector `x` in `F^n`, populates `out` with `eq_n(x, y)` for `y` on hypercube `H_n`.
///
/// The multilinear equality polynomial is defined as:
/// ```text
///     eq(x, z) = \prod_{i=0}^{n-1} (x_i z_i + (1 - x_i)(1 - z_i)).
/// ```
/// Rayon-parallel; see [`evals_eq_hypercube_serial`] for the single-threaded reference.
// Reference: <https://github.com/Plonky3/Plonky3/blob/main/multilinear-util/src/eq.rs>
pub fn evals_eq_hypercube_par<F: Field>(x: &[F]) -> Vec<F> {
    let n = x.len();
    let mut out = F::zero_vec(1 << n);
    fill_eq_hypercube_evals(&mut out, x);
    out
}

/// Fill `out` with `scale * eq(x, y)` for every `y in H_n`.
///
/// Output ordering is little-endian in the hypercube coordinates: bit `i` corresponds to `x[i]`.
pub fn fill_scaled_eq_hypercube_evals<F: Field>(out: &mut [F], x: &[F], scale: F) {
    debug_assert_eq!(out.len(), 1 << x.len());
    out[0] = scale;
    for (i, &x_i) in x.iter().enumerate() {
        let one_minus_x = F::ONE - x_i;
        let step = 1usize << i;
        let active_len = 2usize << i;
        let (los, his) = out[..active_len].split_at_mut(step);
        if active_len >= 1024 {
            los.par_iter_mut()
                .zip(his.par_iter_mut())
                .for_each(|(lo, hi)| {
                    let prev = *lo;
                    *hi = prev * x_i;
                    *lo = prev * one_minus_x;
                });
        } else {
            for (lo, hi) in los.iter_mut().zip(his.iter_mut()) {
                let prev = *lo;
                *hi = prev * x_i;
                *lo = prev * one_minus_x;
            }
        }
    }
}

/// Fill `out` with `eq(x, y)` for every `y in H_n`.
pub fn fill_eq_hypercube_evals<F: Field>(out: &mut [F], x: &[F]) {
    fill_scaled_eq_hypercube_evals(out, x, F::ONE);
}

fn fill_eq_hypercube_evals_serial<F: Field>(out: &mut [F], x: &[F]) {
    debug_assert_eq!(out.len(), 1 << x.len());
    out[0] = F::ONE;
    for (i, &x_i) in x.iter().enumerate() {
        let (los, his) = out[..2 << i].split_at_mut(1 << i);
        for (lo, hi) in los.iter_mut().zip(his.iter_mut()) {
            *hi = *lo * x_i;
            *lo *= F::ONE - x_i;
        }
    }
}

/// Accumulate `w_evals += gamma * eq(point, -)` when `point` and `w_evals` are in the same field.
///
/// `scratch` is reused and may contain arbitrary prior contents.
pub fn accumulate_scaled_eq_hypercube_same_field<F: Field>(
    w_evals: &mut [F],
    point: &[F],
    gamma: F,
    scratch: &mut Vec<F>,
) {
    scratch.resize(w_evals.len(), F::ZERO);
    fill_scaled_eq_hypercube_evals(scratch, point, gamma);
    w_evals
        .par_iter_mut()
        .zip(scratch.par_iter())
        .for_each(|(w, eq)| *w += *eq);
}

/// Accumulate `w_evals += gamma * eq(point, -)` for a base-field point and extension accumulator.
///
/// `scratch` stores base-field equality evaluations so the hot loop uses `EF * F`, not `EF * EF`.
pub fn accumulate_scaled_eq_hypercube_base_field<F, EF>(
    w_evals: &mut [EF],
    point: &[F],
    gamma: EF,
    scratch: &mut Vec<F>,
) where
    F: Field,
    EF: ExtensionField<F>,
{
    scratch.resize(w_evals.len(), F::ZERO);
    fill_eq_hypercube_evals(scratch, point);
    w_evals
        .par_iter_mut()
        .zip(scratch.par_iter())
        .for_each(|(w, eq)| *w += gamma * *eq);
}

/// Given vector `u_tilde` in `F^n`, populates `out` with `mobius_eq_kernel(u_tilde, b)` for
/// `b` on hypercube `H_n`.
///
/// For boolean `b_i ∈ {0,1}` the per-coordinate kernel is:
/// - `K_i(0) = 1 - 2 * u_tilde_i`
/// - `K_i(1) = u_tilde_i`
///
/// The output ordering matches [`evals_eq_hypercube_par`]: mask bit `i` corresponds to `u_tilde[i]`.
pub fn evals_mobius_eq_hypercube<F: Field>(u_tilde: &[F]) -> Vec<F> {
    let n = u_tilde.len();
    let mut out = F::zero_vec(1 << n);
    out[0] = F::ONE;
    for (i, &u_i) in u_tilde.iter().enumerate() {
        let w0 = F::ONE - u_i.double();
        let w1 = u_i;
        let (los, his) = out[..2 << i].split_at_mut(1 << i);
        los.par_iter_mut()
            .zip(his.par_iter_mut())
            .for_each(|(lo, hi)| {
                let prev = *lo;
                *hi = prev * w1;
                *lo = prev * w0;
            })
    }
    out
}

/// Given vector `x` in `F^n`, returns a concatenation of `evals_eq_hypercube_par(x[..n])` for all
/// valid `n` in order. Also, the order of masks is of different endianness.
pub fn evals_eq_hypercubes<'a, F: Field>(n: usize, x: impl IntoIterator<Item = &'a F>) -> Vec<F> {
    let mut out = F::zero_vec((2 << n) - 1);
    out[0] = F::ONE;
    for (i, &x_i) in x.into_iter().enumerate() {
        for y in 0..(1 << i) {
            out[(1 << (i + 1)) - 1 + (2 * y + 1)] = out[(1 << i) - 1 + y] * x_i;
            out[(1 << (i + 1)) - 1 + (2 * y)] = out[(1 << i) - 1 + y] * (F::ONE - x_i);
        }
    }
    out
}

/// Given vector `(z,x)` in `F^{n+1}`, populates `out` with `eq_{l_skip,n}(x, y)` for `y` on
/// hyperprism `D_n`.
pub fn evals_eq_hyperprism<F: TwoAdicField, EF: ExtensionField<F>>(
    omega_pows: &[F],
    z: EF,
    x: &[EF],
) -> Vec<EF> {
    // Size of D
    let d_size = omega_pows.len();
    let l_skip = log2_strict_usize(d_size);
    let n = x.len();
    let mut out = EF::zero_vec(d_size << n);
    for (omega_pow, eq_uni) in zip(omega_pows, out.iter_mut()) {
        *eq_uni = eval_eq_uni(l_skip, z, EF::from(*omega_pow));
    }
    for (i, &x_i) in x.iter().enumerate() {
        for y in (0..d_size << i).rev() {
            let eq_prev = out[y];
            // Don't overwrite in y = 0 case
            out[y | (d_size << i)] = eq_prev * x_i;
            out[y] = eq_prev * (EF::ONE - x_i);
        }
    }
    out
}

pub fn eq_sharp_uni_poly<EF: TwoAdicField>(xi_1: &[EF]) -> UnivariatePoly<EF> {
    let evals = evals_eq_hypercube_serial(xi_1);
    UnivariatePoly::from_evals_idft(&evals)
}

#[cfg(test)]
mod tests {
    use std::iter::zip;

    use crate::config::koala_bear_poseidon2::*;
    use p3_field::PrimeCharacteristicRing;

    use super::{super::mle::Mle, *};
    use rand::{rngs::StdRng, RngExt, SeedableRng};

    #[test]
    fn test_eq_hypercube_par_serial_pointwise_agree() {
        let mut rng = StdRng::seed_from_u64(7);
        for n in 0..=8usize {
            let x: Vec<F> = (0..n).map(|_| F::from_u32(rng.random())).collect();
            let par = evals_eq_hypercube_par(&x);
            let serial = evals_eq_hypercube_serial(&x);
            assert_eq!(par, serial, "par vs serial, n={n}");
            // Each hypercube point equals the pointwise kernel `eval_eq_mle(x, y)`.
            for (mask, &v) in par.iter().enumerate() {
                let y: Vec<F> = (0..n)
                    .map(|i| {
                        if (mask >> i) & 1 == 1 {
                            F::ONE
                        } else {
                            F::ZERO
                        }
                    })
                    .collect();
                let expected: F = eval_eq_mle(&x, &y);
                assert_eq!(v, expected, "point {mask}, n={n}");
            }
        }
    }

    #[test]
    fn test_eval_in_uni() {
        let l = 3;
        let n = -2;
        let u_0 = F::from_u32(12345);
        let ind = eval_in_uni(l, n, u_0);
        let expected = (u_0.exp_power_of_2(l) - F::ONE)
            * (u_0.exp_power_of_2(l.wrapping_add_signed(n)) - F::ONE).inverse()
            * F::from_usize(1 << n.unsigned_abs()).inverse();
        assert_eq!(ind, expected);
    }

    #[test]
    fn test_evals_mobius_eq_hypercube_matches_naive() {
        let mut rng = StdRng::seed_from_u64(0);

        for n in 0..=10usize {
            let u_tilde = (0..n)
                .map(|_| F::from_u64(rng.random()))
                .collect::<Vec<_>>();
            let evals = evals_mobius_eq_hypercube(&u_tilde);
            assert_eq!(evals.len(), 1 << n);

            for (mask, &eval) in evals.iter().enumerate() {
                let mut expected = F::ONE;
                for (i, &w) in u_tilde.iter().enumerate() {
                    expected *= if (mask >> i) & 1 == 0 {
                        F::ONE - w.double()
                    } else {
                        w
                    };
                }
                assert_eq!(eval, expected);
            }
        }
    }

    #[test]
    fn test_fill_eq_hypercube_matches_vector_api() {
        let mut rng = StdRng::seed_from_u64(9);
        for n in 0..=10usize {
            let x = (0..n)
                .map(|_| F::from_u64(rng.random()))
                .collect::<Vec<_>>();
            let mut out = F::zero_vec(1 << n);
            fill_eq_hypercube_evals(&mut out, &x);
            assert_eq!(out, evals_eq_hypercube_serial(&x), "n={n}");
        }
    }

    #[test]
    fn test_accumulate_scaled_eq_same_field_matches_vector_api() {
        let mut rng = StdRng::seed_from_u64(10);
        for n in 0..=10usize {
            let x = (0..n)
                .map(|_| F::from_u64(rng.random()))
                .collect::<Vec<_>>();
            let gamma = F::from_u64(rng.random());
            let mut got = (0..(1usize << n))
                .map(|_| F::from_u64(rng.random()))
                .collect::<Vec<_>>();
            let mut expected = got.clone();
            let eq = evals_eq_hypercube_serial(&x);
            for (w, eq) in expected.iter_mut().zip(eq) {
                *w += gamma * eq;
            }

            let mut scratch = Vec::new();
            accumulate_scaled_eq_hypercube_same_field(&mut got, &x, gamma, &mut scratch);
            assert_eq!(got, expected, "n={n}");
            assert_eq!(scratch.len(), 1 << n);
        }
    }

    #[test]
    fn test_accumulate_scaled_eq_base_field_matches_vector_api() {
        let mut rng = StdRng::seed_from_u64(11);
        for n in 0..=10usize {
            let x = (0..n)
                .map(|_| F::from_u64(rng.random()))
                .collect::<Vec<_>>();
            let gamma = EF::from_u64(rng.random());
            let mut got = (0..(1usize << n))
                .map(|_| EF::from_u64(rng.random()))
                .collect::<Vec<_>>();
            let mut expected = got.clone();
            let eq = evals_eq_hypercube_serial(&x);
            for (w, eq) in expected.iter_mut().zip(eq) {
                *w += gamma * eq;
            }

            let mut scratch = Vec::new();
            accumulate_scaled_eq_hypercube_base_field(&mut got, &x, gamma, &mut scratch);
            assert_eq!(got, expected, "n={n}");
            assert_eq!(scratch.len(), 1 << n);
        }
    }

    #[test]
    fn test_decoder_kernel_identity() {
        let mut rng = StdRng::seed_from_u64(1);

        for m in 0..=10usize {
            let a = (0..(1usize << m))
                .map(|_| F::from_u64(rng.random()))
                .collect::<Vec<_>>();

            // RS coefficients under eval-to-coeff encoding are the hypercube evaluations of f.
            let mut rs_coeffs = a.clone();
            Mle::coeffs_to_evals_inplace(&mut rs_coeffs);

            // WHIR works with the associated MLE HatF whose coefficients are `rs_coeffs`.
            // We need HatF evaluations on the hypercube.
            let mut hatf_evals = rs_coeffs.clone();
            Mle::coeffs_to_evals_inplace(&mut hatf_evals);

            let u_tilde = (0..m)
                .map(|_| F::from_u64(rng.random()))
                .collect::<Vec<_>>();

            let mobius_eq_evals = evals_mobius_eq_hypercube(&u_tilde);
            let lhs = zip(&hatf_evals, &mobius_eq_evals).fold(F::ZERO, |acc, (&f, &g)| acc + f * g);

            // Naive evaluation of f(u_tilde) from its coefficient table.
            let rhs = a.iter().enumerate().fold(F::ZERO, |acc, (mask, &coeff)| {
                let mut term = coeff;
                for (i, &w) in u_tilde.iter().enumerate() {
                    if (mask >> i) & 1 == 1 {
                        term *= w;
                    }
                }
                acc + term
            });

            assert_eq!(lhs, rhs);
        }
    }
}
