//! Univariate polynomial ([`UnivariatePoly`]) in coefficient form: Horner eval, small fixed-point
//! Lagrange interpolation helpers, and the DFT-based interpolation routines (from evals / cosets).

use core::ops::{Add, Mul};
use std::iter::zip;

use itertools::Itertools;
use p3_dft::TwoAdicSubgroupDft;
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing, TwoAdicField};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_util::{log2_ceil_usize, log2_strict_usize};
use tracing::instrument;

use super::ntt::SerialRadix2Dft;
use crate::utils::batch_multiplicative_inverse_serial;

// Source: https://github.com/starkware-libs/stwo/blob/dev/crates/stwo/src/prover/lookups/utils.rs#L12
/// Univariate polynomial in coefficient form.
#[derive(Clone, Debug)]
pub struct UnivariatePoly<F>(pub(crate) Vec<F>);

impl<F> UnivariatePoly<F> {
    pub fn new(coeffs: Vec<F>) -> Self {
        Self(coeffs)
    }

    pub fn coeffs(&self) -> &[F] {
        &self.0
    }

    pub fn coeffs_mut(&mut self) -> &mut Vec<F> {
        &mut self.0
    }

    pub fn into_coeffs(self) -> Vec<F> {
        self.0
    }
}

impl<F: Field> UnivariatePoly<F> {
    pub fn eval_at_point<EF: ExtensionField<F>>(&self, x: EF) -> EF {
        horner_eval(&self.0, x)
    }
}

/// Evaluates univariate polynomial using [Horner's method].
///
/// [Horner's method]: https://en.wikipedia.org/wiki/Horner%27s_method
pub fn horner_eval<F1, F2, F3>(coeffs: &[F1], x: F2) -> F3
where
    F1: Field,
    F2: Field,
    F3: Field + Add<F1, Output = F3>,
    F3: Mul<F2, Output = F3>,
{
    coeffs.iter().rfold(F3::ZERO, |acc, coeff| acc * x + *coeff)
}

/// Interpolates a linear polynomial through points (0, evals[0]), (1, evals[1])
/// and evaluates it at x.
#[inline(always)]
pub fn interpolate_linear_at_01<F: Field>(evals: &[F; 2], x: F) -> F {
    let p = evals[1] - evals[0];
    p * x + evals[0]
}

/// Interpolates a quadratic polynomial through points (0, evals[0]), (1, evals[1]),
/// (2, evals[2])  and evaluates it at x.
#[inline(always)]
pub fn interpolate_quadratic_at_012<F: Field>(evals: &[F; 3], x: F) -> F {
    let s1 = evals[1] - evals[0];
    let s2 = evals[2] - evals[1];
    let p = (s2 - s1).halve();
    let q = s1 - p;
    (p * x + q) * x + evals[0]
}

/// Interpolates a cubic polynomial through points (0, evals[0]), (1, evals[1]),
/// (2, evals[2]), (3, evals[3]) and evaluates it at x.
#[inline(always)]
pub fn interpolate_cubic_at_0123<F: Field>(evals: &[F; 4], x: F) -> F {
    let inv6 = F::from_u64(6).inverse();

    let s1 = evals[1] - evals[0];
    let s2 = evals[2] - evals[0];
    let s3 = evals[3] - evals[0];

    let d3 = s3 - (s2 - s1) * F::from_u64(3);

    let p = d3 * inv6;
    let q = (s2 - d3).halve() - s1;
    let r = s1 - p - q;

    ((p * x + q) * x + r) * x + evals[0]
}

pub struct ExpPowers2<T> {
    current: Option<T>,
}

impl<T: Squarable + PrimeCharacteristicRing> Iterator for ExpPowers2<T> {
    type Item = T;
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(curr) = self.current.take() {
            let next = curr.square();
            self.current = Some(next);
            Some(curr)
        } else {
            None
        }
    }
}

pub trait Squarable: PrimeCharacteristicRing + Clone {
    #[inline]
    fn exp_powers_of_2(&self) -> ExpPowers2<Self> {
        ExpPowers2 {
            current: Some(self.clone()),
        }
    }
}

impl<T: PrimeCharacteristicRing + Clone> Squarable for T {}

impl<F: Field> UnivariatePoly<F> {
    #[instrument(level = "debug", skip_all)]
    pub fn lagrange_interpolate<BF: Field>(points: &[BF], evals: &[F]) -> Self
    where
        F: ExtensionField<BF>,
    {
        assert_eq!(points.len(), evals.len());
        let len = points.len();

        // Special case: empty or single evaluation
        if len == 0 {
            return Self(vec![]);
        }
        if len == 1 {
            return Self(vec![evals[0]]);
        }

        // Lagrange interpolation algorithm
        // P(x) = sum_{i=0}^{len-1} evals[i] * L_i(x)
        // where L_i(x) = prod_{j != i} (x - points[j]) / (points[i] - points[j])

        // Step 1: Compute all denominators (points[i] - points[j]) for i != j
        let mut denominators = Vec::with_capacity(len * (len - 1));
        for i in 0..len {
            for j in 0..len {
                if i != j {
                    denominators.push(points[i] - points[j]);
                }
            }
        }

        // Step 2: Batch invert all denominators
        let inv_denominators = batch_multiplicative_inverse_serial(&denominators);

        // Step 3: Build coefficient form by accumulating Lagrange basis polynomials
        let mut coeffs = vec![F::ZERO; len];

        // Reusable workspace for Lagrange polynomial computation
        let mut lagrange_poly = Vec::with_capacity(len);

        #[allow(clippy::needless_range_loop)]
        for i in 0..len {
            // Skip if evaluation is zero (optimization)
            if evals[i] == F::ZERO {
                continue;
            }

            // Build L_i(x) in coefficient form using polynomial multiplication
            // L_i(x) = prod_{j != i} (x - points[j]) / (points[i] - points[j])

            // Start with constant polynomial 1
            lagrange_poly.clear();
            lagrange_poly.push(F::ONE);

            // Get the precomputed inverse denominators for this i
            let inv_denom_start = i * (len - 1);
            let mut inv_idx = 0;

            // Multiply by (x - points[j]) / (points[i] - points[j]) for each j != i
            #[allow(clippy::needless_range_loop)]
            for j in 0..len {
                if i != j {
                    let scale = inv_denominators[inv_denom_start + inv_idx];
                    inv_idx += 1;

                    // Multiply lagrange_poly by (x - points[j]) * scale in place
                    // This is equivalent to: lagrange_poly * (x - points[j]) * scale
                    // = lagrange_poly * x * scale - lagrange_poly * points[j] * scale

                    lagrange_poly.push(F::ZERO); // Extend by one for the new highest degree term
                    for k in (1..lagrange_poly.len()).rev() {
                        let prev_coeff = lagrange_poly[k - 1] * scale;
                        lagrange_poly[k] += prev_coeff;
                        lagrange_poly[k - 1] = -prev_coeff * points[j];
                    }
                }
            }

            // Add evals[i] * L_i(x) to the result
            for (k, &coeff) in lagrange_poly.iter().enumerate() {
                coeffs[k] += evals[i] * coeff;
            }
        }

        Self(coeffs)
    }
}

impl<F: TwoAdicField> UnivariatePoly<F> {
    /// Computes P(1), P(omega), ..., P(omega^{n-1}).
    fn chirp_z(poly: &[F], omega: F, n: usize) -> Vec<F> {
        if n == 0 {
            return Vec::new();
        }
        if poly.is_empty() {
            return vec![F::ZERO; n];
        }
        let s = poly.len() + n;
        let omega_powers = (0..(s as u64))
            .map(|i| omega.exp_u64(i * (i.saturating_sub(1)) / 2))
            .collect_vec();
        let omega_powers_inv = batch_multiplicative_inverse_serial(&omega_powers);
        let mut p = zip(poly, &omega_powers_inv)
            .map(|(&c, &inv)| c * inv)
            .collect_vec();
        let mut q = omega_powers.iter().rev().copied().collect_vec();

        let dft_deg = (p.len() + q.len() - 1).next_power_of_two();
        p.resize(dft_deg, F::ZERO);
        q.resize(dft_deg, F::ZERO);
        let dft = SerialRadix2Dft;
        p = dft.dft(p);
        q = dft.dft(q);
        for (x, y) in p.iter_mut().zip(q.iter()) {
            *x *= *y;
        }
        p = dft.idft(p);
        zip(p.into_iter().skip(n).take(n).rev(), omega_powers_inv)
            .map(|(x, inv)| x * inv)
            .collect()
    }

    /// Given z and n, find product (1 - x)(1 - zx)...(1 - z^{n-1}x).
    /// If n is odd, this can be trivially computed from n - 1.
    /// Otherwise, F_n(x) = F_{n/2}(x) * F_{n/2}(x * z^{n/2}).
    fn geometric_sequence_linear_product_helper(dft: &SerialRadix2Dft, z: F, n: usize) -> Vec<F> {
        if n == 1 {
            vec![F::ONE, F::NEG_ONE]
        } else if n % 2 == 1 {
            let mut prev = Self::geometric_sequence_linear_product_helper(dft, z, n - 1);
            let zp = z.exp_u64((n - 1) as u64);
            prev.push(F::ZERO);
            for i in (1..prev.len()).rev() {
                let value = prev[i - 1] * zp;
                prev[i] -= value;
            }
            prev
        } else {
            let mut prev = Self::geometric_sequence_linear_product_helper(dft, z, n / 2);
            let zp = z.exp_u64((n / 2) as u64);
            let mut another = prev
                .iter()
                .zip(zp.powers())
                .map(|(a, b)| *a * b)
                .collect_vec();
            let len = prev.len().next_power_of_two() * 2;
            prev.resize(len, F::ZERO);
            another.resize(len, F::ZERO);
            prev = dft.dft(prev);
            another = dft.dft(another);
            for (x, y) in prev.iter_mut().zip(another) {
                *x *= y;
            }
            prev = dft.idft(prev);
            prev.truncate(n + 1);
            prev
        }
    }

    /// Constructs the polynomial in coefficient form from its evaluations on
    /// `{omega^0,...,omega^d}` where `d` is the degree of the polynomial. Here `omega` is a
    /// (fixed) generator of the two-adic subgroup of order `(d+1).next_power_of_two()`.
    #[instrument(level = "debug", skip_all)]
    pub fn from_evals(evals: &[F]) -> Self {
        let n = evals.len();
        let log_n = log2_ceil_usize(n);
        let omega = F::two_adic_generator(log_n);
        let omega_pows = omega.powers().take((1 << log_n) + 1).collect_vec();
        if n == 0 {
            return Self(Vec::new());
        }
        if n == 1 {
            return Self(vec![evals[0]]);
        }

        // We know that, by Lagrange interpolation,
        // P(x) = \sum_i evals[i] * \prod_{j\neq i} (x - omega^j) / (omega^i - omega^j).
        // Let y[i] = evals[i] / (omega^{(n-1) * i} * prod_{j < n - 1 - i}(1 - omega^j) * prod_{j <
        // i}(1 - omega^{-j})). Then P(x) = \sum_i y[i] * \prod_{j\neq i} (x - omega^j).

        let mut positive_denoms = vec![F::ONE; n];
        let mut negative_denoms = vec![F::ONE; n];
        for i in 0..(n - 1) {
            positive_denoms[i + 1] = positive_denoms[i] / (F::ONE - omega_pows[i + 1]);
            negative_denoms[i + 1] =
                negative_denoms[i] / (F::ONE - omega_pows[(1 << log_n) - 1 - i]);
        }
        let omega_inv = omega_pows[(1 << log_n) - 1];
        let y = (0..n)
            .map(|i| {
                evals[i]
                    * omega_inv.exp_u64(((n - 1) * i) as u64)
                    * negative_denoms[i]
                    * positive_denoms[n - 1 - i]
            })
            .collect_vec();

        // If we reverse both P and replace all (x - a) with (1 - ax), we'll still have an equality.
        // So from now we assume that P(x) = \sum_i y[i] * \prod_{j\neq i} (1 - omega^j * x).
        // If we divide everything by Q(x) = \prod_i (1 - omega^i * x), then we'll have
        // P(x) / Q(x) = \sum_i y[i] / (1 - omega^i * x).

        // We want to find the first n coefficients of the right-hand side.
        // [x^k](\sum_i y[i] / (1 - x * omega^i)) = \sum_i y[i] / (omega^{ik}) = Y(omega^k).

        let mut rhs = Self::chirp_z(&y, omega, n);

        // Now we need the denominator in the left-hand side.
        let dft = SerialRadix2Dft;
        let mut denom = Self::geometric_sequence_linear_product_helper(&dft, omega, n);

        let len = (denom.len() + rhs.len() - 1).next_power_of_two();
        denom.resize(len, F::ZERO);
        rhs.resize(len, F::ZERO);
        denom = dft.dft(denom);
        rhs = dft.dft(rhs);
        let res = denom.into_iter().zip(rhs).map(|(a, b)| a * b).collect_vec();
        let mut res = dft.idft(res);
        res.truncate(n);
        // Remember that P(x) is reversed
        res.reverse();
        Self(res)
    }

    /// Constructs the polynomial in coefficient form from its evaluations on a smooth subgroup of
    /// `F^*` by performing inverse DFT.
    ///
    /// Requires that `evals.len()` is a power of 2.
    pub fn from_evals_idft(evals: &[F]) -> Self {
        // Use Bowers instead of DIT to avoid RefCell.
        let dft = SerialRadix2Dft;
        let coeffs = dft.idft(evals.to_vec());
        Self(coeffs)
    }

    /// Interpolates from evaluations on cosets `init * g^i D` for `i = 0,..,width-1` where `D` is
    /// a smooth subgroup of F.
    pub fn from_geometric_cosets_evals_idft<BF: Field>(
        evals: RowMajorMatrix<F>,
        shift: BF,
        init: BF,
    ) -> Self
    where
        F: ExtensionField<BF>,
    {
        let height = Matrix::height(&evals);
        let width = Matrix::width(&evals);
        if height == 0 || width == 0 {
            return Self(Vec::new());
        }

        let log_height = log2_strict_usize(height);
        let dft = SerialRadix2Dft;

        // First interpolate within each coset (size `height`) to get the remainder
        // modulo `X^height - shift^height`, then unshift coefficients by `(init * shift^i)^{-t}`.
        let mut coeffs_mat = dft.idft_batch(evals);
        let shift_inv = shift.inverse();
        let init_inv = init.inverse();
        // shift_invs[i] = (init * shift^i)^{-1} = init^{-1} * shift^{-i}
        let shift_invs = (0..width)
            .fold(
                (Vec::with_capacity(width), init_inv),
                |(mut acc, pow), _| {
                    acc.push(pow);
                    (acc, pow * shift_inv)
                },
            )
            .0;
        let mut shift_pows = vec![F::ONE; width];
        for row in coeffs_mat.rows_mut() {
            for (col, value) in row.iter_mut().enumerate() {
                *value *= shift_pows[col];
                shift_pows[col] *= shift_invs[col];
            }
        }

        // Interpolate across cosets for each coefficient degree.
        // Points are init^height, init^height * shift^height, ..., init^height *
        // shift^{(width-1)*height}
        let coset_base = shift.exp_power_of_2(log_height);
        let init_base = init.exp_power_of_2(log_height);
        let lagrange_basis = lagrange_basis_from_geometric_points(coset_base, width, init_base);
        let mut coeffs = vec![F::ZERO; height * width];
        for (row_idx, row_vals) in coeffs_mat.row_slices().enumerate() {
            let mut poly_coeffs = vec![F::ZERO; width];
            for (i, &value) in row_vals.iter().enumerate() {
                if value == F::ZERO {
                    continue;
                }
                for (k, basis_coeff) in lagrange_basis[i].iter().enumerate() {
                    poly_coeffs[k] += value * *basis_coeff;
                }
            }
            for (coset_idx, coeff) in poly_coeffs.into_iter().enumerate() {
                coeffs[coset_idx * height + row_idx] = coeff;
            }
        }
        Self(coeffs)
    }
}

/// Precompute Lagrange basis polynomials for interpolation at `init * base^i` for i=0..width-1.
fn lagrange_basis_from_geometric_points<F: Field>(base: F, width: usize, init: F) -> Vec<Vec<F>> {
    if width == 0 {
        return Vec::new();
    }
    if width == 1 {
        return vec![vec![F::ONE]];
    }

    // Points are init, init * base, init * base^2, ..., init * base^{width-1}
    let points = (0..width)
        .fold((Vec::with_capacity(width), init), |(mut acc, pow), _| {
            acc.push(pow);
            (acc, pow * base)
        })
        .0;

    // Build the monic polynomial P(x) = ∏(x - points[i]).
    let mut root_poly = vec![F::ONE];
    for &x in &points {
        root_poly.push(F::ZERO);
        for k in (1..root_poly.len()).rev() {
            let prev = root_poly[k - 1];
            root_poly[k] = prev - x * root_poly[k];
        }
        root_poly[0] = -x * root_poly[0];
    }

    // Precompute products of (1 - base^k) for k=1..width-1.
    let mut prefix = vec![F::ONE; width];
    for (i, base_pow) in base.powers().skip(1).take(width - 1).enumerate() {
        prefix[i + 1] = prefix[i] * (F::ONE - base_pow);
    }

    // Compute P(x)/(x - points[i]) for each i and scale by the inverse denominator.
    let mut quotients = Vec::with_capacity(width);
    for (i, &x) in points.iter().enumerate() {
        let mut q = vec![F::ZERO; width];
        q[width - 1] = root_poly[width];
        for k in (0..width - 1).rev() {
            q[k] = root_poly[k + 1] + x * q[k + 1];
        }

        // Denominator is prod_{j != i} (points[i] - points[j])
        // = prod_{j != i} (init * base^i - init * base^j)
        // = init^{width-1} * base^{i*(width-1)} * prod_{j != i} (1 - base^{j-i})
        // = init^{width-1} * base^{i*(width-1)} * prod_{k=1}^{i} (1 - base^{-k}) *
        // prod_{k=1}^{width-1-i} (1 - base^k) For k=1..i: (1 - base^{-k}) = -base^{-k} * (1
        // - base^k) So prod_{k=1}^{i} (1 - base^{-k}) = (-1)^i * base^{-i*(i+1)/2} *
        // prefix[i]
        let sign = if i % 2 == 0 { F::ONE } else { F::NEG_ONE };
        let exp = i * (width - 1) - (i * (i + 1) / 2);
        let pow = base.exp_u64(exp as u64);
        let init_pow = init.exp_u64((width - 1) as u64);
        let denom = sign * init_pow * pow * prefix[i] * prefix[width - 1 - i];
        let inv_denom = denom.inverse();
        for coeff in q.iter_mut() {
            *coeff *= inv_denom;
        }
        quotients.push(q);
    }
    quotients
}

#[cfg(test)]
mod tests {
    use std::iter::zip;

    use crate::config::koala_bear_poseidon2::*;
    use itertools::Itertools;
    use p3_field::{PrimeCharacteristicRing, TwoAdicField};
    use p3_util::{log2_ceil_usize, log2_strict_usize};
    use rand::{rngs::StdRng, RngExt, SeedableRng};

    use super::*;
    use crate::poly::ntt::SerialRadix2Dft;
    use p3_dft::TwoAdicSubgroupDft;

    #[test]
    fn test_interpolate_linear() {
        let evals = [
            EF::from_u64(20), // s(0)
            EF::from_u64(10), // s(1)
        ];

        assert_eq!(interpolate_linear_at_01(&evals, EF::ZERO), evals[0]);
        assert_eq!(interpolate_linear_at_01(&evals, EF::ONE), evals[1]);
    }

    #[test]
    fn test_interpolate_quadratic() {
        let evals = [
            EF::from_u64(20), // s(0)
            EF::from_u64(10), // s(1)
            EF::from_u64(18), // s(2)
        ];

        assert_eq!(interpolate_quadratic_at_012(&evals, EF::ZERO), evals[0]);
        assert_eq!(interpolate_quadratic_at_012(&evals, EF::ONE), evals[1]);
        assert_eq!(
            interpolate_quadratic_at_012(&evals, EF::from_u64(2)),
            evals[2]
        );
    }

    #[test]
    fn test_interpolate_cubic() {
        let evals = [
            EF::from_u64(20), // s(0)
            EF::from_u64(10), // s(1)
            EF::from_u64(18), // s(2)
            EF::from_u64(28), // s(3)
        ];

        assert_eq!(interpolate_cubic_at_0123(&evals, EF::ZERO), evals[0]);
        assert_eq!(interpolate_cubic_at_0123(&evals, EF::ONE), evals[1]);
        assert_eq!(interpolate_cubic_at_0123(&evals, EF::from_u64(2)), evals[2]);
        assert_eq!(interpolate_cubic_at_0123(&evals, EF::from_u64(3)), evals[3]);
    }

    #[test]
    fn test_exp_powers_of_2() {
        let x = F::from_u32(3);
        let s = x.exp_powers_of_2().take(3).collect_vec();
        assert_eq!(s, vec![x, x * x, x * x * x * x],);
    }

    /// `from_evals_idft` inverts a DFT: coeffs -> dft -> from_evals_idft -> coeffs.
    #[test]
    fn test_from_evals_idft_round_trip() {
        let mut rng = StdRng::seed_from_u64(5);
        let dft = SerialRadix2Dft;
        for log_n in 0..=6usize {
            let coeffs: Vec<F> = (0..(1usize << log_n))
                .map(|_| F::from_u32(rng.random()))
                .collect();
            let evals = dft.dft(coeffs.clone());
            let poly = UnivariatePoly::from_evals_idft(&evals);
            assert_eq!(poly.into_coeffs(), coeffs, "log_n={log_n}");
        }
    }

    /// `UnivariatePoly::eval_at_point` (Horner) matches the naive power-sum evaluation.
    #[test]
    fn test_eval_at_point_matches_naive() {
        let mut rng = StdRng::seed_from_u64(6);
        for degree in 0..16usize {
            let coeffs: Vec<F> = (0..=degree).map(|_| F::from_u32(rng.random())).collect();
            let poly = UnivariatePoly::new(coeffs.clone());
            let x = F::from_u32(rng.random());
            let naive = {
                let mut acc = F::ZERO;
                let mut p = F::ONE;
                for &c in &coeffs {
                    acc += c * p;
                    p *= x;
                }
                acc
            };
            assert_eq!(poly.eval_at_point::<F>(x), naive, "degree={degree}");
        }
    }

    #[test]
    fn test_lagrange_interpolation_round_trip() {
        let mut rng = StdRng::seed_from_u64(0);
        // Test various polynomial degrees
        for degree in 0..8usize {
            let num_evals: usize = degree + 1;

            // Create random coefficients for a polynomial of given degree
            let mut original_coeffs = vec![];
            for _ in 0..num_evals {
                original_coeffs.push(F::from_u32(rng.random()));
            }

            // Generate evaluation points (powers of omega)
            let log_domain_size = log2_ceil_usize(num_evals);
            let omega = F::two_adic_generator(log_domain_size);

            // Evaluate polynomial at these points
            let mut evals = vec![];
            let points = omega.powers().take(num_evals).collect_vec();
            for &x in &points {
                evals.push(horner_eval(&original_coeffs, x));
            }

            // Reconstruct polynomial from evaluations using Lagrange interpolation
            let reconstructed_poly = UnivariatePoly::lagrange_interpolate(&points, &evals);

            // Verify coefficients match (up to the original degree)
            for (i, (coeff, reconstructed_coeff)) in
                zip(original_coeffs, reconstructed_poly.0).enumerate()
            {
                assert_eq!(
                    coeff, reconstructed_coeff,
                    "Coefficient mismatch at index {} for degree {} polynomial",
                    i, degree
                );
            }
        }
    }

    #[test]
    fn test_chirp_z() {
        let mut rng = StdRng::seed_from_u64(0);
        for degree in 0..8usize {
            let num_evals: usize = degree + 1;

            let mut original_coeffs = vec![];
            for _ in 0..num_evals {
                original_coeffs.push(F::from_u32(rng.random()));
            }

            let log_domain_size = log2_ceil_usize(num_evals);
            let omega = F::two_adic_generator(log_domain_size);

            let mut evals = vec![];
            let points = omega.powers().take(num_evals).collect_vec();
            for &x in &points {
                evals.push(horner_eval(&original_coeffs, x));
            }

            assert_eq!(
                evals,
                UnivariatePoly::chirp_z(&original_coeffs, omega, num_evals)
            );

            let reconstructed_poly = UnivariatePoly::from_evals(&evals);

            for (i, (coeff, reconstructed_coeff)) in
                zip(original_coeffs, reconstructed_poly.0).enumerate()
            {
                assert_eq!(
                    coeff, reconstructed_coeff,
                    "Coefficient mismatch at index {} for degree {} polynomial",
                    i, degree
                );
            }
        }
    }

    #[test]
    fn test_from_geometric_cosets_evals_idft_round_trip() {
        let mut rng = StdRng::seed_from_u64(0);
        let height = 8usize;
        let log_height = log2_strict_usize(height);
        let omega = F::two_adic_generator(log_height);

        let configs = [
            (F::GENERATOR, F::ONE),
            (F::two_adic_generator(log_height + 2), F::GENERATOR),
        ];

        for (shift, init) in configs {
            for width in 2..=4usize {
                let coeffs = (0..height * width)
                    .map(|_| F::from_u32(rng.random()))
                    .collect_vec();
                let coeffs_ref = &coeffs;

                // Evaluations on cosets init * shift^i * D for i = 0, ..., width - 1
                let evals: Vec<F> = (0..height)
                    .flat_map(|row| {
                        let omega_pow = omega.exp_u64(row as u64);
                        (0..width).map(move |col| {
                            let coset_shift = init * shift.exp_u64(col as u64);
                            horner_eval(coeffs_ref, coset_shift * omega_pow)
                        })
                    })
                    .collect_vec();

                let evals_mat = RowMajorMatrix::new(evals, width);
                let poly = UnivariatePoly::from_geometric_cosets_evals_idft(evals_mat, shift, init);
                assert_eq!(
                    poly.into_coeffs(),
                    coeffs,
                    "width {width} round-trip failed"
                );
            }
        }
    }
}
