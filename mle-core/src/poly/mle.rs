//! Multilinear extension polynomial ([`Mle`]) in coefficient form, plus the
//! evals<->coeffs hypercube transforms.

use core::ops::Mul;
use std::iter::zip;

use getset::Getters;
use p3_field::{ExtensionField, Field};
use p3_maybe_rayon::prelude::*;
use p3_util::log2_strict_usize;

/// Multilinear extension polynomial, in coefficient form.
///
/// Length of `coeffs` is `2^n` where `n` is hypercube dimension.
/// Indexing of `coeffs` is to use the little-endian encoding of integer index as the powers of
/// variables.
#[derive(Getters)]
pub struct Mle<F> {
    #[getset(get = "pub")]
    coeffs: Vec<F>,
}

impl<F: Field> Mle<F> {
    pub fn from_coeffs(coeffs: Vec<F>) -> Self {
        Self { coeffs }
    }

    /// Create MLE from evaluations on the hypercube.
    ///
    /// Takes evaluations of the polynomial at all points in {0,1}^n and converts
    /// them to coefficient form.
    ///
    /// The input `evals` should have length 2^n where n is the number of variables.
    /// The evaluation at index i corresponds to the point whose binary representation
    /// is i (with bit 0 being the least significant).
    pub fn from_evaluations(evals: &[F]) -> Self {
        assert!(!evals.is_empty(), "Evaluations cannot be empty");
        let mut coeffs = evals.to_vec();
        Self::evals_to_coeffs_inplace(&mut coeffs);
        Self { coeffs }
    }

    pub fn into_coeffs(self) -> Vec<F> {
        self.coeffs
    }

    /// Evaluate with `O(1)` extra memory via naive algorithm.
    ///
    /// Performs `N*log(N)/2` multiplications when `N = coeffs.len()` is a power of two.
    pub fn eval_at_point<F2: Field, EF: ExtensionField<F> + Mul<F2, Output = EF>>(
        &self,
        x: &[F2],
    ) -> EF {
        debug_assert_eq!(log2_strict_usize(self.coeffs.len()), x.len());
        let mut res = EF::ZERO;
        for (i, coeff) in self.coeffs.iter().enumerate() {
            let mut term = EF::from(*coeff);
            for (j, x_j) in x.iter().enumerate() {
                if (i >> j) & 1 == 1 {
                    term = term * *x_j;
                }
            }
            res += term;
        }
        res
    }

    /// Evaluate with `O(1)` extra memory but consuming `self`.
    ///
    /// Performs `N - 1` multiplications when `N = coeffs.len()`.
    pub fn eval_at_point_inplace<F2>(self, x: &[F2]) -> F
    where
        F2: Field,
        F: Mul<F2, Output = F>,
    {
        let mut buf = self.coeffs;
        debug_assert_eq!(buf.len(), 1 << x.len());
        let mut len = 1usize << x.len();
        // Assumes caller ensured buf[..len] is initialized with the current coefficients.
        for &xj in x.iter().rev() {
            len >>= 1;
            let (left, right) = buf.split_at_mut(len);
            for (li, &ri) in zip(left.iter_mut(), right.iter()) {
                *li += ri * xj;
            }
        }
        buf[0]
    }

    pub fn evals_to_coeffs_inplace(a: &mut [F]) {
        let n = log2_strict_usize(a.len());
        // Go through coordinates X_1, ..., X_n and interpolate each one from s(0), s(1) -> s(0) +
        // (s(1) - s(0)) X_i
        for log_step in 0..n {
            let step = 1usize << log_step;
            let span = step << 1;
            a.par_chunks_exact_mut(span).for_each(|chunk| {
                let (first_half, second_half) = chunk.split_at_mut(step);
                first_half
                    .par_iter()
                    .zip(second_half.par_iter_mut())
                    .for_each(|(u, v)| {
                        *v -= *u;
                    });
            });
        }
    }

    pub fn coeffs_to_evals_inplace(a: &mut [F]) {
        let n = log2_strict_usize(a.len());

        for b in 0..n {
            let step = 1usize << b;
            let span = step << 1;
            for i in (0..a.len()).step_by(span) {
                for j in 0..step {
                    let u = i + j;
                    let v = u + step;
                    a[v] += a[u];
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::koala_bear_poseidon2::F;
    use p3_field::PrimeCharacteristicRing;
    use rand::{rngs::StdRng, RngExt, SeedableRng};

    /// The O(N-1) consuming fold (`eval_at_point_inplace`) agrees with the naive O(N log N) eval.
    #[test]
    fn eval_inplace_fold_matches_naive() {
        let mut rng = StdRng::seed_from_u64(0);
        for n in 0..=8usize {
            let coeffs: Vec<F> = (0..(1usize << n))
                .map(|_| F::from_u32(rng.random()))
                .collect();
            let x: Vec<F> = (0..n).map(|_| F::from_u32(rng.random())).collect();
            let naive: F = Mle::from_coeffs(coeffs.clone()).eval_at_point::<F, F>(&x);
            let folded: F = Mle::from_coeffs(coeffs.clone()).eval_at_point_inplace(&x);
            assert_eq!(naive, folded, "n={n}");
        }
    }

    /// `evals_to_coeffs_inplace` and `coeffs_to_evals_inplace` are inverses.
    #[test]
    fn evals_coeffs_round_trip() {
        let mut rng = StdRng::seed_from_u64(1);
        for n in 0..=10usize {
            let orig: Vec<F> = (0..(1usize << n))
                .map(|_| F::from_u32(rng.random()))
                .collect();
            let mut a = orig.clone();
            Mle::evals_to_coeffs_inplace(&mut a);
            Mle::coeffs_to_evals_inplace(&mut a);
            assert_eq!(a, orig, "n={n}");
        }
    }

    /// Building an MLE from hypercube evaluations then evaluating at a boolean point returns the
    /// original evaluation (the "NTT + fold" commit-prep flow, end to end).
    #[test]
    fn from_evaluations_then_eval_at_boolean_points() {
        let mut rng = StdRng::seed_from_u64(2);
        for n in 0..=7usize {
            let evals: Vec<F> = (0..(1usize << n))
                .map(|_| F::from_u32(rng.random()))
                .collect();
            let mle = Mle::from_evaluations(&evals);
            for (mask, &e) in evals.iter().enumerate() {
                let x: Vec<F> = (0..n)
                    .map(|i| {
                        if (mask >> i) & 1 == 1 {
                            F::ONE
                        } else {
                            F::ZERO
                        }
                    })
                    .collect();
                let got: F = mle.eval_at_point::<F, F>(&x);
                assert_eq!(got, e, "n={n}, mask={mask}");
            }
        }
    }
}
