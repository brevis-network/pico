//! Prismalinear extension polynomial ([`Ple`]) in coefficient form, plus the RS-message
//! eval-to-coeff encoding used by WHIR.
//!
//! The reference path uses upstream parallel `p3_dft::Radix2Bowers`; CPU hot paths may use the
//! cached-twiddle helper when they repeatedly transform chunks of the same size.

use getset::Getters;
use p3_dft::{Radix2Bowers, TwoAdicSubgroupDft};
use p3_field::{ExtensionField, TwoAdicField};
use p3_maybe_rayon::prelude::*;
use p3_util::log2_strict_usize;

use super::{mle::Mle, ntt::TwiddleDft};

/// Prismalinear extension polynomial, in coefficient form.
///
/// Depends on implicit univariate skip parameter `l_skip`.
/// Length of `coeffs` is `2^{l_skip + n}` where `n` is hypercube dimension.
/// Indexing is to decompose `i = i_0 + 2^{l_skip} * (i_1 + 2 * i_2 .. + 2^{n-1} * i_n)` and let
/// `coeffs[i]` be the coefficient of `Z^{i_0} X_1^{i_1} .. X_n^{i_n}`.
#[derive(Getters)]
pub struct Ple<F> {
    #[getset(get = "pub")]
    pub(crate) coeffs: Vec<F>,
}

impl<F: TwoAdicField> Ple<F> {
    /// Create PLE from evaluations on the hypercube with univariate skip.
    ///
    /// Takes evaluations at 2^{l_skip + n} points and converts them to coefficient form
    /// for a polynomial in n+1 variables: degree < 2^l_skip in the first variable,
    /// degree < 2 (linear) in the other n variables.
    ///
    /// The input `evals` should have length 2^{l_skip + n}.
    /// The evaluation at index i corresponds to:
    /// - bits 0 to l_skip-1: univariate point index
    /// - bits l_skip to l_skip+n-1: multilinear variable assignments
    pub fn from_evaluations(l_skip: usize, evals: &[F]) -> Self {
        let prism_dim = log2_strict_usize(evals.len());
        assert!(
            prism_dim >= l_skip,
            "Total variables must be at least l_skip"
        );
        // Go through coordinates Z, X_1, ..., X_n and interpolate each one
        // For first Z coordinate, we do parallel iDFT on each 2^l_skip sized chunk
        let mut buf: Vec<_> = evals
            .par_chunks_exact(1 << l_skip)
            .flat_map(|chunk| {
                let dft = Radix2Bowers;
                dft.idft(chunk.to_vec())
            })
            .collect();

        let n = prism_dim - l_skip;
        // Go through coordinates X_1, ..., X_n and interpolate each one from s(0), s(1) -> s(0) +
        // (s(1) - s(0)) X_i
        for i in 0..n {
            let step = 1usize << (l_skip + i);
            let span = step << 1;
            buf.par_chunks_exact_mut(span).for_each(|chunk| {
                let (first_half, second_half) = chunk.split_at_mut(step);
                first_half
                    .par_iter()
                    .zip(second_half.par_iter_mut())
                    .for_each(|(u, v)| {
                        *v -= *u;
                    });
            });
        }
        Self { coeffs: buf }
    }

    pub fn eval_at_point<EF: ExtensionField<F>>(&self, l_skip: usize, z: EF, x: &[EF]) -> EF {
        let n = x.len();
        debug_assert_eq!(l_skip + n, log2_strict_usize(self.coeffs.len()));
        let mut res = EF::ZERO;
        let mut z_pow = EF::ONE;
        for (i, coeff) in self.coeffs.iter().enumerate() {
            if i.trailing_zeros() >= l_skip as u32 {
                z_pow = EF::ONE;
            }
            let i_x = i >> l_skip;
            let mut term = z_pow * *coeff;
            for (j, x_j) in x.iter().enumerate() {
                if (i_x >> j) & 1 == 1 {
                    term *= *x_j;
                }
            }
            z_pow *= z;
            res += term;
        }
        res
    }

    pub fn into_coeffs(self) -> Vec<F> {
        self.coeffs
    }
}

/// Convert evaluations of a prismalinear polynomial on `D × {0,1}^n` into the RS coefficient
/// vector for **eval-to-coeff** encoding.
///
/// - `|D| = 2^l_skip`, and `evals` must be ordered so the lower `l_skip` bits of the index select
///   the point in `D`, and higher bits select the boolean assignment.
/// - The output ordering matches the same convention: `idx = z_mask + (1 << l_skip) * x_mask`.
///
/// This avoids computing full prismalinear monomial coefficients in the boolean variables (which
/// would later be re-zeta-transformed), by:
/// 1) Performing an iDFT in `Z` for each boolean assignment.
/// 2) Applying the subset-zeta transform only over the `Z`-mask bits.
pub fn eval_to_coeff_rs_message<F: TwoAdicField>(l_skip: usize, evals: &[F]) -> Vec<F> {
    assert!(!evals.is_empty(), "Evaluations cannot be empty");
    let prism_dim = log2_strict_usize(evals.len());
    assert!(
        prism_dim >= l_skip,
        "Total variables must be at least l_skip"
    );

    let chunk_len = 1usize << l_skip;
    let mut buf: Vec<_> = evals
        .par_chunks_exact(chunk_len)
        .flat_map(|chunk| {
            let dft = Radix2Bowers;
            dft.idft(chunk.to_vec())
        })
        .collect();

    // For each fixed boolean assignment, convert Z-monomial coefficients into hypercube
    // evaluations over the Z-bit variables.
    buf.par_chunks_exact_mut(chunk_len)
        .for_each(Mle::coeffs_to_evals_inplace);

    buf
}

/// Cached-twiddle variant of [`eval_to_coeff_rs_message`].
///
/// This is algebraically identical to the reference path, but reuses precomputed twiddles for the
/// fixed `Z`-chunk size `2^l_skip`. The input and output ordering are unchanged:
/// `idx = z_mask + (1 << l_skip) * x_mask`.
pub fn eval_to_coeff_rs_message_with_twiddles<F: TwoAdicField>(
    evals: &[F],
    twiddles: &TwiddleDft<F>,
) -> Vec<F> {
    assert!(!evals.is_empty(), "Evaluations cannot be empty");
    let chunk_len = twiddles.size();
    let l_skip = log2_strict_usize(chunk_len);
    let prism_dim = log2_strict_usize(evals.len());
    assert!(
        prism_dim >= l_skip,
        "Total variables must be at least l_skip"
    );

    let mut buf = evals.to_vec();

    // For each fixed boolean assignment, interpolate along D.
    for chunk in buf.chunks_exact_mut(chunk_len) {
        twiddles.idft_inplace(chunk);
    }

    // Convert Z-monomial coefficients into hypercube evaluations over the Z-bit variables.
    buf.par_chunks_exact_mut(chunk_len)
        .for_each(Mle::coeffs_to_evals_inplace);

    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::koala_bear_poseidon2::F;
    use p3_field::{PrimeCharacteristicRing, TwoAdicField};
    use rand::{rngs::StdRng, RngExt, SeedableRng};

    /// Sampling a random prismalinear polynomial on the `D × {0,1}^n` grid and feeding the
    /// evaluations back through `from_evaluations` recovers the original coefficients.
    #[test]
    fn from_evaluations_round_trip() {
        let mut rng = StdRng::seed_from_u64(0);
        for l_skip in 0..=3usize {
            for n in 0..=3usize {
                let len = 1usize << (l_skip + n);
                let coeffs: Vec<F> = (0..len).map(|_| F::from_u32(rng.random())).collect();
                let ple = Ple {
                    coeffs: coeffs.clone(),
                };
                let omega = F::two_adic_generator(l_skip);

                // Evaluations on D × {0,1}^n: low `l_skip` bits index the D point, high bits the
                // boolean assignment (matching `from_evaluations`'s ordering convention).
                let evals: Vec<F> = (0..len)
                    .map(|idx| {
                        let z_mask = idx & ((1 << l_skip) - 1);
                        let x_mask = idx >> l_skip;
                        let z = omega.exp_u64(z_mask as u64);
                        let x: Vec<F> = (0..n)
                            .map(|i| {
                                if (x_mask >> i) & 1 == 1 {
                                    F::ONE
                                } else {
                                    F::ZERO
                                }
                            })
                            .collect();
                        ple.eval_at_point(l_skip, z, &x)
                    })
                    .collect();

                let recovered = Ple::from_evaluations(l_skip, &evals);
                assert_eq!(recovered.coeffs, coeffs, "l_skip={l_skip}, n={n}");
            }
        }
    }

    /// The cached-twiddle eval-to-coeff path must match the reference `Radix2Bowers` path.
    #[test]
    fn eval_to_coeff_with_twiddles_matches_reference() {
        let mut rng = StdRng::seed_from_u64(3);
        for l_skip in 0..=4usize {
            for n in 0..=4usize {
                let len = 1usize << (l_skip + n);
                let evals: Vec<F> = (0..len).map(|_| F::from_u32(rng.random())).collect();
                let twiddles = TwiddleDft::new(l_skip);
                let got = eval_to_coeff_rs_message_with_twiddles(&evals, &twiddles);
                let expected = eval_to_coeff_rs_message(l_skip, &evals);
                assert_eq!(got, expected, "l_skip={l_skip}, n={n}");
            }
        }
    }
}
