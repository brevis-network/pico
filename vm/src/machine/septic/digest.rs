//! Elliptic Curve digests with a starting point to avoid weierstrass addition exceptions.

use super::{FieldSepticCurve, SepticCurve, SepticExtension};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use serde::{Deserialize, Serialize};
use std::{any::Any, iter::Sum};

/// A global cumulative sum digest, a point on the elliptic curve that `SepticCurve<F>` represents.
/// As these digests start with the `CURVE_CUMULATIVE_SUM_START` point, they require special summing logic.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct SepticDigest<F>(pub SepticCurve<F>);

impl<F: PrimeCharacteristicRing + Any> SepticDigest<F> {
    #[must_use]
    /// The zero digest, the starting point of the accumulation of curve points derived from the scheme.
    pub fn zero() -> Self {
        // We could use below code to check the F type for `same_field` here.
        //
        // ``` ignore
        // let typ = std::any::type_name::<F>();
        // println!("Found type = {typ:?}");
        // ```

        SepticDigest(SepticCurve {
            x: SepticExtension::<F>::from_basis_coefficients_fn(|i| {
                F::from_u32(F::CURVE_CUMULATIVE_SUM_START_X[i])
            }),
            y: SepticExtension::<F>::from_basis_coefficients_fn(|i| {
                F::from_u32(F::CURVE_CUMULATIVE_SUM_START_Y[i])
            }),
        })
    }

    #[must_use]
    /// The digest used for starting the accumulation of digests.
    pub fn starting_digest() -> Self {
        SepticDigest(SepticCurve {
            x: SepticExtension::<F>::from_basis_coefficients_fn(|i| {
                F::from_u32(F::DIGEST_SUM_START_X[i])
            }),
            y: SepticExtension::<F>::from_basis_coefficients_fn(|i| {
                F::from_u32(F::DIGEST_SUM_START_Y[i])
            }),
        })
    }
}

impl<F: Field> SepticDigest<F> {
    /// Checks that the digest is zero, the starting point of the accumulation.
    pub fn is_zero(&self) -> bool {
        *self == SepticDigest::<F>::zero()
    }
}

impl<F: Field> Sum for SepticDigest<F> {
    fn sum<I: Iterator<Item = Self>>(mut iter: I) -> Self {
        match iter.size_hint() {
            (0, Some(0)) => Self::zero(),
            (1, Some(1)) => iter.next().unwrap(),
            _ => {
                let start = SepticDigest::<F>::starting_digest().0;

                // Computation order is start + (digest1 - offset) + (digest2 - offset) + ... + (digestN - offset) + offset - start.
                let mut ret = iter.fold(start, |acc, x| {
                    let sum_offset = acc.add_incomplete(x.0);
                    sum_offset.sub_incomplete(SepticDigest::<F>::zero().0)
                });

                ret.add_assign(SepticDigest::<F>::zero().0);
                ret.sub_assign(start);
                SepticDigest(ret)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SepticDigest;
    use crate::machine::septic::SepticCurve;
    use p3_field::PrimeCharacteristicRing;
    use p3_koala_bear::KoalaBear;

    /// Distinct valid curve points — `lift_x` is the only honest way to get them; hand-built
    /// coordinates would not lie on the curve and the group law would be meaningless.
    fn digests(n: usize) -> Vec<SepticDigest<KoalaBear>> {
        (0..n)
            .map(|i| {
                let m = std::array::from_fn(|j| KoalaBear::from_u32((i * 8 + j) as u32));
                SepticDigest(SepticCurve::lift_x(m).0)
            })
            .collect()
    }

    /// `Sum` is homomorphic over partitioning: summing partial sums equals summing every term.
    ///
    /// The two-machine path depends on exactly this: neither process's chunks sum
    /// to zero on their own — the secondary sends its partial and the primary adds it to its own —
    /// so if this did not hold, the cross-process memory-consistency check would be quietly wrong
    /// rather than loudly broken.
    ///
    /// It is not obvious from the type: there is no `Add` impl, and `Sum` folds each element as
    /// `(x - Z)` before adding a single `Z` back, so the property has to be checked rather than
    /// assumed from "addition is associative".
    #[test]
    fn sum_of_partial_sums_equals_sum_of_all() {
        let all = digests(6);

        let whole: SepticDigest<KoalaBear> = all.iter().copied().sum();

        for split in 0..=all.len() {
            let (a, b) = all.split_at(split);
            let left: SepticDigest<KoalaBear> = a.iter().copied().sum();
            let right: SepticDigest<KoalaBear> = b.iter().copied().sum();
            let combined: SepticDigest<KoalaBear> = [left, right].into_iter().sum();
            assert_eq!(
                combined, whole,
                "partial sums split at {split} did not recombine to the whole"
            );
        }
    }

    /// Three-way, since a run may have more than two machines and the reduction is written as one
    /// `sum` over a vector rather than a pairwise fold.
    #[test]
    fn sum_of_three_partials_equals_sum_of_all() {
        let all = digests(9);
        let whole: SepticDigest<KoalaBear> = all.iter().copied().sum();

        let parts: Vec<SepticDigest<KoalaBear>> = all
            .chunks(3)
            .map(|c| c.iter().copied().sum::<SepticDigest<KoalaBear>>())
            .collect();
        let combined: SepticDigest<KoalaBear> = parts.into_iter().sum();

        assert_eq!(combined, whole);
    }

    /// The empty partial is the identity — the case that actually occurs when one machine is
    /// assigned no chunks, which is precisely the starve-the-secondary bug PR 4 fixed.
    #[test]
    fn an_empty_partial_is_the_identity() {
        let all = digests(4);
        let whole: SepticDigest<KoalaBear> = all.iter().copied().sum();
        let empty: SepticDigest<KoalaBear> = std::iter::empty().sum();
        assert!(empty.is_zero(), "the empty sum must be the zero point");

        let combined: SepticDigest<KoalaBear> = [whole, empty].into_iter().sum();
        assert_eq!(combined, whole);
    }
}
