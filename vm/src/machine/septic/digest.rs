//! Elliptic Curve digests with a starting point to avoid weierstrass addition exceptions.

use super::{config::*, SepticCurve, SepticExtension};
use p3_field::{Field, FieldAlgebra, FieldExtensionAlgebra};
use serde::{Deserialize, Serialize};
use std::iter::Sum;

/// A global cumulative sum digest, a point on the elliptic curve that `SepticCurve<F>` represents.
/// As these digests start with the `CURVE_CUMULATIVE_SUM_START` point, they require special summing logic.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct SepticDigest<F>(pub SepticCurve<F>);

impl<F: FieldAlgebra> SepticDigest<F> {
    #[must_use]
    /// The zero digest, the starting point of the accumulation of curve points derived from the scheme.
    pub fn zero() -> Self {
        SepticDigest(SepticCurve {
            x: SepticExtension::<F>::from_base_fn(|i| {
                F::from_canonical_u32(CURVE_CUMULATIVE_SUM_START_X[i])
            }),
            y: SepticExtension::<F>::from_base_fn(|i| {
                F::from_canonical_u32(CURVE_CUMULATIVE_SUM_START_Y[i])
            }),
        })
    }

    #[must_use]
    /// The digest used for starting the accumulation of digests.
    pub fn starting_digest() -> Self {
        SepticDigest(SepticCurve {
            x: SepticExtension::<F>::from_base_fn(|i| F::from_canonical_u32(DIGEST_SUM_START_X[i])),
            y: SepticExtension::<F>::from_base_fn(|i| F::from_canonical_u32(DIGEST_SUM_START_Y[i])),
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
