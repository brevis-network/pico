// TODO-Alan: refactor to use p3 BionmialExtensionField
use std::ops::{Add, Div, Mul, Neg, Sub};

use crate::primitives::consts::EXTENSION_DEGREE;
use p3_field::{
    extension::{BinomialExtensionField, BinomiallyExtendable},
    Field, FieldAlgebra, FieldExtensionAlgebra,
};
use pico_derive::AlignedBorrow;

/// A binomial extension element represented over a generic type `T`.
#[derive(AlignedBorrow, Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct BinomialExtension<T>(pub [T; EXTENSION_DEGREE]);

impl<T> BinomialExtension<T> {
    /// Creates a new binomial extension element from a base element.
    pub fn from_base(b: T) -> Self
    where
        T: FieldAlgebra,
    {
        let mut arr: [T; EXTENSION_DEGREE] = core::array::from_fn(|_| T::ZERO);
        arr[0] = b;
        Self(arr)
    }

    /// Returns a reference to the underlying slice.
    pub const fn as_base_slice(&self) -> &[T] {
        &self.0
    }

    /// Creates a new binomial extension element from a binomial extension element.
    #[allow(clippy::needless_pass_by_value)]
    pub fn from<S: Into<T> + Clone>(from: BinomialExtension<S>) -> Self {
        BinomialExtension(core::array::from_fn(|i| from.0[i].clone().into()))
    }
}

impl<T: Add<Output = T> + Clone> Add for BinomialExtension<T> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(core::array::from_fn(|i| {
            self.0[i].clone() + rhs.0[i].clone()
        }))
    }
}

impl<T: Sub<Output = T> + Clone> Sub for BinomialExtension<T> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(core::array::from_fn(|i| {
            self.0[i].clone() - rhs.0[i].clone()
        }))
    }
}

impl<T: Add<Output = T> + Mul<Output = T> + FieldAlgebra> Mul for BinomialExtension<T> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut result = [T::ZERO, T::ZERO, T::ZERO, T::ZERO];
        let w = T::from_canonical_u32(11);

        for i in 0..EXTENSION_DEGREE {
            for j in 0..EXTENSION_DEGREE {
                if i + j >= EXTENSION_DEGREE {
                    result[i + j - EXTENSION_DEGREE] +=
                        w.clone() * self.0[i].clone() * rhs.0[j].clone();
                } else {
                    result[i + j] += self.0[i].clone() * rhs.0[j].clone();
                }
            }
        }

        Self(result)
    }
}

impl<F> Div for BinomialExtension<F>
where
    F: BinomiallyExtendable<EXTENSION_DEGREE>,
{
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        let p3_ef_lhs = BinomialExtensionField::from_base_slice(&self.0);
        let p3_ef_rhs = BinomialExtensionField::from_base_slice(&rhs.0);
        let p3_ef_result = p3_ef_lhs / p3_ef_rhs;
        Self(p3_ef_result.as_base_slice().try_into().unwrap())
    }
}

impl<F> BinomialExtension<F>
where
    F: BinomiallyExtendable<4>,
{
    /// Returns the multiplicative inverse of the element.
    #[must_use]
    pub fn inverse(&self) -> Self {
        let p3_ef = BinomialExtensionField::from_base_slice(&self.0);
        let p3_ef_inverse = p3_ef.inverse();
        Self(p3_ef_inverse.as_base_slice().try_into().unwrap())
    }

    /// Returns the multiplicative inverse of the element, if it exists.
    #[must_use]
    pub fn try_inverse(&self) -> Option<Self> {
        let p3_ef = BinomialExtensionField::from_base_slice(&self.0);
        let p3_ef_inverse = p3_ef.try_inverse()?;
        Some(Self(p3_ef_inverse.as_base_slice().try_into().unwrap()))
    }
}

impl<T: FieldAlgebra + Copy> Neg for BinomialExtension<T> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self([-self.0[0], -self.0[1], -self.0[2], -self.0[3]])
    }
}

impl<AF> From<BinomialExtensionField<AF, EXTENSION_DEGREE>> for BinomialExtension<AF>
where
    AF: FieldAlgebra + Copy,
    AF::F: BinomiallyExtendable<EXTENSION_DEGREE>,
{
    fn from(value: BinomialExtensionField<AF, EXTENSION_DEGREE>) -> Self {
        let arr: [AF; EXTENSION_DEGREE] = value.as_base_slice().try_into().unwrap();
        Self(arr)
    }
}

impl<AF> From<BinomialExtension<AF>> for BinomialExtensionField<AF, EXTENSION_DEGREE>
where
    AF: FieldAlgebra + Copy,
    AF::F: BinomiallyExtendable<EXTENSION_DEGREE>,
{
    fn from(value: BinomialExtension<AF>) -> Self {
        BinomialExtensionField::from_base_slice(&value.0)
    }
}

impl<T> IntoIterator for BinomialExtension<T> {
    type Item = T;
    type IntoIter = core::array::IntoIter<T, EXTENSION_DEGREE>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
