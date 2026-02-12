// TODO: refactor to use p3 BionmialExtensionField

use core::marker::PhantomData;
use p3_field::{
    extension::{BinomialExtensionField, BinomiallyExtendable},
    Field, FieldAlgebra, FieldExtensionAlgebra,
};
use pico_derive::AlignedBorrow;
use std::ops::{Add, Div, Mul, Neg, Sub};
//use typenum::Unsigned;

/// A binomial extension element represented over a generic type `T` which is
/// mapped into by base field B
#[derive(AlignedBorrow, Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct BinomialExtension<B, T, const D: usize>(pub [T; D], pub PhantomData<fn(B) -> B>);

impl<B, T, const D: usize> Default for BinomialExtension<B, T, D>
where
    [T; D]: Default,
{
    fn default() -> Self {
        Self(Default::default(), PhantomData)
    }
}

impl<B, T, const D: usize> BinomialExtension<B, T, D> {
    /// Creates a new binomial extension element from a base element.
    pub fn from_base(b: T) -> Self
    where
        T: FieldAlgebra,
    {
        let mut arr: [T; D] = core::array::from_fn(|_| T::ZERO);
        arr[0] = b;
        Self(arr, PhantomData)
    }

    /// Returns a reference to the underlying slice.
    pub const fn as_base_slice(&self) -> &[T] {
        &self.0
    }

    /// Creates a new binomial extension element from a binomial extension element.
    #[allow(clippy::needless_pass_by_value)]
    pub fn from<S: Into<T>>(from: BinomialExtension<B, S, D>) -> Self {
        Self(from.0.map(Into::into), PhantomData)
    }
}

impl<B, T: Add<Output = T> + Clone, const D: usize> Add for BinomialExtension<B, T, D> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(
            core::array::from_fn(|i| self.0[i].clone() + rhs.0[i].clone()),
            PhantomData,
        )
    }
}

impl<B, T: Sub<Output = T> + Clone, const D: usize> Sub for BinomialExtension<B, T, D> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(
            core::array::from_fn(|i| self.0[i].clone() - rhs.0[i].clone()),
            PhantomData,
        )
    }
}

impl<B: Field + BinomiallyExtendable<D>, T: Add + Mul + FieldAlgebra + From<B>, const D: usize> Mul
    for BinomialExtension<B, T, D>
{
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut result = [T::ZERO; D];
        //let w = T::from_canonical_u32(B::W::U32);
        let w = T::from(B::W);

        for i in 0..D {
            for j in 0..D {
                if i + j >= D {
                    result[i + j - D] = result[i + j - D].clone()
                        + w.clone() * self.0[i].clone() * rhs.0[j].clone();
                } else {
                    result[i + j] = result[i + j].clone() + self.0[i].clone() * rhs.0[j].clone();
                }
            }
        }

        Self(result, PhantomData)
    }
}

impl<B, F, const D: usize> Div for BinomialExtension<B, F, D>
where
    F: BinomiallyExtendable<D>,
{
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        let p3_ef_lhs = BinomialExtensionField::from_base_slice(&self.0);
        let p3_ef_rhs = BinomialExtensionField::from_base_slice(&rhs.0);
        let p3_ef_result = p3_ef_lhs / p3_ef_rhs;
        Self(
            p3_ef_result.as_base_slice().try_into().unwrap(),
            PhantomData,
        )
    }
}

impl<B, F, const D: usize> BinomialExtension<B, F, D>
where
    F: BinomiallyExtendable<D>,
{
    /// Returns the multiplicative inverse of the element.
    #[must_use]
    pub fn inverse(&self) -> Self {
        let p3_ef = BinomialExtensionField::from_base_slice(&self.0);
        let p3_ef_inverse = p3_ef.inverse();
        Self(
            p3_ef_inverse.as_base_slice().try_into().unwrap(),
            PhantomData,
        )
    }

    /// Returns the multiplicative inverse of the element, if it exists.
    #[must_use]
    pub fn try_inverse(&self) -> Option<Self> {
        let p3_ef = BinomialExtensionField::from_base_slice(&self.0);
        let p3_ef_inverse = p3_ef.try_inverse()?;
        Some(Self(
            p3_ef_inverse.as_base_slice().try_into().unwrap(),
            PhantomData,
        ))
    }
}

impl<B, T: FieldAlgebra + Copy, const D: usize> Neg for BinomialExtension<B, T, D> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.map(|x| -x), PhantomData)
    }
}

impl<B, AF, const D: usize> From<BinomialExtensionField<AF, D>> for BinomialExtension<B, AF, D>
where
    AF: FieldAlgebra + Copy,
    AF::F: BinomiallyExtendable<D>,
{
    fn from(value: BinomialExtensionField<AF, D>) -> Self {
        let arr: [AF; D] = value.as_base_slice().try_into().unwrap();
        Self(arr, PhantomData)
    }
}

impl<B, AF, const D: usize> From<BinomialExtension<B, AF, D>> for BinomialExtensionField<AF, D>
where
    AF: FieldAlgebra + Copy,
    AF::F: BinomiallyExtendable<D>,
{
    fn from(value: BinomialExtension<B, AF, D>) -> Self {
        BinomialExtensionField::from_base_slice(&value.0)
    }
}

impl<B, T, const D: usize> IntoIterator for BinomialExtension<B, T, D> {
    type Item = T;
    type IntoIter = core::array::IntoIter<T, D>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
