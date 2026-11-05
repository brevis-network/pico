use core::marker::PhantomData;
use p3_field::{
    extension::{
        trinomial_quintic_mul, QuinticTrinomialExtendable, QuinticTrinomialExtensionField,
    },
    BasedVectorSpace, Field, PrimeCharacteristicRing,
};
use pico_derive::AlignedBorrow;
use std::ops::{Add, Div, Mul, Neg, Sub};

/// A symbolic extension-field element over a generic type `T` (a column variable or an
/// expression), with base field `B`. The arithmetic is that of KoalaBear^5, `X^5 + X^2 - 1`
/// (`trinomial_quintic_mul`); the name predates the quintic trinomial extension and is kept
/// because every recursion chip spells it (renaming is a follow-up).
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
        T: PrimeCharacteristicRing,
    {
        let mut arr: [T; D] = core::array::from_fn(|_| T::ZERO);
        arr[0] = b;
        Self(arr, PhantomData)
    }

    /// Returns a reference to the underlying slice.
    pub const fn as_basis_coefficients_slice(&self) -> &[T] {
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

// D = 5: the quintic trinomial extension `X^5 + X^2 - 1` (KoalaBear^5), the production challenge
// field. The multiplication is Plonky3's
// `trinomial_quintic_mul`, generic over any `PrimeCharacteristicRing`, so it works on symbolic
// expressions as it does on field elements.
impl<B: QuinticTrinomialExtendable, T: PrimeCharacteristicRing> Mul for BinomialExtension<B, T, 5> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        let mut result = [T::ZERO; 5];
        trinomial_quintic_mul(&self.0, &rhs.0, &mut result);
        Self(result, PhantomData)
    }
}

impl<B, F> Div for BinomialExtension<B, F, 5>
where
    F: QuinticTrinomialExtendable,
{
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        let p3_ef_lhs =
            QuinticTrinomialExtensionField::<F>::from_basis_coefficients_slice(&self.0).unwrap();
        let p3_ef_rhs =
            QuinticTrinomialExtensionField::<F>::from_basis_coefficients_slice(&rhs.0).unwrap();
        let p3_ef_result = p3_ef_lhs / p3_ef_rhs;
        Self(
            p3_ef_result
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap(),
            PhantomData,
        )
    }
}

impl<B, F> BinomialExtension<B, F, 5>
where
    F: QuinticTrinomialExtendable,
{
    /// Returns the multiplicative inverse of the element.
    #[must_use]
    pub fn inverse(&self) -> Self {
        let p3_ef =
            QuinticTrinomialExtensionField::<F>::from_basis_coefficients_slice(&self.0).unwrap();
        let p3_ef_inverse = p3_ef.inverse();
        Self(
            p3_ef_inverse
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap(),
            PhantomData,
        )
    }

    /// Returns the multiplicative inverse of the element, if it exists.
    #[must_use]
    pub fn try_inverse(&self) -> Option<Self> {
        let p3_ef = QuinticTrinomialExtensionField::<F>::from_basis_coefficients_slice(&self.0)?;
        let p3_ef_inverse = p3_ef.try_inverse()?;
        Some(Self(
            p3_ef_inverse
                .as_basis_coefficients_slice()
                .try_into()
                .unwrap(),
            PhantomData,
        ))
    }
}

impl<B, F> From<QuinticTrinomialExtensionField<F>> for BinomialExtension<B, F, 5>
where
    F: QuinticTrinomialExtendable,
{
    fn from(value: QuinticTrinomialExtensionField<F>) -> Self {
        let arr: [F; 5] = value.as_basis_coefficients_slice().try_into().unwrap();
        Self(arr, PhantomData)
    }
}

impl<B, F> From<BinomialExtension<B, F, 5>> for QuinticTrinomialExtensionField<F>
where
    F: QuinticTrinomialExtendable,
{
    fn from(value: BinomialExtension<B, F, 5>) -> Self {
        QuinticTrinomialExtensionField::<F>::from_basis_coefficients_slice(&value.0).unwrap()
    }
}

impl<B, T: PrimeCharacteristicRing + Copy, const D: usize> Neg for BinomialExtension<B, T, D> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(self.0.map(|x| -x), PhantomData)
    }
}

impl<B, T, const D: usize> IntoIterator for BinomialExtension<B, T, D> {
    type Item = T;
    type IntoIter = core::array::IntoIter<T, D>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::air::symbolic::symbolic_expression::SymbolicExpression;
    use p3_koala_bear::KoalaBear;

    type Ef5 = QuinticTrinomialExtensionField<KoalaBear>;
    type Sym5 = BinomialExtension<KoalaBear, KoalaBear, 5>;

    fn sample(seed: u32) -> Ef5 {
        let coeffs: [KoalaBear; 5] = core::array::from_fn(|i| {
            KoalaBear::from_u32(seed.wrapping_mul(7919).wrapping_add(i as u32 * 104_729 + 1))
        });
        Ef5::from_basis_coefficients_slice(&coeffs).unwrap()
    }

    /// The D = 5 arithmetic on base-field coefficients agrees with Plonky3's quintic type.
    #[test]
    fn quintic_arithmetic_matches_plonky3() {
        for seed in 1..=16u32 {
            let (a, b) = (sample(seed), sample(seed + 100));
            let (sa, sb): (Sym5, Sym5) = (a.into(), b.into());
            assert_eq!(Ef5::from(sa * sb), a * b, "mul, seed {seed}");
            assert_eq!(Ef5::from(sa / sb), a / b, "div, seed {seed}");
            assert_eq!(Ef5::from(sa.inverse()), a.inverse(), "inverse, seed {seed}");
            assert_eq!(
                sa.try_inverse().map(Ef5::from),
                a.try_inverse(),
                "try_inverse, seed {seed}"
            );
            let round_trip: Sym5 = a.into();
            assert_eq!(Ef5::from(round_trip), a, "round trip, seed {seed}");
        }
        assert_eq!(Sym5::from_base(KoalaBear::ZERO).try_inverse(), None);
    }

    /// The D = 5 multiplication instantiates on symbolic expressions, which is how the recursion
    /// chips use it.
    #[test]
    fn quintic_multiplication_instantiates_on_symbolic_expressions() {
        type Expr5 = BinomialExtension<KoalaBear, SymbolicExpression<KoalaBear>, 5>;
        let x = Expr5::from_base(SymbolicExpression::<KoalaBear>::ONE);
        let _ = x.clone() * x;
    }
}
