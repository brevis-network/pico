use super::FieldSepticCurve;
use crate::machine::builder::{ChipBuilder, SepticExtensionBuilder};
use num_bigint::BigUint;
use num_traits::One;
use p3_field::{ExtensionField, Field, FieldAlgebra, FieldExtensionAlgebra, Packable, PrimeField};
use serde::{Deserialize, Serialize};
use std::{
    any::Any,
    array,
    fmt::Display,
    iter::{Product, Sum},
    ops::{Add, AddAssign, Div, Index, IndexMut, Mul, MulAssign, Neg, Sub, SubAssign},
};

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct SepticExtension<F>(pub [F; 7]);

impl<F: Field> Field for SepticExtension<F> {
    type Packing = Self;

    const GENERATOR: Self = Self(F::EXT_GENERATOR);

    fn try_inverse(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }
        Some(self.inv())
    }

    fn order() -> BigUint {
        F::order().pow(7)
    }
}

impl<F: FieldAlgebra + Any> FieldAlgebra for SepticExtension<F> {
    type F = SepticExtension<F::F>;

    const ZERO: Self = SepticExtension([
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
    ]);

    const ONE: Self =
        SepticExtension([F::ONE, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO]);

    const TWO: Self =
        SepticExtension([F::TWO, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO]);

    const FOUR: Self = SepticExtension([
        F::FOUR,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
    ]);

    const FIVE: Self = SepticExtension([
        F::FIVE,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
    ]);

    const NEG_ONE: Self = SepticExtension([
        F::NEG_ONE,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
        F::ZERO,
    ]);

    fn from_f(f: Self::F) -> Self {
        SepticExtension([
            F::from_f(f.0[0]),
            F::from_f(f.0[1]),
            F::from_f(f.0[2]),
            F::from_f(f.0[3]),
            F::from_f(f.0[4]),
            F::from_f(f.0[5]),
            F::from_f(f.0[6]),
        ])
    }

    fn from_bool(b: bool) -> Self {
        SepticExtension([
            F::from_bool(b),
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
        ])
    }

    fn from_canonical_u8(n: u8) -> Self {
        SepticExtension([
            F::from_canonical_u8(n),
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
        ])
    }

    fn from_canonical_u16(n: u16) -> Self {
        SepticExtension([
            F::from_canonical_u16(n),
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
        ])
    }

    fn from_canonical_u32(n: u32) -> Self {
        SepticExtension([
            F::from_canonical_u32(n),
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
        ])
    }

    fn from_canonical_u64(n: u64) -> Self {
        SepticExtension([
            F::from_canonical_u64(n),
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
        ])
    }

    fn from_canonical_usize(n: usize) -> Self {
        SepticExtension([
            F::from_canonical_usize(n),
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
        ])
    }

    fn from_wrapped_u32(n: u32) -> Self {
        SepticExtension([
            F::from_wrapped_u32(n),
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
        ])
    }

    fn from_wrapped_u64(n: u64) -> Self {
        SepticExtension([
            F::from_wrapped_u64(n),
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
            F::ZERO,
        ])
    }
}

impl<F: FieldAlgebra + Any> FieldExtensionAlgebra<F> for SepticExtension<F> {
    const D: usize = 7;

    fn from_base(b: F) -> Self {
        SepticExtension([b, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO])
    }

    fn from_base_slice(bs: &[F]) -> Self {
        SepticExtension([
            bs[0].clone(),
            bs[1].clone(),
            bs[2].clone(),
            bs[3].clone(),
            bs[4].clone(),
            bs[5].clone(),
            bs[6].clone(),
        ])
    }

    fn from_base_fn<G: FnMut(usize) -> F>(f: G) -> Self {
        Self(array::from_fn(f))
    }

    fn as_base_slice(&self) -> &[F] {
        self.0.as_slice()
    }

    fn from_base_iter<I: Iterator<Item = F>>(mut iter: I) -> Self {
        SepticExtension([
            iter.next().unwrap(),
            iter.next().unwrap(),
            iter.next().unwrap(),
            iter.next().unwrap(),
            iter.next().unwrap(),
            iter.next().unwrap(),
            iter.next().unwrap(),
        ])
    }
}

impl<F: Field> ExtensionField<F> for SepticExtension<F> {
    type ExtensionPacking = SepticExtension<F::Packing>;
}

impl<F: Field> Packable for SepticExtension<F> {}

impl<F: FieldAlgebra> Add for SepticExtension<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        let mut res = self.0;
        for (r, rhs_val) in res.iter_mut().zip(rhs.0) {
            *r = (*r).clone() + rhs_val;
        }
        Self(res)
    }
}

impl<F: FieldAlgebra> AddAssign for SepticExtension<F> {
    fn add_assign(&mut self, rhs: Self) {
        self.0[0] += rhs.0[0].clone();
        self.0[1] += rhs.0[1].clone();
        self.0[2] += rhs.0[2].clone();
        self.0[3] += rhs.0[3].clone();
        self.0[4] += rhs.0[4].clone();
        self.0[5] += rhs.0[5].clone();
        self.0[6] += rhs.0[6].clone();
    }
}

impl<F: FieldAlgebra> Sub for SepticExtension<F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        let mut res = self.0;
        for (r, rhs_val) in res.iter_mut().zip(rhs.0) {
            *r = (*r).clone() - rhs_val;
        }
        Self(res)
    }
}

impl<F: FieldAlgebra> SubAssign for SepticExtension<F> {
    fn sub_assign(&mut self, rhs: Self) {
        self.0[0] -= rhs.0[0].clone();
    }
}

impl<F: FieldAlgebra> Neg for SepticExtension<F> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        let mut res = self.0;
        for r in res.iter_mut() {
            *r = -r.clone();
        }
        Self(res)
    }
}

impl<F: FieldAlgebra + Any> MulAssign for SepticExtension<F> {
    fn mul_assign(&mut self, rhs: Self) {
        let res = self.clone() * rhs;
        *self = res;
    }
}

impl<F: FieldAlgebra + Any> Product for SepticExtension<F> {
    fn product<I: Iterator<Item = Self>>(iter: I) -> Self {
        let one = Self::ONE;
        iter.fold(one, |acc, x| acc * x)
    }
}

impl<F: FieldAlgebra + Any> Sum for SepticExtension<F> {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        let zero = Self::ZERO;
        iter.fold(zero, |acc, x| acc + x)
    }
}

impl<F: FieldAlgebra> From<F> for SepticExtension<F> {
    fn from(f: F) -> Self {
        SepticExtension([f, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO])
    }
}

impl<F: FieldAlgebra> Add<F> for SepticExtension<F> {
    type Output = Self;

    fn add(self, rhs: F) -> Self::Output {
        SepticExtension([
            self.0[0].clone() + rhs,
            self.0[1].clone(),
            self.0[2].clone(),
            self.0[3].clone(),
            self.0[4].clone(),
            self.0[5].clone(),
            self.0[6].clone(),
        ])
    }
}

impl<F: FieldAlgebra> AddAssign<F> for SepticExtension<F> {
    fn add_assign(&mut self, rhs: F) {
        self.0[0] += rhs;
    }
}

impl<F: FieldAlgebra> Sub<F> for SepticExtension<F> {
    type Output = Self;

    fn sub(self, rhs: F) -> Self::Output {
        self + (-rhs)
    }
}

impl<F: FieldAlgebra> SubAssign<F> for SepticExtension<F> {
    fn sub_assign(&mut self, rhs: F) {
        self.0[0] -= rhs;
    }
}

impl<F: FieldAlgebra> Mul<F> for SepticExtension<F> {
    type Output = Self;

    fn mul(self, rhs: F) -> Self::Output {
        SepticExtension([
            self.0[0].clone() * rhs.clone(),
            self.0[1].clone() * rhs.clone(),
            self.0[2].clone() * rhs.clone(),
            self.0[3].clone() * rhs.clone(),
            self.0[4].clone() * rhs.clone(),
            self.0[5].clone() * rhs.clone(),
            self.0[6].clone() * rhs.clone(),
        ])
    }
}

impl<F: FieldAlgebra> MulAssign<F> for SepticExtension<F> {
    fn mul_assign(&mut self, rhs: F) {
        for i in 0..7 {
            self.0[i] *= rhs.clone();
        }
    }
}

impl<F: Field> Div for SepticExtension<F> {
    type Output = Self;

    #[allow(clippy::suspicious_arithmetic_impl)]
    fn div(self, rhs: Self) -> Self::Output {
        self * rhs.inverse()
    }
}

impl<F: FieldAlgebra> Display for SepticExtension<F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl<F: FieldAlgebra + Any> Mul for SepticExtension<F> {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        // We could use below code to check the F type for `same_field` here.
        //
        // ``` ignore
        // let typ = std::any::type_name::<F>();
        // println!("Found type = {typ:?}");
        // ```

        // 0) Predefine the "reduction coefficients" for z^7
        // 1) Polynomial multiply: we get up to degree-12 polynomial
        // We'll store that in `res[0..13]`.
        let mut res = [F::ZERO; 13];
        for i in 0..7 {
            for j in 0..7 {
                // multiply each pair of coefficients and accumulate
                res[i + j] = res[i + j].clone() + (self.0[i].clone() * rhs.0[j].clone());
            }
        }

        // 2) In-place reduction: fold down z^k for k >= 7
        // We'll do it from high powers down to 7 so we don't overwrite
        // something we still need.
        for power in (7..=12).rev() {
            let coeff = res[power].clone();
            // if !(coeff == F::ZERO) {
            // z^power = z^(power-7) * z^7
            // use the relation z^7 = sum(COEFFS) * z^0..z^6
            // fold it back into lower degrees
            for (offset, &red) in F::EXT_COEFFS.iter().enumerate() {
                let idx = (power - 7) + offset; // this is <= 6 + 6 = 12, safe
                res[idx] = res[idx].clone() + (coeff.clone() * F::from_canonical_u32(red));
            }
            // zero out the old coefficient so we don't double-count
            res[power] = F::ZERO;
            // }
        }

        // 3) Now res[0..7] is our final polynomial of degree <= 6
        let mut out = [F::ZERO; 7];
        out.clone_from_slice(&res[..7]);
        Self(out)
    }
}

impl<F: Field> SepticExtension<F> {
    #[must_use]
    fn frobenius(&self) -> Self {
        let mut result = Self::ZERO;
        result += self.0[0];
        result += Self::z_pow_p(1) * self.0[1];
        result += Self::z_pow_p(2) * self.0[2];
        result += Self::z_pow_p(3) * self.0[3];
        result += Self::z_pow_p(4) * self.0[4];
        result += Self::z_pow_p(5) * self.0[5];
        result += Self::z_pow_p(6) * self.0[6];
        result
    }

    #[must_use]
    fn double_frobenius(&self) -> Self {
        let mut result = Self::ZERO;
        result += self.0[0];
        result += Self::z_pow_p2(1) * self.0[1];
        result += Self::z_pow_p2(2) * self.0[2];
        result += Self::z_pow_p2(3) * self.0[3];
        result += Self::z_pow_p2(4) * self.0[4];
        result += Self::z_pow_p2(5) * self.0[5];
        result += Self::z_pow_p2(6) * self.0[6];
        result
    }

    #[must_use]
    fn pow_r_1(&self) -> Self {
        let base = self.frobenius() * self.double_frobenius();
        let base_p2 = base.double_frobenius();
        let base_p4 = base_p2.double_frobenius();
        base * base_p2 * base_p4
    }

    #[must_use]
    pub fn inv(&self) -> Self {
        let pow_r_1 = self.pow_r_1();
        let pow_r = pow_r_1 * *self;
        pow_r_1 * pow_r.0[0].inverse()
    }

    pub fn is_square(&self) -> (F, bool) {
        let pow_r_1 = self.pow_r_1();
        let pow_r = pow_r_1 * *self;
        let exp = (F::order() - BigUint::one()) / BigUint::from(2u8);
        let exp = exp.to_u64_digits()[0];

        (pow_r.0[0], pow_r.0[0].exp_u64(exp) == F::ONE)
    }

    pub fn z_pow_p(index: usize) -> Self {
        Self(F::Z_POW_P[index].map(F::from_canonical_u32))
    }

    pub fn z_pow_p2(index: usize) -> Self {
        Self(F::Z_POW_P2[index].map(F::from_canonical_u32))
    }

    /// Computes the square root of the septic field extension element.
    /// Returns None if the element is not a square, and Some(result) if it is a square.
    pub fn sqrt(&self) -> Option<Self> {
        let n = *self;

        if n == Self::ZERO || n == Self::ONE {
            return Some(n);
        }

        let (numerator, is_square) = n.is_square();

        if !is_square {
            return None;
        }

        let n_power = F::n_power(n);

        let mut n_frobenius = n_power.frobenius();
        let mut denominator = n_frobenius;

        n_frobenius = n_frobenius.double_frobenius();
        denominator *= n_frobenius;
        n_frobenius = n_frobenius.double_frobenius();
        denominator *= n_frobenius;
        denominator *= n;

        let base = numerator.inverse();
        let g = F::GENERATOR;
        let mut a = F::ONE;
        let mut nonresidue = F::ONE - base;
        let legendre_exp = (F::order() - BigUint::one()) / BigUint::from(2u8);

        while nonresidue.exp_u64(legendre_exp.to_u64_digits()[0]) == F::ONE {
            a *= g;
            nonresidue = a.square() - base;
        }

        let order = F::order();
        let cipolla_pow = (&order + BigUint::one()) / BigUint::from(2u8);
        let mut x = CipollaExtension::new(a, F::ONE);
        x = x.pow(&cipolla_pow, nonresidue);

        Some(denominator * x.real)
    }
}

impl<F: PrimeField> SepticExtension<F> {
    /// Returns whether the extension field element viewed as an y-coordinate of a digest represents a receive interaction.
    pub fn is_receive(&self) -> bool {
        BigUint::from(1u32) <= self.0[6].as_canonical_biguint()
            && self.0[6].as_canonical_biguint()
                <= (F::order() - BigUint::from(1u32)) / BigUint::from(2u32)
    }

    /// Returns whether the extension field element viewed as an y-coordinate of a digest represents a send interaction.
    pub fn is_send(&self) -> bool {
        (F::order() + BigUint::from(1u32)) / BigUint::from(2u32) <= self.0[6].as_canonical_biguint()
            && self.0[6].as_canonical_biguint() <= (F::order() - BigUint::from(1u32))
    }

    /// Returns whether the extension field element viewed as an y-coordinate of a digest cannot represent anything.
    pub fn is_exception(&self) -> bool {
        self.0[6].as_canonical_biguint() == BigUint::from(0u32)
    }
}

/// Extension field for Cipolla's algorithm, taken from <https://github.com/Plonky3/Plonky3/pull/439/files>.
#[derive(Clone, Copy, Debug)]
pub struct CipollaExtension<F: Field> {
    real: F,
    imag: F,
}

impl<F: Field> CipollaExtension<F> {
    fn new(real: F, imag: F) -> Self {
        Self { real, imag }
    }

    fn one() -> Self {
        Self::new(F::ONE, F::ZERO)
    }

    fn mul_ext(&self, other: Self, nonresidue: F) -> Self {
        Self::new(
            self.real * other.real + nonresidue * self.imag * other.imag,
            self.real * other.imag + self.imag * other.real,
        )
    }

    fn pow(&self, exp: &BigUint, nonresidue: F) -> Self {
        let mut result = Self::one();
        let mut base = *self;
        let bits = exp.bits();

        for i in 0..bits {
            if exp.bit(i) {
                result = result.mul_ext(base, nonresidue);
            }
            base = base.mul_ext(base, nonresidue);
        }
        result
    }
}

/// A block of columns for septic extension.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[repr(C)]
pub struct SepticBlock<T>(pub [T; 7]);

impl<T> SepticBlock<T> {
    /// Maps a `SepticBlock<T>` to `SepticBlock<U>` based on a map from `T` to `U`.
    pub fn map<F, U>(self, f: F) -> SepticBlock<U>
    where
        F: FnMut(T) -> U,
    {
        SepticBlock(self.0.map(f))
    }

    /// A function similar to `core:array::from_fn`.
    pub fn from_base_fn<G: FnMut(usize) -> T>(f: G) -> Self {
        Self(array::from_fn(f))
    }
}

impl<T: Field> SepticBlock<T> {
    /// Takes a `SepticBlock` into a `SepticExtension` of expressions.
    pub fn as_extension<AB: SepticExtensionBuilder<T>>(&self) -> SepticExtension<AB::Expr> {
        let arr: [AB::Expr; 7] = self.0.map(|x| AB::Expr::ZERO + x);
        SepticExtension(arr)
    }

    /// Takes a single expression into a `SepticExtension` of expressions.
    pub fn as_extension_from_base<AB: ChipBuilder<T>>(
        &self,
        base: AB::Expr,
    ) -> SepticExtension<AB::Expr> {
        let mut arr: [AB::Expr; 7] = self.0.map(|_| AB::Expr::ZERO);
        arr[0] = base;

        SepticExtension(arr)
    }
}

impl<T> From<[T; 7]> for SepticBlock<T> {
    fn from(arr: [T; 7]) -> Self {
        Self(arr)
    }
}

impl<T: FieldAlgebra> From<T> for SepticBlock<T> {
    fn from(value: T) -> Self {
        Self([value, T::ZERO, T::ZERO, T::ZERO, T::ZERO, T::ZERO, T::ZERO])
    }
}

impl<T: Copy> From<&[T]> for SepticBlock<T> {
    fn from(slice: &[T]) -> Self {
        let arr: [T; 7] = slice.try_into().unwrap();
        Self(arr)
    }
}

impl<T, I> Index<I> for SepticBlock<T>
where
    [T]: Index<I>,
{
    type Output = <[T] as Index<I>>::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        Index::index(&self.0, index)
    }
}

impl<T, I> IndexMut<I> for SepticBlock<T>
where
    [T]: IndexMut<I>,
{
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        IndexMut::index_mut(&mut self.0, index)
    }
}

impl<T> IntoIterator for SepticBlock<T> {
    type Item = T;
    type IntoIter = std::array::IntoIter<T, 7>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
