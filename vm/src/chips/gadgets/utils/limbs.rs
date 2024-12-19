use crate::chips::gadgets::utils::polynomial::Polynomial;
use core::{
    fmt::Debug,
    ops::{Index, IndexMut},
};
use hybrid_array::{Array, ArraySize};

/// Each limb is represented as a u8
pub const BITS_PER_LIMB: usize = 8;

/// An array representing N limbs of T.
///
/// Array allows us to constrain the correct array lengths so we can have # of limbs and # of
/// witness limbs associated in NumLimbs / FieldParameters.
/// See: https://github.com/RustCrypto/traits/issues/1481
#[derive(Clone, Default)]
pub struct Limbs<T, N: ArraySize>(pub Array<T, N>);

impl<T: Debug, N: ArraySize> Debug for Limbs<T, N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Limbs({:?})", self.0.as_slice())
    }
}

impl<T: Copy, N: ArraySize> Copy for Limbs<T, N> where N::ArrayType<T>: Copy {}

impl<T, N: ArraySize> Index<usize> for Limbs<T, N> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<T, N: ArraySize> IndexMut<usize> for Limbs<T, N> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl<T, N: ArraySize> IntoIterator for Limbs<T, N> {
    type Item = T;
    type IntoIter = <Array<T, N> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<Var: Into<Expr> + Clone, N: ArraySize, Expr: Clone> From<Limbs<Var, N>> for Polynomial<Expr> {
    fn from(value: Limbs<Var, N>) -> Self {
        Polynomial::from_coefficients(&value.0.into_iter().map(|x| x.into()).collect::<Vec<_>>())
    }
}

impl<T: Copy, N: ArraySize> From<Polynomial<T>> for Limbs<T, N> {
    fn from(value: Polynomial<T>) -> Self {
        let inner = (&*value.as_coefficients()).try_into().unwrap();
        Self(inner)
    }
}
