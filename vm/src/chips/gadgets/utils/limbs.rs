use crate::chips::gadgets::utils::polynomial::Polynomial;
use generic_array::{ArrayLength, GenericArray};
use std::{
    fmt::Debug,
    ops::{Index, IndexMut},
    slice::Iter,
};

/// Each limb is represented as a u8
pub const NB_BITS_PER_LIMB: usize = 8;

/// An array representing N limbs of T.
///
/// GenericArray allows us to constrain the correct array lengths so we can have # of limbs and # of
/// witness limbs associated in NumLimbs / FieldParameters.
/// See: https://github.com/RustCrypto/traits/issues/1481
#[derive(Debug, Clone)]
pub struct Limbs<T, N: ArrayLength>(pub GenericArray<T, N>);

impl<T: Copy, N: ArrayLength> Copy for Limbs<T, N> where N::ArrayType<T>: Copy {}

impl<T, N: ArrayLength> Default for Limbs<T, N>
where
    T: Default + Copy,
{
    fn default() -> Self {
        Self(GenericArray::default())
    }
}

impl<T, N: ArrayLength> Index<usize> for Limbs<T, N> {
    type Output = T;

    fn index(&self, index: usize) -> &Self::Output {
        &self.0[index]
    }
}

impl<T, N: ArrayLength> IndexMut<usize> for Limbs<T, N> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.0[index]
    }
}

impl<T, N: ArrayLength> IntoIterator for Limbs<T, N> {
    type Item = T;
    type IntoIter = <GenericArray<T, N> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<Var: Into<Expr> + Clone, N: ArrayLength, Expr: Clone> From<Limbs<Var, N>>
    for Polynomial<Expr>
{
    fn from(value: Limbs<Var, N>) -> Self {
        Polynomial::from_coefficients(&value.0.into_iter().map(|x| x.into()).collect::<Vec<_>>())
    }
}

impl<T: Debug + Default + Clone, N: ArrayLength> From<Polynomial<T>> for Limbs<T, N> {
    fn from(value: Polynomial<T>) -> Self {
        let inner = value.as_coefficients().try_into().unwrap();
        Self(inner)
    }
}

impl<'a, T: Debug + Default + Clone, N: ArrayLength> From<Iter<'a, T>> for Limbs<T, N> {
    fn from(value: Iter<'a, T>) -> Self {
        let vec: Vec<T> = value.cloned().collect();
        let inner = vec.try_into().unwrap();
        Self(inner)
    }
}
