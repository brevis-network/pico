use crate::{
    machine::{builder::ChipBuilder, extension::BinomialExtension},
    primitives::consts::{EXTENSION_DEGREE, PACK_LANES},
};
use core::marker::PhantomData;
use p3_air::AirBuilder;
use p3_field::{
    extension::QuinticTrinomialExtendable, ExtensionField, Field, PrimeCharacteristicRing,
};
use pico_derive::AlignedBorrow;
use rand::{
    distr::{Distribution, StandardUniform},
    Rng, RngExt,
};
use serde::{Deserialize, Serialize};
use std::ops::{Index, IndexMut};

/// The smallest unit of memory that can be read and written to.
#[derive(
    AlignedBorrow, Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize,
)]
#[repr(C)]
pub struct Block<T>(pub [T; EXTENSION_DEGREE]);

impl<T> Distribution<Block<T>> for StandardUniform
where
    StandardUniform: Distribution<T>,
{
    fn sample<R: Rng + ?Sized>(&self, rng: &mut R) -> Block<T> {
        Block::from_fn(|_| rng.random())
    }
}

pub trait BlockBuilder: AirBuilder {
    fn assert_block_eq<Lhs: Into<Self::Expr>, Rhs: Into<Self::Expr>>(
        &mut self,
        lhs: Block<Lhs>,
        rhs: Block<Rhs>,
    ) {
        for (l, r) in lhs.0.into_iter().zip(rhs.0) {
            self.assert_eq(l, r);
        }
    }
}

impl<AB: AirBuilder> BlockBuilder for AB {}

impl<T> Block<T> {
    /// A block whose lane `i` is `f(i)`.
    pub fn from_fn<F: FnMut(usize) -> T>(f: F) -> Self {
        Self(core::array::from_fn(f))
    }

    pub fn map<F, U>(self, f: F) -> Block<U>
    where
        F: FnMut(T) -> U,
    {
        Block(self.0.map(f))
    }

    pub fn ext<E>(&self) -> E
    where
        T: Field,
        E: ExtensionField<T>,
    {
        E::from_basis_coefficients_slice(&self.0)
            .expect("a Block holds EXTENSION_DEGREE coefficients")
    }
}

impl<T: PrimeCharacteristicRing> Block<T> {
    /// A block packing `PACK_LANES` base-field values: lanes `0..PACK_LANES` hold them, every
    /// remaining lane is zero. The producers of packed blocks and at least one consumer of every
    /// hinted packed block go through this constructor (`looking_packed` / `looked_packed`), so
    /// the memory bus pins the padding lanes of a hinted packed block to zero; see `PACK_LANES`.
    pub fn packed(lanes: [T; PACK_LANES]) -> Self {
        let mut iter = lanes.into_iter();
        Self::from_fn(|_| iter.next().unwrap_or(T::ZERO))
    }
}

impl<T: Clone> Block<T> {
    pub fn as_extension<F: Field + QuinticTrinomialExtendable, AB: ChipBuilder<F, Var = T>>(
        &self,
    ) -> BinomialExtension<F, AB::Expr, EXTENSION_DEGREE> {
        let arr: [AB::Expr; EXTENSION_DEGREE] = self.0.clone().map(|x| AB::Expr::ZERO + x);
        BinomialExtension(arr, PhantomData)
    }

    pub fn as_extension_from_base<
        F: Field + QuinticTrinomialExtendable,
        AB: ChipBuilder<F, Var = T>,
    >(
        &self,
        base: AB::Expr,
    ) -> BinomialExtension<F, AB::Expr, EXTENSION_DEGREE> {
        let mut arr: [AB::Expr; EXTENSION_DEGREE] = self.0.clone().map(|_| AB::Expr::ZERO);
        arr[0] = base;

        BinomialExtension(arr, PhantomData)
    }
}

impl<T> From<[T; EXTENSION_DEGREE]> for Block<T> {
    fn from(arr: [T; EXTENSION_DEGREE]) -> Self {
        Self(arr)
    }
}

impl<T: PrimeCharacteristicRing> From<T> for Block<T> {
    fn from(value: T) -> Self {
        let mut value = Some(value);
        Self::from_fn(|_| value.take().unwrap_or(T::ZERO))
    }
}

impl<T: Copy> From<&[T]> for Block<T> {
    fn from(slice: &[T]) -> Self {
        let arr: [T; EXTENSION_DEGREE] = slice.try_into().unwrap();
        Self(arr)
    }
}

impl<T, I> Index<I> for Block<T>
where
    [T]: Index<I>,
{
    type Output = <[T] as Index<I>>::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output {
        Index::index(&self.0, index)
    }
}

impl<T, I> IndexMut<I> for Block<T>
where
    [T]: IndexMut<I>,
{
    #[inline]
    fn index_mut(&mut self, index: I) -> &mut Self::Output {
        IndexMut::index_mut(&mut self.0, index)
    }
}

impl<T> IntoIterator for Block<T> {
    type Item = T;
    type IntoIter = std::array::IntoIter<T, EXTENSION_DEGREE>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}
