//! Builder functions for the extension field

use super::ChipBuilder;
use crate::machine::extension::BinomialExtension;
use core::marker::PhantomData;
use p3_field::Field;
use std::array;

/// A builder that can operation on extension elements.
pub trait ExtensionBuilder<F: Field, const D: usize>: ChipBuilder<F> {
    /// Asserts that the two field extensions are equal.
    fn assert_ext_eq<B, I: Into<Self::Expr>>(
        &mut self,
        left: BinomialExtension<B, I, D>,
        right: BinomialExtension<B, I, D>,
    ) {
        for (left, right) in left.0.into_iter().zip(right.0) {
            self.assert_eq(left, right);
        }
    }

    /// Checks if an extension element is a base element.
    fn assert_is_base_element<B, I: Into<Self::Expr> + Clone>(
        &mut self,
        element: BinomialExtension<B, I, D>,
    ) {
        let base_slice = element.as_base_slice();
        let degree = base_slice.len();
        base_slice[1..degree].iter().for_each(|coeff| {
            self.assert_zero(coeff.clone().into());
        });
    }

    /// Performs an if else on extension elements.
    fn if_else_ext<B>(
        &mut self,
        condition: impl Into<Self::Expr> + Clone,
        a: BinomialExtension<B, impl Into<Self::Expr> + Clone, D>,
        b: BinomialExtension<B, impl Into<Self::Expr> + Clone, D>,
    ) -> BinomialExtension<B, Self::Expr, D> {
        BinomialExtension(
            array::from_fn(|i| self.if_else(condition.clone(), a.0[i].clone(), b.0[i].clone())),
            PhantomData,
        )
    }
}
