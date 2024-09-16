use crate::{
    folder::{ProverConstraintFolder, VerifierConstraintFolder},
    lookup::{symbolic_to_virtual_pair, SymbolicLookup, VirtualPairLookup},
};
use itertools::Itertools;
use p3_air::{AirBuilder, ExtensionBuilder, FilteredAirBuilder, PairCol, PermutationAirBuilder};
use p3_field::{AbstractExtensionField, AbstractField, ExtensionField, Field};
use p3_matrix::{dense::RowMajorMatrix, Matrix};
use p3_uni_stark::{Entry, SymbolicExpression, SymbolicVariable};
use pico_configs::config::{StarkGenericConfig, Val};

/// Chip builder
pub trait ChipBuilder<F: Field>:
    AirBuilder<F = F> + LookupBuilder<SymbolicLookup<Self::Expr>>
{
    /// Returns a sub-builder whose constraints are enforced only when `condition` is not one.
    fn when_not<I: Into<Self::Expr>>(&mut self, condition: I) -> FilteredAirBuilder<Self> {
        self.when_ne(condition, Self::F::one())
    }

    /// Asserts that an iterator of expressions are all equal.
    fn assert_all_eq<I1: Into<Self::Expr>, I2: Into<Self::Expr>>(
        &mut self,
        left: impl IntoIterator<Item = I1>,
        right: impl IntoIterator<Item = I2>,
    ) {
        for (left, right) in left.into_iter().zip_eq(right) {
            self.assert_eq(left, right);
        }
    }

    /// Asserts that an iterator of expressions are all zero.
    fn assert_all_zero<I: Into<Self::Expr>>(&mut self, iter: impl IntoIterator<Item = I>) {
        iter.into_iter().for_each(|expr| self.assert_zero(expr));
    }

    /// Will return `a` if `condition` is 1, else `b`.  This assumes that `condition` is already
    /// checked to be a boolean.
    #[inline]
    fn if_else(
        &mut self,
        condition: impl Into<Self::Expr> + Clone,
        a: impl Into<Self::Expr> + Clone,
        b: impl Into<Self::Expr> + Clone,
    ) -> Self::Expr {
        condition.clone().into() * a.into() + (Self::Expr::one() - condition.into()) * b.into()
    }

    /// Index an array of expressions using an index bitmap.  This function assumes that the
    /// `EIndex` type is a boolean and that `index_bitmap`'s entries sum to 1.
    fn index_array(
        &mut self,
        array: &[impl Into<Self::Expr> + Clone],
        index_bitmap: &[impl Into<Self::Expr> + Clone],
    ) -> Self::Expr {
        let mut result = Self::Expr::zero();

        for (value, i) in array.iter().zip_eq(index_bitmap) {
            result += value.clone().into() * i.clone().into();
        }

        result
    }

    /// get preprocessed trace
    /// Originally from PaiBuilder in p3
    fn preprocessed(&self) -> Self::M;
}

impl<'a, F: Field, AB: AirBuilder<F = F>> ChipBuilder<F> for FilteredAirBuilder<'a, AB> {
    fn preprocessed(&self) -> Self::M {
        panic!("Should not be called!")
    }
}

/// message builder for the chips.
pub trait LookupBuilder<M> {
    fn looking(&mut self, message: M);

    fn looked(&mut self, message: M);
}

/// A message builder for which sending and receiving messages is a no-op.
pub trait EmptyLookupBuilder: AirBuilder {}

impl<AB: EmptyLookupBuilder, M> LookupBuilder<M> for AB {
    fn looking(&mut self, _message: M) {}

    fn looked(&mut self, _message: M) {}
}

impl<'a, SC: StarkGenericConfig> EmptyLookupBuilder for ProverConstraintFolder<'a, SC> {}
impl<'a, SC: StarkGenericConfig> EmptyLookupBuilder for VerifierConstraintFolder<'a, SC> {}
impl<'a, F: Field, AB: AirBuilder<F = F>> EmptyLookupBuilder for FilteredAirBuilder<'a, AB> {}

/// Permutation builder to include all permutation-related variables
pub trait PermutationBuilder: AirBuilder + ExtensionBuilder {
    /// from PermutationAirBuilder
    type MP: Matrix<Self::VarEF>;

    type RandomVar: Into<Self::ExprEF> + Copy;

    fn permutation(&self) -> Self::MP;

    fn permutation_randomness(&self) -> &[Self::RandomVar];

    /// for cumulative sum
    // The type of the cumulative sum.
    type Sum: Into<Self::ExprEF>;

    // Returns the cumulative sum of the permutation.
    fn cumulative_sum(&self) -> Self::Sum;
}

/// AirBuilder with public values
/// originally from AirBuilderWithPublicValues in p3
pub trait PublicValuesBuilder: AirBuilder {
    type PublicVar: Into<Self::Expr> + Copy;

    fn public_values(&self) -> &[Self::PublicVar];
}
