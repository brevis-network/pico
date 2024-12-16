//! Permutation associating builder functions

use p3_air::{AirBuilder, ExtensionBuilder};
use p3_matrix::Matrix;

/// Permutation builder to include all permutation-related variables
pub trait PermutationBuilder: AirBuilder + ExtensionBuilder {
    /// from PermutationAirBuilder
    type MP: Matrix<Self::VarEF>;

    type RandomVar: Into<Self::ExprEF> + Copy;

    fn permutation(&self) -> Self::MP;

    fn permutation_randomness(&self) -> &[Self::RandomVar];

    /// for cumulative sum
    // The type of the cumulative sum.
    type Sum: Into<Self::ExprEF> + Copy;

    // Returns the cumulative sum of the permutation.
    fn cumulative_sums(&self) -> &[Self::Sum];
}
