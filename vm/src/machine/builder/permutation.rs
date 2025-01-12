//! Permutation associating builder functions

use crate::machine::septic::SepticDigest;
use p3_air::{AirBuilder, ExtensionBuilder};
use p3_matrix::Matrix;

/// Permutation builder to include all permutation-related variables
pub trait PermutationBuilder: AirBuilder + ExtensionBuilder {
    /// from PermutationAirBuilder
    type MP: Matrix<Self::VarEF>;

    type RandomVar: Into<Self::ExprEF> + Copy;

    /// The type of the local cumulative sum.
    type RegionalSum: Into<Self::ExprEF> + Copy;

    /// The type of the global cumulative sum;
    type GlobalSum: Into<Self::Expr> + Copy;

    fn permutation(&self) -> Self::MP;

    fn permutation_randomness(&self) -> &[Self::RandomVar];

    /// Returns the local cumulative sum of the permutation.
    fn regional_cumulative_sum(&self) -> &Self::RegionalSum;

    /// Returns the global cumulative sum of the permutation.
    fn global_cumulative_sum(&self) -> &SepticDigest<Self::GlobalSum>;
}
