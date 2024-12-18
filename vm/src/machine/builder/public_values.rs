//! Permutation associating builder functions

use super::ChipBuilder;
use p3_air::{AirBuilder, FilteredAirBuilder};
use p3_field::Field;

impl<F: Field, AB: AirBuilder<F = F> + PublicValuesBuilder> ChipBuilder<F>
    for FilteredAirBuilder<'_, AB>
{
    fn preprocessed(&self) -> Self::M {
        panic!("Should not be called!")
    }
}

impl<AB: PublicValuesBuilder> PublicValuesBuilder for FilteredAirBuilder<'_, AB> {
    type PublicVar = AB::PublicVar;

    fn public_values(&self) -> &[Self::PublicVar] {
        self.inner.public_values()
    }
}

/// AirBuilder with public values
/// originally from AirBuilderWithPublicValues in p3
pub trait PublicValuesBuilder: AirBuilder {
    type PublicVar: Into<Self::Expr> + Copy;

    fn public_values(&self) -> &[Self::PublicVar];
}
