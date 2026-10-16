//! Public-value access for chip builders.
//!
//! Plonky3's `AirBuilder` carries `PublicVar` / `public_values()` itself since 0.5, so this is a
//! marker every `AirBuilder` satisfies; it stays so the `ChipBuilder` trait stack keeps its shape.

use super::ChipBuilder;
use p3_air::{AirBuilder, FilteredAirBuilder};
use p3_field::Field;

impl<F: Field, AB: AirBuilder<F = F> + ChipBuilder<F>> ChipBuilder<F>
    for FilteredAirBuilder<'_, AB>
{
}

/// Builder that exposes public values (every `AirBuilder` does).
pub trait PublicValuesBuilder: AirBuilder {}

impl<AB: AirBuilder> PublicValuesBuilder for AB {}
