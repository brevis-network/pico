//! Builder functions for the septic extension elements

use super::ChipBuilder;
use crate::machine::septic::SepticExtension;
use p3_field::Field;

pub trait SepticExtensionBuilder<F: Field>: ChipBuilder<F> {
    /// Asserts that the two field extensions are equal.
    fn assert_septic_ext_eq<I: Into<Self::Expr>>(
        &mut self,
        left: SepticExtension<I>,
        right: SepticExtension<I>,
    ) {
        for (left, right) in left.0.into_iter().zip(right.0) {
            self.assert_eq(left, right);
        }
    }
}
