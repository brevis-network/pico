use std::marker::PhantomData;

mod columns;
mod constraints;
#[cfg(test)]
mod tests;
mod traces;

pub use columns::*;

/// MLE column opening consistency verifier.
///
/// Each row asserts that a specific (air_id, col_id) column, evaluated
/// at the multi-linear evaluation point `xi`, equals `opening_value`.
/// The actual sumcheck derivation of `opening_value` happens in the
/// BatchConstraint sumcheck; this chip just ensures the claimed opening
/// is consistently referenced across the proof.
///
/// The constraint is a membership check: the verifier looks up
/// `(air_id, col_id, opening_value)` from a bus that the BatchConstraint
/// module populates.  Implemented here as a simple equality check on the
/// trace column to the looked-up value.
#[derive(Default)]
pub struct MleOpenChip<F> {
    pub _phantom: PhantomData<fn(F) -> F>,
}
