use std::marker::PhantomData;

mod columns;
mod constraints;
#[cfg(test)]
mod tests;
mod traces;

pub use columns::*;

/// GKR fractional fold: (p1, q1) ⊕ (p2, q2) = (p1·q2 + p2·q1, q1·q2)
/// Each row of the trace performs one fold of two extension-field fractions.
#[derive(Default)]
pub struct FracFoldChip<F> {
    pub _phantom: PhantomData<fn(F) -> F>,
}
