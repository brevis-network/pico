use std::marker::PhantomData;

mod columns;
mod constraints;
#[cfg(test)]
mod tests;
mod traces;

pub use columns::*;

/// Asserts that the extension-field value at a given memory address equals zero.
///
/// No output is produced; the chip reads one EF value and enforces val == 0.
/// Used to implement equality checks (assert_ext_eq(a, b) = assert_ext_zero(a - b))
/// and the WHIR final-claim check (final_poly(r) == whir_claim).
#[derive(Default)]
pub struct AssertZeroExtChip<F> {
    pub _phantom: PhantomData<fn(F) -> F>,
}
