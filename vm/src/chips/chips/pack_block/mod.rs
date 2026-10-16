use std::marker::PhantomData;

mod columns;
mod constraints;
#[cfg(test)]
mod tests;
mod traces;

pub use columns::*;

/// Packs 4 single base-field lanes into one memory Block in a single row.
///
/// One row reads the first lane of each of the 4 input addresses and writes the
/// Block `[l0, l1, l2, l3]` to the output address. The values are forwarded
/// as-is (no algebraic constraints beyond the memory lookups).
#[derive(Default)]
pub struct PackBlockChip<F> {
    pub _phantom: PhantomData<fn(F) -> F>,
}
