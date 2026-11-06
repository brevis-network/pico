use std::marker::PhantomData;

mod columns;
mod constraints;
#[cfg(test)]
mod tests;
mod traces;

pub use columns::*;

/// Packs `PACK_LANES` single base-field values into one memory Block in a single row.
///
/// One row reads the first lane of each of the `PACK_LANES` input addresses and
/// writes `Block::packed([l0, .., l{PACK_LANES-1}])` (lane `PACK_LANES..` zero) to
/// the output address. The values are forwarded as-is (no algebraic constraints
/// beyond the memory lookups).
#[derive(Default)]
pub struct PackBlockChip<F> {
    pub _phantom: PhantomData<fn(F) -> F>,
}
