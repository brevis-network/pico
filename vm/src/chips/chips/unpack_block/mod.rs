use std::marker::PhantomData;

mod columns;
mod constraints;
#[cfg(test)]
mod tests;
mod traces;

pub use columns::*;

/// Unpacks one memory Block into its `EXTENSION_DEGREE` single base-field lanes in a single
/// row.
///
/// One row reads the Block at the input address and writes each lane
/// `val.0[i]` to its own output address with a per-lane multiplicity. The
/// values are forwarded as-is (no algebraic constraints beyond the memory
/// lookups). On the packing path only the first `PACK_LANES` outputs are used;
/// the lowering backfills the others' multiplicity with zero.
#[derive(Default)]
pub struct UnpackBlockChip<F> {
    pub _phantom: PhantomData<fn(F) -> F>,
}
