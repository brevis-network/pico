use std::marker::PhantomData;

mod columns;
mod constraints;
#[cfg(test)]
mod tests;
mod traces;

pub use columns::*;

/// Bit-select of a full 8-lane digest in a single row.
///
/// One row constrains out[i] = bit * in2[i] + (1 - bit) * in1[i] for all 8
/// digest lanes (the same algebra as the SelectChip's out1 lane, widened to a
/// digest). Used by the Merkle path verification in the convert lowering,
/// replacing 8 Select instructions per tree level with one instruction.
#[derive(Default)]
pub struct DigestSelectChip<F> {
    pub _phantom: PhantomData<fn(F) -> F>,
}
