use std::marker::PhantomData;

pub mod columns;
pub mod constraints;
pub mod event;
pub mod traces;
pub mod utils;

/// The number of different range check operations.
pub const NUM_RANGECHECK_OPS: usize = 3;

/// A chip for computing range checks
///
/// The chip contains a preprocessed table of byte lookups under 2^16.
#[derive(Debug, Clone, Copy, Default)]
pub struct RangeCheckChip<R, P, F>(PhantomData<(R, P, F)>);
