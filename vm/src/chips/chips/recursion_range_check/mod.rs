pub mod columns;
pub mod constraints;
pub mod event;
pub mod opcode;
pub mod traces;

pub use event::RangeCheckEvent;
pub use opcode::*;
use std::marker::PhantomData;

/// The number of different range check operations.
pub const NUM_RANGE_CHECK_OPS: usize = 2;

/// A chip for computing range check operations.
///
/// The chip contains a preprocessed table of all possible range check operations. Other chips can
/// then use lookups into this table to range check their values.
#[derive(Debug, Clone, Copy, Default)]
pub struct RangeCheckChip<F>(PhantomData<F>);
