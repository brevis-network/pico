use std::marker::PhantomData;

pub mod constraints;
pub mod columns;
pub mod traces;
pub mod utils;

/// The number of different byte operations.
pub const NUM_BYTE_OPS: usize = 9;

/// The number of different byte lookup channels.
pub const NUM_BYTE_LOOKUP_CHANNELS: u8 = 16;

/// A chip for computing byte operations.
///
/// The chip contains a preprocessed table of all possible byte operations. Other chips can then
/// use lookups into this table to compute their own operations.
#[derive(Debug, Clone, Copy, Default)]
pub struct ByteChip<F>(PhantomData<F>);