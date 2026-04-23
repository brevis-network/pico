use std::marker::PhantomData;

pub mod columns;
pub mod constraints;
#[cfg(test)]
mod tests;
pub mod traces;

/// A chip for memory read and write
#[derive(Default)]
pub struct MemoryReadWriteChip<F>(PhantomData<F>);
