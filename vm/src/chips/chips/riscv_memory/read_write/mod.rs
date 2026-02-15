use std::marker::PhantomData;

pub mod columns;
pub mod constraints;
pub mod traces;

#[cfg(test)]
mod tests;

/// A chip for memory read and write
#[derive(Default)]
pub struct MemoryReadWriteChip<F>(PhantomData<F>);
