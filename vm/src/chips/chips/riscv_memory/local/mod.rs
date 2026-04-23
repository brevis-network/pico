use std::marker::PhantomData;

pub mod columns;
pub mod constraints;
#[cfg(test)]
mod tests;
pub mod traces;

#[derive(Default)]
pub struct MemoryLocalChip<F>(PhantomData<F>);
