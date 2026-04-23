pub mod columns;
pub mod constraints;
#[cfg(test)]
mod tests;
pub mod traces;

use std::marker::PhantomData;

#[derive(Default)]
pub struct MemoryVarChip<F>(PhantomData<F>);
