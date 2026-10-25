use std::marker::PhantomData;

pub mod columns;
pub mod constraints;
pub mod traces;

#[cfg(test)]
mod tests;

/// A chip that implements the program multiplicity trace.
#[derive(Default)]
pub struct ProgramChip<F>(PhantomData<F>);
