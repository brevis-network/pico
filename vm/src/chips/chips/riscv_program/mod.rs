use std::marker::PhantomData;

pub mod columns;
pub mod constraints;
#[cfg(test)]
mod tests;
pub mod traces;

/// A chip that implements addition for the opcodes ADD and ADDI.
#[derive(Default)]
pub struct ProgramChip<F>(PhantomData<F>);
