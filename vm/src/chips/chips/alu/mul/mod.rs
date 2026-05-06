use std::marker::PhantomData;

/// A chip that implements multiplication for the multiplication opcodes.
#[derive(Default)]
pub struct MulChip<F>(PhantomData<F>);

pub mod columns;
pub mod constraints;
#[cfg(test)]
pub mod tests;
pub mod traces;
