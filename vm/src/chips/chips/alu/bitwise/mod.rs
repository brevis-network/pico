use std::marker::PhantomData;

pub mod columns;
pub mod constraints;
pub mod traces;

#[cfg(test)]
mod tests;

/// A chip that implements bitwise operations for the opcodes XOR, OR, and AND.
#[derive(Default)]
pub struct BitwiseChip<F>(PhantomData<F>);
