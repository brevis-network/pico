use std::marker::PhantomData;

pub mod columns;
pub mod constraints;
pub mod traces;

#[cfg(test)]
mod tests;

/// A chip that implements 64-bit subtraction for the opcode SUB.
///
/// Each row verifies `a = b - c` (mod 2^64) for a single SUB operation.
/// Operands are stored as four u16 limbs (little-endian) to match `SubGadget`.
#[derive(Default)]
pub struct SubChip<F>(PhantomData<F>);
