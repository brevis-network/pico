use std::marker::PhantomData;

pub mod columns;
pub mod constraints;
#[cfg(test)]
mod tests;
pub mod traces;

/// A chip that implements 64-bit addition for the opcode ADD.
///
/// Each row verifies `a = b + c` (mod 2^64) for a single ADD operation.
/// Operands are stored as four u16 limbs (little-endian) to match `AddGadget`.
#[derive(Default)]
pub struct AddChip<F>(PhantomData<F>);
