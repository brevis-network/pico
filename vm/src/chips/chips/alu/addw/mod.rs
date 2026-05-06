use std::marker::PhantomData;

pub mod columns;
pub mod constraints;
pub mod traces;

#[cfg(test)]
mod tests;

/// A chip that implements 64-bit ADDW for the opcode ADDW.
///
/// ADDW adds the lower 32 bits of two 64-bit operands and sign-extends the result to 64 bits.
/// Each row verifies `a = sign_extend_32(b + c)`.
/// Operands are stored as four u16 limbs (little-endian); the result is two u16 limbs + MSB.
#[derive(Default)]
pub struct AddwChip<F>(PhantomData<F>);
