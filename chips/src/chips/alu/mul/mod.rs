use std::marker::PhantomData;

use pico_compiler::word::WORD_SIZE;

pub mod columns;
pub mod constraints;
pub mod traces;
mod utils;

/// The number of digits in the product is at most the sum of the number of digits in the
/// multiplicands.
const PRODUCT_SIZE: usize = 2 * WORD_SIZE;

/// The mask for a byte.
const BYTE_MASK: u8 = 0xff;

/// A chip that implements multiplication for the multiplication opcodes.
#[derive(Default)]
pub struct MulChip<F>(PhantomData<F>);
