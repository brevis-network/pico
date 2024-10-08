use std::marker::PhantomData;

pub mod columns;
pub mod constraints;
pub mod traces;
mod utils;

/// A chip that implements addition for the opcodes DIV/REM.
#[derive(Default)]
pub struct DivRemChip<F>(PhantomData<F>);
