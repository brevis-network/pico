pub mod columns;
pub mod constraints;
pub mod traces;

use std::marker::PhantomData;

#[derive(Default)]
pub struct MemoryVarChip<F>(PhantomData<F>);
