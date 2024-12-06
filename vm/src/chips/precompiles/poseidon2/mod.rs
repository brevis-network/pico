mod columns;
mod constraints;
mod traces;

use std::marker::PhantomData;

#[derive(Debug, Default)]
pub struct Poseidon2PermuteChip<F>(PhantomData<F>);
