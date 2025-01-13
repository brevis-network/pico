mod columns;
mod constraints;
mod traces;

use std::marker::PhantomData;

#[derive(Debug, Default)]
pub struct Poseidon2PermuteChip<
    F,
    const HALF_EXTERNAL_ROUNDS: usize,
    const NUM_INTERNAL_ROUNDS: usize,
>(PhantomData<F>);
