mod columns;
mod constraints;
mod traces;

use crate::configs::config::Poseidon2Config;
use core::marker::PhantomData;
use typenum::Unsigned;

#[derive(Debug)]
pub struct Poseidon2PermuteChip<F, Config>(PhantomData<fn(F, Config) -> (F, Config)>);

impl<F, Config> Default for Poseidon2PermuteChip<F, Config> {
    fn default() -> Self {
        Self(PhantomData)
    }
}

impl<F, Config: Poseidon2Config> Poseidon2PermuteChip<F, Config> {
    const NUM_EXTERNAL_ROUNDS: usize = Config::ExternalRounds::USIZE;
    const NUM_INTERNAL_ROUNDS: usize = Config::InternalRounds::USIZE;
    const HALF_EXTERNAL_ROUNDS: usize = Config::HalfExternalRounds::USIZE;
}
