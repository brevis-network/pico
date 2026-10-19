use crate::{
    configs::config::Poseidon2Config, machine::field::FieldSpecificPoseidon2Config,
    primitives::consts::PERMUTATION_WIDTH,
};
use hybrid_array::Array;

/// Round constants for Poseidon2, in a format that's convenient for the AIR.
#[derive(Debug, Clone)]
pub struct RoundConstants<F, Config: Poseidon2Config> {
    pub(crate) beginning_full_round_constants:
        Array<[F; PERMUTATION_WIDTH], Config::HalfFullRounds>,
    pub(crate) partial_round_constants: Array<F, Config::PartialRounds>,
    pub(crate) ending_full_round_constants: Array<[F; PERMUTATION_WIDTH], Config::HalfFullRounds>,
}

impl<F: FieldSpecificPoseidon2Config<Poseidon2Config = Config>, Config: Poseidon2Config> Default
    for RoundConstants<F, Config>
{
    fn default() -> Self {
        F::round_constants()
    }
}
