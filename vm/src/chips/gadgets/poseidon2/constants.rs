use crate::{
    configs::config::Poseidon2Config,
    primitives::{consts::PERMUTATION_WIDTH, RC_16_30_U32},
};
use hybrid_array::Array;
use p3_field::Field;
use typenum::Unsigned;

/// Round constants for Poseidon2, in a format that's convenient for the AIR.
#[derive(Debug, Clone)]
pub struct RoundConstants<F, Config: Poseidon2Config> {
    pub(crate) beginning_full_round_constants:
        Array<[F; PERMUTATION_WIDTH], Config::HalfFullRounds>,
    pub(crate) partial_round_constants: Array<F, Config::PartialRounds>,
    pub(crate) ending_full_round_constants: Array<[F; PERMUTATION_WIDTH], Config::HalfFullRounds>,
}

impl<F: Field, Config: Poseidon2Config> Default for RoundConstants<F, Config> {
    fn default() -> Self {
        let mut beginning_full_round_constants = Array::<[F; _], _>::default();
        let mut partial_round_constants = Array::<F, _>::default();
        let mut ending_full_round_constants = Array::<[F; _], _>::default();
        #[allow(non_snake_case)]
        let FIELD_HALF_FULL_ROUNDS = Config::HalfFullRounds::USIZE;
        #[allow(non_snake_case)]
        let FIELD_PARTIAL_ROUNDS = Config::PartialRounds::USIZE;

        let mut pos = 0;
        for i in pos..FIELD_HALF_FULL_ROUNDS {
            for j in 0..PERMUTATION_WIDTH {
                beginning_full_round_constants[i][j] = F::from_wrapped_u32(RC_16_30_U32[i][j]);
            }
        }
        pos = FIELD_HALF_FULL_ROUNDS;

        for i in pos..(pos + FIELD_PARTIAL_ROUNDS) {
            partial_round_constants[i - pos] = F::from_wrapped_u32(RC_16_30_U32[i][0]);
        }
        pos += FIELD_PARTIAL_ROUNDS;

        for i in pos..(pos + FIELD_HALF_FULL_ROUNDS) {
            for j in 0..PERMUTATION_WIDTH {
                ending_full_round_constants[i - pos][j] = F::from_wrapped_u32(RC_16_30_U32[i][j]);
            }
        }

        Self {
            beginning_full_round_constants,
            partial_round_constants,
            ending_full_round_constants,
        }
    }
}
