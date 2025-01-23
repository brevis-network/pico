use crate::primitives::{
    consts::PERMUTATION_WIDTH, FIELD_HALF_FULL_ROUNDS, FIELD_PARTIAL_ROUNDS, RC_16_30_U32,
};
use p3_field::Field;

/// Round constants for Poseidon2, in a format that's convenient for the AIR.
#[derive(Debug, Clone)]
pub struct RoundConstants<F: Field> {
    pub(crate) beginning_full_round_constants: [[F; PERMUTATION_WIDTH]; FIELD_HALF_FULL_ROUNDS],
    pub(crate) partial_round_constants: [F; FIELD_PARTIAL_ROUNDS],
    pub(crate) ending_full_round_constants: [[F; PERMUTATION_WIDTH]; FIELD_HALF_FULL_ROUNDS],
}

impl<F: Field> RoundConstants<F> {
    pub fn new() -> Self {
        let mut beginning_full_round_constants =
            [[F::ZERO; PERMUTATION_WIDTH]; FIELD_HALF_FULL_ROUNDS];
        let mut partial_round_constants = [F::ZERO; FIELD_PARTIAL_ROUNDS];
        let mut ending_full_round_constants =
            [[F::ZERO; PERMUTATION_WIDTH]; FIELD_HALF_FULL_ROUNDS];

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
