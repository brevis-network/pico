use crate::primitives::consts::PERMUTATION_WIDTH;
use serde::{Deserialize, Serialize};

/// The inputs and outputs to a Poseidon2 permutation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Poseidon2Event {
    pub input: [u32; PERMUTATION_WIDTH],
    pub output: [u32; PERMUTATION_WIDTH],
}
