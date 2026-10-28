use crate::{
    configs::config::Poseidon2Config, machine::field::FieldSpecificPoseidon2Config,
    primitives::consts::PERMUTATION_WIDTH,
};
use hybrid_array::Array;
use p3_field::Field;
#[cfg(feature = "cuda")]
use typenum::Unsigned;

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

impl<F: Field, Config: Poseidon2Config> RoundConstants<F, Config> {
    #[cfg(feature = "cuda")]
    /// Flatten into the GPU kernel's round-constant table layout: one `PERMUTATION_WIDTH`-wide row
    /// per round — the beginning half-full rounds, then one row per partial round (the constant in
    /// lane 0, the rest zero — the kernel reads only lane 0), then the ending half-full rounds.
    /// The GPU library compiles no round constants in; every Poseidon2 trace-gen ships the chip's
    /// own constants to the device in this layout.
    pub(crate) fn flatten_for_gpu(&self) -> Vec<F> {
        let half_full = Config::HalfFullRounds::USIZE;
        let partial = Config::PartialRounds::USIZE;
        let mut out = Vec::with_capacity((2 * half_full + partial) * PERMUTATION_WIDTH);
        for row in self.beginning_full_round_constants.iter() {
            out.extend_from_slice(row);
        }
        for &c in self.partial_round_constants.iter() {
            out.push(c);
            out.extend(std::iter::repeat_n(F::ZERO, PERMUTATION_WIDTH - 1));
        }
        for row in self.ending_full_round_constants.iter() {
            out.extend_from_slice(row);
        }
        out
    }
}
