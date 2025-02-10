//! And AIR for the Poseidon2 permutation.
extern crate alloc;

use crate::{
    chips::gadgets::poseidon2::constants::RoundConstants, configs::config::Poseidon2Config,
    machine::field::FieldSpecificPoseidon2Config,
};
use core::marker::PhantomData;
use p3_field::Field;
use typenum::Unsigned;

pub mod constraints;
pub mod traces;

pub(crate) type FieldSpecificPoseidon2Chip<F> = Poseidon2ChipP3<
    F,
    <F as FieldSpecificPoseidon2Config>::LinearLayers,
    <F as FieldSpecificPoseidon2Config>::Poseidon2Config,
>;
pub const POSEIDON2_CHIPNAME: &str = "Poseidon2";

/// A "vectorized" version of Poseidon2Air, for computing multiple Poseidon2 permutations per row.
pub struct Poseidon2ChipP3<F, LinearLayers, Config: Poseidon2Config> {
    pub(crate) constants: RoundConstants<F, Config>,
    pub _phantom: PhantomData<fn(LinearLayers) -> LinearLayers>,
}

impl<F, LinearLayers, Config: Poseidon2Config> Poseidon2ChipP3<F, LinearLayers, Config> {
    const HALF_FULL_ROUNDS: usize = Config::HalfFullRounds::USIZE;
}

impl<F: Field, LinearLayers, Config: Poseidon2Config> Default
    for Poseidon2ChipP3<F, LinearLayers, Config>
{
    fn default() -> Self {
        let constants = RoundConstants::default();
        Self {
            constants,
            _phantom: PhantomData,
        }
    }
}
