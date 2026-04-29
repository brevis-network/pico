mod columns;
mod constraints;
mod traces;

use crate::{
    chips::gadgets::poseidon2::constants::RoundConstants, configs::config::Poseidon2Config,
    machine::field::FieldSpecificPoseidon2Config,
};
use core::marker::PhantomData;
use p3_field::Field;

pub type FieldSpecificPrecompilePoseidon2Chip<F> = Poseidon2PermuteChip<
    F,
    <F as FieldSpecificPoseidon2Config>::LinearLayers,
    <F as FieldSpecificPoseidon2Config>::Poseidon2Config,
>;

#[allow(clippy::type_complexity)]
#[derive(Debug)]
pub struct Poseidon2PermuteChip<F, LinearLayers, Config: Poseidon2Config> {
    pub(crate) constants: RoundConstants<F, Config>,
    pub _phantom: PhantomData<fn(LinearLayers) -> LinearLayers>,
}

impl<F: Field, LinearLayers, Config: Poseidon2Config> Default
    for Poseidon2PermuteChip<F, LinearLayers, Config>
{
    fn default() -> Self {
        let constants = RoundConstants::default();
        Self {
            constants,
            _phantom: PhantomData,
        }
    }
}
