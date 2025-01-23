//! And AIR for the Poseidon2 permutation.
extern crate alloc;

use crate::{
    chips::gadgets::poseidon2::constants::RoundConstants,
    machine::field::FieldSpecificPoseidon2Config,
};
use p3_field::Field;
use std::marker::PhantomData;

pub mod constraints;
pub mod event;
pub mod traces;

pub use event::Poseidon2Event;

pub type Poseidon2Chip<F> = Poseidon2ChipP3<F, <F as FieldSpecificPoseidon2Config>::LinearLayers>;

/// A "vectorized" version of Poseidon2Air, for computing multiple Poseidon2 permutations per row.
pub struct Poseidon2ChipP3<F: Field, LinearLayers> {
    pub(crate) constants: RoundConstants<F>,
    pub _phantom: PhantomData<fn(LinearLayers) -> LinearLayers>,
}

impl<F: Field, LinearLayers> Default for Poseidon2ChipP3<F, LinearLayers> {
    fn default() -> Self {
        let constants = RoundConstants::new();
        Self {
            constants,
            _phantom: PhantomData,
        }
    }
}
