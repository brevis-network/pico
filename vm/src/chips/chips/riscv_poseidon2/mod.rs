//! And AIR for the Poseidon2 permutation.
extern crate alloc;

use crate::{
    chips::gadgets::poseidon2::constants::RoundConstants,
    machine::field::FieldSpecificPoseidon2Config,
    primitives::poseidon2::{babybear, koalabear},
};
use p3_field::Field;
use std::marker::PhantomData;

pub mod constraints;
pub mod event;
pub mod traces;

pub use event::Poseidon2Event;

pub type BabyBearPoseidon2Chip<F> = Poseidon2ChipP3<
    F,
    <F as FieldSpecificPoseidon2Config>::LinearLayers,
    { babybear::FIELD_HALF_FULL_ROUNDS },
    { babybear::FIELD_PARTIAL_ROUNDS },
    { babybear::FIELD_SBOX_REGISTERS },
>;

pub type KoalaBearPoseidon2Chip<F> = Poseidon2ChipP3<
    F,
    <F as FieldSpecificPoseidon2Config>::LinearLayers,
    { koalabear::FIELD_HALF_FULL_ROUNDS },
    { koalabear::FIELD_PARTIAL_ROUNDS },
    { koalabear::FIELD_SBOX_REGISTERS },
>;

/// A "vectorized" version of Poseidon2Air, for computing multiple Poseidon2 permutations per row.
pub struct Poseidon2ChipP3<
    F: Field,
    LinearLayers,
    const FIELD_HALF_FULL_ROUNDS: usize,
    const FIELD_PARTIAL_ROUNDS: usize,
    const FIELD_SBOX_REGISTERS: usize,
> {
    pub(crate) constants: RoundConstants<F, FIELD_HALF_FULL_ROUNDS, FIELD_PARTIAL_ROUNDS>,
    pub _phantom: PhantomData<fn(LinearLayers) -> LinearLayers>,
}

impl<
        F: Field,
        LinearLayers,
        const FIELD_HALF_FULL_ROUNDS: usize,
        const FIELD_PARTIAL_ROUNDS: usize,
        const FIELD_SBOX_REGISTERS: usize,
    > Default
    for Poseidon2ChipP3<
        F,
        LinearLayers,
        FIELD_HALF_FULL_ROUNDS,
        FIELD_PARTIAL_ROUNDS,
        FIELD_SBOX_REGISTERS,
    >
{
    fn default() -> Self {
        let constants = RoundConstants::new();
        Self {
            constants,
            _phantom: PhantomData,
        }
    }
}
