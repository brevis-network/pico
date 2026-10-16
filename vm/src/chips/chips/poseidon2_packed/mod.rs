//! An AIR for the Poseidon2 permutation with packed (Block-valued) memory I/O.
extern crate alloc;

use crate::{
    chips::gadgets::poseidon2::constants::RoundConstants, configs::config::Poseidon2Config,
    machine::field::FieldSpecificPoseidon2Config,
};
use core::marker::PhantomData;
use typenum::Unsigned;

mod columns;
pub mod constraints;
#[cfg(test)]
mod tests;
pub mod traces;

pub use columns::*;

pub(crate) type FieldSpecificPoseidon2PackedChip<F> = Poseidon2PackedChip<
    F,
    <F as FieldSpecificPoseidon2Config>::LinearLayers,
    <F as FieldSpecificPoseidon2Config>::Poseidon2Config,
>;
pub const POSEIDON2_PACKED_CHIPNAME: &str = "Poseidon2Packed";

/// A Poseidon2 permutation chip with packed I/O: the 16-lane state is read from
/// 4 memory Blocks (4 lanes each) and the output is written back as 4 Blocks.
/// One permutation per row (no DATAPAR packing).
pub struct Poseidon2PackedChip<F, LinearLayers, Config: Poseidon2Config> {
    pub(crate) constants: RoundConstants<F, Config>,
    pub _phantom: PhantomData<fn(LinearLayers) -> LinearLayers>,
}

impl<F, LinearLayers, Config: Poseidon2Config> Poseidon2PackedChip<F, LinearLayers, Config> {
    const HALF_FULL_ROUNDS: usize = Config::HalfFullRounds::USIZE;
}

impl<
        F: FieldSpecificPoseidon2Config<Poseidon2Config = Config>,
        LinearLayers,
        Config: Poseidon2Config,
    > Default for Poseidon2PackedChip<F, LinearLayers, Config>
{
    fn default() -> Self {
        let constants = RoundConstants::default();
        Self {
            constants,
            _phantom: PhantomData,
        }
    }
}
