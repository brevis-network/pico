mod columns;
mod constraints;
mod traces;

use crate::{
    chips::gadgets::poseidon2::constants::RoundConstants, configs::config::Poseidon2Config,
    machine::field::FieldSpecificPoseidon2Config, primitives::consts::PERMUTATION_WIDTH,
};
use core::marker::PhantomData;
use p3_field::Field;

/// The permutation state is `PERMUTATION_WIDTH` 32-bit words in guest memory.
const STATE_WORD_BYTES: usize = 4;

/// Bytes the permutation state occupies in guest memory.
pub(crate) const STATE_NUM_BYTES: u32 = (PERMUTATION_WIDTH * STATE_WORD_BYTES) as u32;

/// Dwords the permutation state occupies in guest memory.
///
/// RV64 memory is 8-byte granular: the emulator reads and writes this buffer with
/// `mr_dword_slice`/`mw_dword_slice`, one access per dword
/// (`emulator/riscv/syscalls/precompiles/poseidon2/permute.rs`). Each dword carries two
/// consecutive 32-bit state words, so the chip has half as many memory accesses as it has
/// state elements.
pub(crate) const STATE_NUM_DWORDS: usize = PERMUTATION_WIDTH / 2;

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

#[cfg(test)]
mod tests;
