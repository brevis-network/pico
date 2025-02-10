use std::marker::PhantomData;

use p3_keccak_air::KeccakAir;

mod columns;
mod constraint;
mod traces;

pub(crate) const STATE_SIZE: usize = 25;

// The permutation state is 25 u64's.  Our word size is 32 bits, so it is 50 words.
pub const STATE_NUM_WORDS: usize = STATE_SIZE * 2;

#[derive(Debug)]
pub struct KeccakPermuteChip<F> {
    p3_keccak: KeccakAir,
    _marker: PhantomData<fn(F) -> F>,
}

impl<T: Default> Default for KeccakPermuteChip<T> {
    fn default() -> Self {
        KeccakPermuteChip {
            p3_keccak: KeccakAir {},
            _marker: PhantomData,
        }
    }
}
