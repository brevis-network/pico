use crate::chips::gadgets::{uint256::U256Field, utils::field_params::NumWords};
use std::marker::PhantomData;
use typenum::Unsigned;

mod columns;
mod constraints;
mod traces;

type Uint256NumWords = <U256Field as NumWords>::WordsFieldElement;
pub const UINT256_NUM_WORDS: usize = Uint256NumWords::USIZE;

#[derive(Default)]
pub struct Uint256MulChip<F> {
    _phantom: PhantomData<F>,
}
