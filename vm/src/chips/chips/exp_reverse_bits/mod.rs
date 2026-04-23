pub mod columns;
pub mod constraints;
#[cfg(test)]
mod tests;
pub mod traces;

use columns::*;
use std::marker::PhantomData;

#[derive(Clone, Debug, Copy, Default)]
pub struct ExpReverseBitsLenChip<F> {
    pub _phantom: PhantomData<fn(F) -> F>,
}
