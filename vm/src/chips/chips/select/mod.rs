pub mod columns;
pub mod constraints;
#[cfg(test)]
mod tests;
pub mod trace;

use std::marker::PhantomData;

#[derive(Default)]
pub struct SelectChip<F> {
    pub _phantom: PhantomData<fn(F) -> F>,
}
