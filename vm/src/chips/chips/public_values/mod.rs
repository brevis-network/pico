use std::marker::PhantomData;

mod columns;
mod constraints;
#[cfg(test)]
mod tests;
mod traces;

pub(crate) const PUB_VALUES_LOG_HEIGHT: usize = 4;
#[derive(Default)]
pub struct PublicValuesChip<F> {
    _phantom: PhantomData<F>,
}
