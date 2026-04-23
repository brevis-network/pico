use std::marker::PhantomData;

mod columns;
mod constraints;
#[cfg(test)]
mod tests;
mod traces;

#[derive(Default)]
pub struct BatchFRIChip<F> {
    pub _phantom: PhantomData<fn(F) -> F>,
}
