use std::marker::PhantomData;

mod columns;
mod constraints;
mod traces;

#[derive(Default)]
pub struct BatchFRIChip<const DEGREE: usize, F> {
    pub _phantom: PhantomData<fn(F) -> F>,
}
