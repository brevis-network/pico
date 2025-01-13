use std::marker::PhantomData;

mod columns;
mod constraints;
mod traces;

#[derive(Default)]
pub struct BatchFRIChip<const DEGREE: usize, const W: u32, F> {
    pub _phantom: PhantomData<fn(F) -> F>,
}
