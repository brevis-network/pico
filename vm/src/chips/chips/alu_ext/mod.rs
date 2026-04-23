use std::marker::PhantomData;

pub mod columns;
mod constraints;
mod traces;

#[cfg(test)]
mod tests;

#[derive(Default)]
pub struct ExtAluChip<F> {
    pub _phantom: PhantomData<fn(F) -> F>,
}
