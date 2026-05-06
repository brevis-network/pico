use std::marker::PhantomData;

pub mod columns;
pub mod constraints;
pub mod event;
#[cfg(test)]
mod tests;
pub mod traces;

#[derive(Default)]
pub struct GlobalChip<F>(PhantomData<F>);
