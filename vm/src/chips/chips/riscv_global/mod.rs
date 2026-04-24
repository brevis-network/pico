use std::marker::PhantomData;

pub mod columns;
pub mod constraints;
pub mod event;
pub mod traces;

#[derive(Default)]
pub struct GlobalChip<F>(PhantomData<F>);
