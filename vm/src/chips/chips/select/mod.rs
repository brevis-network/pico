mod columns;
mod constraints;
mod trace;

use std::marker::PhantomData;

#[derive(Default)]
pub struct SelectChip<F> {
    pub _phantom: PhantomData<fn(F) -> F>,
}
