pub mod air;
pub mod columns;
mod event;
mod trace;
pub use event::*;

pub use columns::*;

#[derive(Default)]
pub struct CpuChip<F, const L: usize> {
    pub fixed_log2_rows: Option<usize>,
    pub _phantom: std::marker::PhantomData<F>,
}
