use std::marker::PhantomData;

pub mod columns;
pub mod constraints;
pub mod traces;

/// The type of memory chip that is being initialized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryChipType {
    Initialize,
    Finalize,
}

/// A memory chip that can initialize or finalize values in memory.
pub struct MemoryInitializeFinalizeChip<F> {
    pub kind: MemoryChipType,
    _phantom: PhantomData<F>,
}

impl<F> MemoryInitializeFinalizeChip<F> {
    /// Creates a new memory chip with a certain type.
    pub const fn new(kind: MemoryChipType) -> Self {
        Self {
            kind,
            _phantom: PhantomData,
        }
    }
}
