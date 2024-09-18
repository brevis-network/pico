use std::marker::PhantomData;

pub mod columns;
pub mod constraints;
pub mod traces;

/// Chip that initializes memory that is provided from the program. The table is preprocessed and
/// receives each row in the first shard. This prevents any of these addresses from being
/// overwritten through the normal MemoryInit.
#[derive(Default)]
pub struct MemoryProgramChip<F>(PhantomData<F>);
