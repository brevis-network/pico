use crate::gadgets::is_zero::IsZeroOperation;
use core::mem::size_of;
use pico_derive::AlignedBorrow;
use pico_machine::word::Word;

pub const NUM_MEMORY_PROGRAM_PREPROCESSED_COLS: usize =
    size_of::<MemoryProgramPreprocessedCols<u8>>();
pub const NUM_MEMORY_PROGRAM_MULT_COLS: usize = size_of::<MemoryProgramMultCols<u8>>();

/// The column layout for the chip.
#[derive(AlignedBorrow, Clone, Copy, Default)]
#[repr(C)]
pub struct MemoryProgramPreprocessedCols<T> {
    pub addr: T,
    pub value: Word<T>,
    pub is_real: T,
}

/// Multiplicity columns.
#[derive(AlignedBorrow, Clone, Copy, Default)]
#[repr(C)]
pub struct MemoryProgramMultCols<T> {
    /// The multiplicity of the event.
    ///
    /// This column is technically redundant with `is_real`, but it's included for clarity.
    pub multiplicity: T,

    /// Whether the shard is the first shard.
    pub is_first_shard: IsZeroOperation<T>,
}

/// Chip that initializes memory that is provided from the program. The table is preprocessed and
/// receives each row in the first shard. This prevents any of these addresses from being
/// overwritten through the normal MemoryInit.
#[derive(Default)]
pub struct MemoryProgramChip;

impl MemoryProgramChip {
    pub const fn new() -> Self {
        Self {}
    }
}
