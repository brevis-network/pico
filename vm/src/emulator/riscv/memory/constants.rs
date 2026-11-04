/// Guest memory, one byte per address: `layout::MEMORY_SIZE`.
pub const VALUES_SIZE: usize = crate::primitives::layout::MEMORY_SIZE as usize;
pub const METADATA_SIZE: usize = VALUES_SIZE >> 3;
pub const NUM_REGISTERS: u32 = 32;

// Guest memory (`VALUES_SIZE` bytes) / 8 (bytes per dword) / 64 (bits per u64).
pub(super) const BITMAP_SIZE_U64: usize = (VALUES_SIZE >> 3) >> 6;

pub(super) const LOG_PAGE_LEN: usize = 14;
pub(super) const PAGE_LEN: usize = 1 << LOG_PAGE_LEN;
pub(super) const PAGE_MASK: usize = PAGE_LEN - 1;
