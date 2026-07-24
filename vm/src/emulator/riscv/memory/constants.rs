pub const VALUES_SIZE: usize = 0x7800_0000;
pub const METADATA_SIZE: usize = VALUES_SIZE >> 3;
pub const NUM_REGISTERS: u32 = 32;

// SDK max memory (0x7800_0000 bytes) / 8 (bytes per dword) / 64 (bits per u64).
pub(super) const BITMAP_SIZE_U64: usize = (VALUES_SIZE >> 3) >> 6;

pub(super) const LOG_PAGE_LEN: usize = 14;
pub(super) const PAGE_LEN: usize = 1 << LOG_PAGE_LEN;
pub(super) const PAGE_MASK: usize = PAGE_LEN - 1;
