use pico_derive::AlignedBorrow;

use crate::chips::chips::recursion_memory::MemoryAccessCols;

pub const NUM_EXP_BITS_LEN_COLS: usize = core::mem::size_of::<ExpBitsLenCols<u8>>();
pub const NUM_EXP_BITS_LEN_PREPROCESSED_COLS: usize =
    core::mem::size_of::<ExpBitsLenPreprocessedCols<u8>>();

/// Number of trace rows in one `ExpBitsLen` request block.
///
/// Rows `0..=30` decompose the 31 canonical bits of the field element (KoalaBear is a 31-bit
/// field); row `31` is the terminal row.
pub const NUM_BITS_MAX_PLUS_ONE: usize = 32;

/// Width of the KoalaBear "low region" used by the `< p` canonicality check.
///
/// `p = 2^31 - 2^24 + 1 = 127 * 2^24 + 1`, so `p mod 2^24 = 1` and `p >> 24 = 127` (bits 24..30 all
/// one). The low region is bits `0..23` (24 bits); the high region is bits `24..30` (7 bits).
pub const LOW_BITS_COUNT: usize = 24;

/// Program-fixed (preprocessed) columns for the `ExpBitsLen` chip.
///
/// `is_first`/`is_last`/`is_real` are baked here by `generate_preprocessed` (they are program
/// structure, not witnessed data). Memory I/O follows the recursion memory-bus convention: negative `mult`
/// encodes a read, positive `mult` encodes a write (the write count is backfilled from
/// `read_counts` in `convert.rs`'s `finish()`).
#[derive(AlignedBorrow, Clone, Copy, Debug)]
#[repr(C)]
pub struct ExpBitsLenPreprocessedCols<T: Copy> {
    /// First row of a 32-row request block.
    pub is_first: T,
    /// Terminal row of a 32-row request block.
    pub is_last: T,
    /// Marks rows that belong to a request rather than trailing padding.
    pub is_real: T,
    /// Input read of the field element to decompose (read on the `is_first` row only).
    pub bit_src_in: MemoryAccessCols<T>,
    /// Output write of the final `result` (written on the `is_first` row only).
    pub result_out: MemoryAccessCols<T>,
    /// Output write of this row's decomposition bit (`bit_src_mod_2`).
    pub bit_out: MemoryAccessCols<T>,
    /// Per-request `base` constant, injected on the `is_first` row.
    pub base_const: T,
    /// Per-request `num_bits` constant, injected on the `is_first` row.
    pub num_bits_const: T,
}

/// Witnessed (main) columns for the `ExpBitsLen` chip.
#[derive(AlignedBorrow, Debug, Clone, Copy)]
#[repr(C)]
pub struct ExpBitsLenCols<T: Copy> {
    /// Bit position carried by this row (`0..=31`).
    pub bit_idx: T,
    /// `base^(2^bit_idx)`.
    pub base: T,
    /// Remaining suffix of the canonical 31-bit decomposition after shifting right by `bit_idx`.
    pub bit_src: T,
    /// Remaining number of low bits that still affect `result`.
    pub num_bits: T,
    /// Boolean witness for `num_bits != 0`.
    pub apply_bit: T,
    /// Countdown for the low 24 bits of the KoalaBear `< p` canonicality check.
    pub low_bits_left: T,
    /// Boolean witness for `low_bits_left != 0`.
    pub in_low_region: T,
    /// Running (reverse) product for the requested low-bit exponentiation. On the `is_first` row
    /// this equals the final `base^(bit_src mod 2^num_bits)`.
    pub result: T,
    /// Multiplies `result` by either `1` or `base` across the transition.
    pub result_multiplier: T,
    /// Current decomposition bit (`bit_idx`-th canonical bit of the field element).
    pub bit_src_mod_2: T,
    /// Running flag: all low bits `b0..b23` seen so far are zero.
    pub low_bits_are_zero: T,
    /// Running flag: all high bits `b24..b30` seen so far are one.
    pub high_bits_all_one: T,
}
