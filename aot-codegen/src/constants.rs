//! AOT Codegen Tunable Constants
//!
//! All performance-tuning parameters are centralized here for easy adjustment.
//! These constants control various aspects of AOT compilation including chunk
//! sizing, lookup strategies, CFG analysis, and inline behavior.

// =============================================================================
// Chunking Strategy Constants
// =============================================================================

/// Desired blocks per chunk for auto-sizing heuristic
/// Used to prevent accidentally creating chunks with 1000+ blocks
/// Higher values = fewer chunks but slower per-chunk compilation
/// Lower values = more chunks, more parallelism, but more dispatch overhead
pub const DESIRED_BLOCKS_PER_CHUNK: usize = 144;

/// Default maximum number of chunks for auto-sizing
/// Limits the total number of chunk crates to prevent excessive overhead
/// Higher values = more parallelism but more compilation overhead
pub const DEFAULT_MAX_CHUNK_COUNT: usize = 256;

// =============================================================================
// CFG-Aware Chunking Constants
// =============================================================================

/// Minimum window size multiplier for CFG-aware chunk boundary search
/// The minimum chunk size is computed as: desired_blocks_per_chunk * this_multiplier
/// Range: [0.5, 1.0], recommended: 0.75
/// Lower values = more flexibility in chunk sizing, but may create very small chunks
pub const CFG_CHUNK_MIN_SIZE_MULTIPLIER: f64 = 0.75;

/// Maximum window size multiplier for CFG-aware chunk boundary search
/// The maximum chunk size is computed as: desired_blocks_per_chunk * this_multiplier
/// Range: [1.0, 2.0], recommended: 1.25
/// Higher values = more flexibility in chunk sizing, but may create very large chunks
pub const CFG_CHUNK_MAX_SIZE_MULTIPLIER: f64 = 1.25;

// =============================================================================
// CFG Edge Weight Constants
// =============================================================================

/// Base weight for fallthrough edges (sequential control flow)
/// Fallthrough edges are the most common and should be preserved within chunks
/// Higher values = higher penalty for splitting fallthrough paths
pub const CFG_EDGE_WEIGHT_FALLTHROUGH: u32 = 5;

/// Base weight for branch target edges (conditional jumps taken path)
/// Branch targets are moderately important to keep within chunks
/// Medium penalty for splitting branch targets across chunks
pub const CFG_EDGE_WEIGHT_BRANCH_TARGET: u32 = 3;

/// Base weight for JAL target edges (unconditional jumps/calls)
/// JAL targets are less critical since they're already indirect
/// Lower penalty for splitting JAL targets across chunks
pub const CFG_EDGE_WEIGHT_JAL_TARGET: u32 = 1;

/// Multiplier for back-edge weights (loops)
/// Back-edges indicate loops and should be strongly preserved within chunks
/// Applied to base edge weights when target_pc < source_pc
/// Higher values = much higher penalty for splitting loops across chunks
pub const CFG_EDGE_WEIGHT_BACK_EDGE_MULTIPLIER: u32 = 6;

// =============================================================================
// Inline Strategy Constants
// =============================================================================

/// Default threshold for #[inline(always)] - small blocks
/// Blocks with <= this many instructions get forced inlining
/// Recommended: 5-8 instructions
pub const DEFAULT_SMALL_BLOCK_THRESHOLD: u32 = 8;

/// Default threshold for #[inline] hint - medium blocks
/// Blocks with <= this many instructions (but > small threshold) get inline hint
/// Recommended: 16-24 instructions
pub const DEFAULT_MEDIUM_BLOCK_THRESHOLD: u32 = 24;

// =============================================================================
// Block Splitting Constants
// =============================================================================

/// Default maximum instructions per superblock before forced split.
/// Larger values improve locality but increase compile time and code size.
pub const DEFAULT_MAX_SUPERBLOCK_INSNS: u32 = 256;

/// Default maximum instructions per block before forced split.
/// Smaller values reduce interpreter fallback near chunk boundaries.
pub const DEFAULT_MAX_BLOCK_INSTRUCTIONS: u32 = 4096;

/// Maximum block count for chunk lookup to use #[inline(always)]
/// Chunks with more blocks will not be inlined to prevent cross-crate inlining explosion
/// Recommended: 20-30 blocks
pub const LOOKUP_INLINE_THRESHOLD: usize = 24;

// =============================================================================
// Chunk Lookup Strategy Constants
// =============================================================================

/// Dense index table: maximum range_words to consider dense strategy
/// If range exceeds this, run table is used instead
/// Higher values = allow dense index for larger address ranges, more memory usage
pub const DENSE_INDEX_MAX_RANGE_WORDS: usize = 8192;

/// Dense index table: maximum ratio of range_words to block count
/// Dense index is only used if: range_words <= ratio * block_count
/// Higher values = allow more sparse dense indexes, more memory usage
pub const DENSE_INDEX_MAX_RATIO: usize = 32;

/// Dense index table: minimum density threshold
/// Dense index is only used if: (block_count / range_words) >= threshold
/// Higher values = require denser blocks for dense index, more conservative
pub const DENSE_INDEX_MIN_DENSITY: f64 = 0.08;

// =============================================================================
// Page Hint Table Constants
// =============================================================================

/// Page hint table: target average chunks per page
/// Used for adaptive page size calculation in dispatch lookup
/// Higher values = larger pages, fewer page entries, coarser hints
/// Lower values = smaller pages, more page entries, finer hints
pub const PAGE_HINT_TARGET_CHUNKS_PER_PAGE: f64 = 1.5;

/// Page hint table: minimum page size in bytes
/// Must be a power of 2, recommended: 64 bytes
pub const PAGE_HINT_MIN_SIZE: u32 = 64;

/// Page hint table: maximum page size in bytes
/// Must be a power of 2, recommended: 4096 bytes (1 page)
pub const PAGE_HINT_MAX_SIZE: u32 = 4096;

/// Default page shift for page hint table (2^6 = 64 bytes)
/// Used when adaptive calculation fails or is disabled
pub const PAGE_HINT_DEFAULT_SHIFT: u32 = 6;
