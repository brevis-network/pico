//! AOT Compilation Configuration

use crate::constants;
use std::path::PathBuf;

/// Configuration for AOT compilation
#[derive(Debug, Clone)]
pub struct AotConfig {
    /// Output directory for generated chunk crates and dispatcher crate.
    pub output_path: PathBuf,

    /// Enable post-processing optimizations
    pub enable_optimizations: bool,

    /// Number of blocks per chunk
    /// Smaller chunks = more parallelism but more dispatch overhead
    /// Used only when target_chunk_count is None and blocks_per_chunk > 0.
    pub blocks_per_chunk: usize,

    /// Target number of chunks for auto sizing.
    /// When set, blocks_per_chunk is ignored.
    pub target_chunk_count: Option<usize>,

    /// Upper bound for auto-sized chunk count.
    pub max_chunk_count: usize,

    /// Threshold for #[inline(always)] - blocks with <= this many instructions
    /// get forced inlining. Default: constants::DEFAULT_SMALL_BLOCK_THRESHOLD
    pub small_block_threshold: u32,

    /// Threshold for #[inline] hint - blocks with <= this many instructions
    /// (but > small_block_threshold) get an inline hint. Default: constants::DEFAULT_MEDIUM_BLOCK_THRESHOLD
    pub medium_block_threshold: u32,

    /// Maximum gap between consecutive block PCs in the same chunk (bytes).
    /// Gaps larger than this will start a new chunk. Default: u32::MAX (disabled).
    pub max_chunk_pc_gap: u32,

    /// Maximum instructions per block before forced split.
    /// Set to 0 to disable block splitting.
    pub max_block_instructions: u32,

    /// Maximum instructions per superblock before forced split.
    /// Larger values improve locality but increase compile time and code size.
    pub max_superblock_instructions: u32,

    /// Enable CFG-aware chunking (minimizes cross-chunk edges)
    /// When enabled, chunk boundaries are chosen to minimize control flow edges
    /// that cross chunk boundaries, preserving more direct jumps within chunks.
    /// Default: true
    pub enable_cfg_aware_chunking: bool,
}

impl AotConfig {
    /// Create a new AOT configuration with default settings
    pub fn new(output_path: PathBuf) -> Self {
        Self {
            output_path,
            enable_optimizations: true,
            blocks_per_chunk: 0,
            target_chunk_count: None,
            max_chunk_count: constants::DEFAULT_MAX_CHUNK_COUNT,
            small_block_threshold: constants::DEFAULT_SMALL_BLOCK_THRESHOLD,
            medium_block_threshold: constants::DEFAULT_MEDIUM_BLOCK_THRESHOLD,
            max_chunk_pc_gap: u32::MAX,
            max_block_instructions: constants::DEFAULT_MAX_BLOCK_INSTRUCTIONS,
            max_superblock_instructions: constants::DEFAULT_MAX_SUPERBLOCK_INSNS,
            enable_cfg_aware_chunking: true,
        }
    }

    /// Set the number of blocks per chunk
    pub fn with_chunk_size(mut self, blocks_per_chunk: usize) -> Self {
        self.blocks_per_chunk = blocks_per_chunk;
        self
    }

    /// Set the target chunk count for auto sizing.
    pub fn with_target_chunk_count(mut self, target_chunk_count: Option<usize>) -> Self {
        self.target_chunk_count = target_chunk_count;
        self
    }

    /// Set the maximum chunk count for auto sizing.
    pub fn with_max_chunk_count(mut self, max_chunk_count: usize) -> Self {
        self.max_chunk_count = max_chunk_count;
        self
    }

    /// Set inline thresholds for selective inlining
    pub fn with_inline_thresholds(mut self, small: u32, medium: u32) -> Self {
        self.small_block_threshold = small;
        self.medium_block_threshold = medium;
        self
    }

    /// Set the maximum PC gap (in bytes) allowed within a chunk.
    pub fn with_max_chunk_pc_gap(mut self, max_gap: u32) -> Self {
        self.max_chunk_pc_gap = max_gap;
        self
    }

    /// Set the maximum instructions per block before forced split.
    pub fn with_max_block_instructions(mut self, max_block_instructions: u32) -> Self {
        self.max_block_instructions = max_block_instructions;
        self
    }

    /// Set the maximum instructions per superblock before forced split.
    pub fn with_max_superblock_instructions(mut self, max_superblock_instructions: u32) -> Self {
        self.max_superblock_instructions = max_superblock_instructions;
        self
    }

    /// Enable or disable CFG-aware chunking
    pub fn with_cfg_aware_chunking(mut self, enable: bool) -> Self {
        self.enable_cfg_aware_chunking = enable;
        self
    }
}
