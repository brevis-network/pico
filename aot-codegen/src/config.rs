//! AOT Compilation Configuration

use crate::constants;
use std::path::PathBuf;

/// Configuration for AOT compilation
#[derive(Debug, Clone)]
pub struct AotConfig {
    /// Output directory for generated chunk crates and dispatcher crate.
    pub output_path: PathBuf,

    /// Number of blocks per chunk
    /// Smaller chunks = more parallelism but more dispatch overhead
    /// Used only when target_chunk_count is None and blocks_per_chunk > 0.
    pub blocks_per_chunk: usize,

    /// Target number of chunks for auto sizing.
    /// When set, blocks_per_chunk is ignored.
    pub target_chunk_count: Option<usize>,

    /// Upper bound for auto-sized chunk count.
    pub max_chunk_count: usize,

    /// Maximum instructions per block before forced split.
    /// Set to 0 to disable block splitting.
    pub max_block_instructions: u32,

    /// Pure mode: blocks that only execute, on `pico_aot_pure::PureState`, with none of the
    /// proving bookkeeping, in crates named apart from the default mode's. A
    /// [`crate::RuntimeSpec::Entry`] then names `pico-aot-pure`.
    pub pure: bool,
}

impl AotConfig {
    /// Create a new AOT configuration with default settings
    pub fn new(output_path: PathBuf) -> Self {
        Self {
            output_path,
            blocks_per_chunk: 0,
            target_chunk_count: None,
            max_chunk_count: constants::DEFAULT_MAX_CHUNK_COUNT,
            max_block_instructions: constants::DEFAULT_MAX_BLOCK_INSTRUCTIONS,
            pure: false,
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

    /// Set the maximum instructions per block before forced split.
    pub fn with_max_block_instructions(mut self, max_block_instructions: u32) -> Self {
        self.max_block_instructions = max_block_instructions;
        self
    }

    /// Generate pure-mode crates.
    pub fn with_pure(mut self, pure: bool) -> Self {
        self.pure = pure;
        self
    }
}
