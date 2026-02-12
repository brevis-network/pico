//! AOT Compilation Metrics
//!
//! This module provides structures for collecting and saving metrics about
//! the AOT compilation process, including program-level and chunk-level statistics.

use serde::{Deserialize, Serialize};

/// Lookup strategy used for a chunk
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LookupStrategy {
    /// Small match statement (n <= LOOKUP_INLINE_THRESHOLD)
    SmallMatch,
    /// Dense index table (O(1) lookup)
    DenseIndex,
    /// Run table with binary search (O(log r) lookup)
    RunTable,
}

/// Metrics for a single chunk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkMetrics {
    /// Chunk index
    pub chunk_idx: usize,
    /// Number of blocks in this chunk
    pub block_count: usize,
    /// Minimum PC address in this chunk
    pub pc_min: u32,
    /// Maximum PC address in this chunk
    pub pc_max: u32,
    /// PC range span in bytes
    pub pc_span: u32,
    /// Number of instruction words in the PC range
    pub range_words: usize,
    /// Block density (block_count / range_words)
    pub density: f64,
    /// Lookup strategy used for this chunk
    pub lookup_strategy: LookupStrategy,
    /// Total instruction count across all blocks in this chunk
    pub total_instructions: u32,
    /// Average instructions per block
    pub avg_instructions_per_block: f64,
    /// Minimum instructions in a block
    pub min_instructions_per_block: u32,
    /// Maximum instructions in a block
    pub max_instructions_per_block: u32,
    /// Median instructions per block
    pub median_instructions_per_block: f64,
    /// 90th percentile instructions per block
    pub p90_instructions_per_block: f64,
    /// Standard deviation of instructions per block
    pub stddev_instructions_per_block: f64,
    /// Number of contiguous runs (for RunTable strategy)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_count: Option<usize>,
    /// Size of dense index table if used (range_words)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dense_index_size: Option<usize>,
}

/// Overall program metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramMetrics {
    /// Total number of instructions in the program
    pub total_instructions: usize,
    /// Total number of basic blocks
    pub total_blocks: usize,
    /// Minimum PC address
    pub pc_min: u32,
    /// Maximum PC address
    pub pc_max: u32,
    /// PC range span in bytes
    pub pc_span: u32,
    /// Average instructions per block
    pub avg_instructions_per_block: f64,
    /// Minimum instructions in a block
    pub min_instructions_per_block: u32,
    /// Maximum instructions in a block
    pub max_instructions_per_block: u32,
    /// Median instructions per block
    pub median_instructions_per_block: f64,
    /// 90th percentile instructions per block
    pub p90_instructions_per_block: f64,
    /// Standard deviation of instructions per block
    pub stddev_instructions_per_block: f64,
}

/// Complete AOT compilation metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AotMetrics {
    /// Program-level metrics
    pub program: ProgramMetrics,
    /// Number of chunks generated
    pub chunk_count: usize,
    /// Average blocks per chunk
    pub avg_blocks_per_chunk: f64,
    /// Blocks per chunk used during compilation
    pub computed_blocks_per_chunk: usize,
    /// Per-chunk metrics
    pub chunks: Vec<ChunkMetrics>,
    /// Distribution of lookup strategies
    pub strategy_distribution: std::collections::HashMap<String, usize>,
}

impl AotMetrics {
    /// Create a new metrics structure
    pub fn new(
        program: ProgramMetrics,
        chunk_count: usize,
        computed_blocks_per_chunk: usize,
        chunks: Vec<ChunkMetrics>,
    ) -> Self {
        let avg_blocks_per_chunk = if chunk_count > 0 {
            program.total_blocks as f64 / chunk_count as f64
        } else {
            0.0
        };

        let mut strategy_distribution = std::collections::HashMap::new();
        for chunk in &chunks {
            let strategy_name = match chunk.lookup_strategy {
                LookupStrategy::SmallMatch => "small_match",
                LookupStrategy::DenseIndex => "dense_index",
                LookupStrategy::RunTable => "run_table",
            };
            *strategy_distribution
                .entry(strategy_name.to_string())
                .or_insert(0) += 1;
        }

        Self {
            program,
            chunk_count,
            avg_blocks_per_chunk,
            computed_blocks_per_chunk,
            chunks,
            strategy_distribution,
        }
    }

    /// Save metrics to a JSON file
    pub fn save_to_file(&self, path: &std::path::Path) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize metrics: {}", e))?;
        std::fs::write(path, json)
            .map_err(|e| format!("Failed to write metrics to {}: {}", path.display(), e))?;
        Ok(())
    }
}
