use crate::primitives::consts::{
    BENCH_MAX_CHUNK_BATCH_SIZE, BENCH_MAX_CHUNK_SIZE, BENCH_MAX_DEFERRED_SPLIT_THRESHOLD,
    BENCH_RECURSION_MAX_CHUNK_SIZE, MAX_LOG_NUMBER_OF_CHUNKS, TEST_CHUNK_BATCH_SIZE,
    TEST_CHUNK_SIZE, TEST_DEFERRED_SPLIT_THRESHOLD,
};
use serde::{Deserialize, Serialize};
use std::env;
use sysinfo::System;
use tracing::debug;

/// Options for the core prover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmulatorOpts {
    /// The size of a chunk in terms of cycles.
    pub chunk_size: u32,
    /// The size of a batch of chunks in terms of cycles.
    pub chunk_batch_size: u32,
    /// Options for splitting deferred events.
    pub split_opts: SplitOpts,
    /// The maximum number of cpu cycles to use for emulation.
    pub max_cycles: Option<u64>,
}

impl Default for EmulatorOpts {
    fn default() -> Self {
        let sys = System::new_all();
        let total_available_mem = sys.total_memory() / (1024 * 1024 * 1024);
        let auto_chunk_size = chunk_size(total_available_mem);
        let auto_chunk_batch_size = chunk_batch_size(total_available_mem);
        debug!("Total available memory: {:?}", total_available_mem);

        let split_threshold = env::var("SPLIT_THRESHOLD")
            .map(|s| s.parse::<usize>().unwrap_or(auto_chunk_size as usize >> 2))
            .unwrap_or(auto_chunk_size as usize >> 2);

        let default_chunk_size = env::var("CHUNK_SIZE").map_or_else(
            |_| auto_chunk_size,
            |s| s.parse::<u32>().unwrap_or(auto_chunk_size),
        );
        let default_chunk_batch_size = env::var("CHUNK_BATCH_SIZE").map_or_else(
            |_| auto_chunk_batch_size,
            |s| s.parse::<u32>().unwrap_or(auto_chunk_batch_size),
        );
        let default_max_cycles = (default_chunk_size as u64) * (2 << MAX_LOG_NUMBER_OF_CHUNKS);

        Self {
            chunk_size: default_chunk_size,
            chunk_batch_size: default_chunk_batch_size,
            split_opts: SplitOpts::new(split_threshold),
            max_cycles: default_max_cycles.into(),
        }
    }
}

impl EmulatorOpts {
    pub fn test_opts() -> Self {
        Self {
            chunk_size: env::var("CHUNK_SIZE").map_or_else(
                |_| TEST_CHUNK_SIZE,
                |s| s.parse::<u32>().unwrap_or(TEST_CHUNK_SIZE),
            ),
            chunk_batch_size: env::var("CHUNK_BATCH_SIZE").map_or_else(
                |_| TEST_CHUNK_BATCH_SIZE,
                |s| s.parse::<u32>().unwrap_or(TEST_CHUNK_BATCH_SIZE),
            ),
            split_opts: SplitOpts::new(TEST_DEFERRED_SPLIT_THRESHOLD),
            ..Default::default()
        }
    }

    fn bench_default_opts() -> (usize, u32, u32) {
        let split_threshold = env::var("SPLIT_THRESHOLD")
            .map(|s| {
                s.parse::<usize>()
                    .unwrap_or(BENCH_MAX_DEFERRED_SPLIT_THRESHOLD)
            })
            .unwrap_or(BENCH_MAX_DEFERRED_SPLIT_THRESHOLD);

        (
            split_threshold,
            BENCH_MAX_CHUNK_SIZE,
            BENCH_MAX_CHUNK_BATCH_SIZE,
        )
    }

    pub fn bench_riscv_ops() -> Self {
        let (split_threshold, default_chunk_size, default_chunk_batch_size) =
            Self::bench_default_opts();
        Self {
            chunk_size: env::var("CHUNK_SIZE").map_or_else(
                |_| default_chunk_size,
                |s| s.parse::<u32>().unwrap_or(default_chunk_size),
            ),
            chunk_batch_size: env::var("CHUNK_BATCH_SIZE").map_or_else(
                |_| default_chunk_batch_size,
                |s| s.parse::<u32>().unwrap_or(default_chunk_batch_size),
            ),
            split_opts: SplitOpts::new(split_threshold),
            ..Default::default()
        }
    }

    pub fn bench_recursion_opts() -> Self {
        let (split_threshold, _, default_chunk_batch_size) = Self::bench_default_opts();
        Self {
            chunk_size: BENCH_RECURSION_MAX_CHUNK_SIZE,
            chunk_batch_size: env::var("CHUNK_BATCH_SIZE").map_or_else(
                |_| default_chunk_batch_size,
                |s| s.parse::<u32>().unwrap_or(default_chunk_batch_size),
            ),
            split_opts: SplitOpts::new(split_threshold),
            ..Default::default()
        }
    }
}

/// Options for splitting deferred events.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitOpts {
    /// The threshold for default events.
    pub deferred: usize,
    /// The threshold for keccak events.
    pub keccak: usize,
    /// The threshold for sha extend events.
    pub sha_extend: usize,
    /// The threshold for sha compress events.
    pub sha_compress: usize,
    /// The threshold for memory events.
    pub memory: usize,
}

impl SplitOpts {
    /// Create a new [`SplitOpts`] with the given threshold.
    #[must_use]
    pub fn new(deferred_shift_threshold: usize) -> Self {
        Self {
            deferred: deferred_shift_threshold,
            keccak: 4 * deferred_shift_threshold / 24,
            sha_extend: 16 * deferred_shift_threshold / 48,
            sha_compress: 16 * deferred_shift_threshold / 80,
            memory: 8 * deferred_shift_threshold * 4,
        }
    }
}

#[allow(clippy::cast_precision_loss)]
fn chunk_size(total_available_mem: u64) -> u32 {
    let log_shard_size = match total_available_mem {
        0..=15 => 17,
        m => ((m as f64).log2() + 13.2).floor() as usize,
    };
    std::cmp::min(1 << log_shard_size, BENCH_MAX_CHUNK_SIZE)
}

fn chunk_batch_size(total_available_mem: u64) -> u32 {
    match total_available_mem {
        0..16 => 1,
        16..48 => 2,
        48..128 => 4,
        128..512 => 8,
        _ => BENCH_MAX_CHUNK_BATCH_SIZE,
    }
}
