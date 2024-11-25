use std::env;

use serde::{Deserialize, Serialize};

use crate::primitives::consts::{
    DEFAULT_CHUNK_BATCH_SIZE, DEFAULT_CHUNK_SIZE, DEFERRED_SPLIT_THRESHOLD, TEST_CHUNK_BATCH_SIZE,
    TEST_CHUNK_SIZE, TEST_DEFERRED_SPLIT_THRESHOLD,
};

/// Options for the core prover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmulatorOpts {
    /// The size of a chunk in terms of cycles.
    pub chunk_size: usize,
    /// The size of a batch of chunks in terms of cycles.
    pub chunk_batch_size: usize,
    /// Options for splitting deferred events.
    pub split_opts: SplitOpts,
}

impl Default for EmulatorOpts {
    fn default() -> Self {
        let split_threshold = env::var("SPLIT_THRESHOLD")
            .map(|s| s.parse::<usize>().unwrap_or(DEFERRED_SPLIT_THRESHOLD))
            .unwrap_or(DEFERRED_SPLIT_THRESHOLD);
        Self {
            chunk_size: env::var("CHUNK_SIZE").map_or_else(
                |_| DEFAULT_CHUNK_SIZE,
                |s| s.parse::<usize>().unwrap_or(DEFAULT_CHUNK_SIZE),
            ),
            chunk_batch_size: env::var("CHUNK_BATCH_SIZE").map_or_else(
                |_| DEFAULT_CHUNK_BATCH_SIZE,
                |s| s.parse::<usize>().unwrap_or(DEFAULT_CHUNK_BATCH_SIZE),
            ),
            split_opts: SplitOpts::new(split_threshold),
        }
    }
}

impl EmulatorOpts {
    pub fn test_opts() -> Self {
        Self {
            chunk_size: env::var("CHUNK_SIZE").map_or_else(
                |_| TEST_CHUNK_SIZE,
                |s| s.parse::<usize>().unwrap_or(TEST_CHUNK_SIZE),
            ),
            chunk_batch_size: env::var("CHUNK_BATCH_SIZE").map_or_else(
                |_| TEST_CHUNK_BATCH_SIZE,
                |s| s.parse::<usize>().unwrap_or(TEST_CHUNK_BATCH_SIZE),
            ),
            split_opts: SplitOpts::new(TEST_DEFERRED_SPLIT_THRESHOLD),
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
            keccak: deferred_shift_threshold / 24,
            sha_extend: deferred_shift_threshold / 48,
            sha_compress: deferred_shift_threshold / 80,
            memory: deferred_shift_threshold * 4,
        }
    }
}
