use std::env;

use serde::{Deserialize, Serialize};

const DEFAULT_CHUNK_SIZE: usize = 1 << 22;
const DEFAULT_CHUNK_BATCH_SIZE: usize = 16;
const DEFAULT_TRACE_GEN_WORKERS: usize = 1;
const DEFAULT_CHECKPOINTS_CHANNEL_CAPACITY: usize = 128;
const DEFAULT_RECORDS_AND_TRACES_CHANNEL_CAPACITY: usize = 1;

/// Options to configure the Pico prover for core and recursive proofs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PicoProverOpts {
    /// Options for the core prover.
    pub core_opts: PicoCoreOpts,
    /// Options for the recursion prover.
    pub recursion_opts: PicoCoreOpts,
}

impl Default for PicoProverOpts {
    fn default() -> Self {
        Self {
            core_opts: PicoCoreOpts::default(),
            recursion_opts: PicoCoreOpts::recursion(),
        }
    }
}

/// Options for the core prover.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PicoCoreOpts {
    /// The size of a chunk in terms of cycles.
    pub chunk_size: usize,
    /// The size of a batch of chunks in terms of cycles.
    pub chunk_batch_size: usize,
    /// Options for splitting deferred events.
    pub split_opts: SplitOpts,
    /// Whether to reconstruct the commitments.
    pub reconstruct_commitments: bool,
    /// The number of workers to use for generating traces.
    pub trace_gen_workers: usize,
    /// The capacity of the channel for checkpoints.
    pub checkpoints_channel_capacity: usize,
    /// The capacity of the channel for records and traces.
    pub records_and_traces_channel_capacity: usize,
}

impl Default for PicoCoreOpts {
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
            reconstruct_commitments: true,
            trace_gen_workers: env::var("TRACE_GEN_WORKERS").map_or_else(
                |_| DEFAULT_TRACE_GEN_WORKERS,
                |s| s.parse::<usize>().unwrap_or(DEFAULT_TRACE_GEN_WORKERS),
            ),
            checkpoints_channel_capacity: env::var("CHECKPOINTS_CHANNEL_CAPACITY").map_or_else(
                |_| DEFAULT_CHECKPOINTS_CHANNEL_CAPACITY,
                |s| {
                    s.parse::<usize>()
                        .unwrap_or(DEFAULT_CHECKPOINTS_CHANNEL_CAPACITY)
                },
            ),
            records_and_traces_channel_capacity: env::var("RECORDS_AND_TRACES_CHANNEL_CAPACITY")
                .map_or_else(
                    |_| DEFAULT_RECORDS_AND_TRACES_CHANNEL_CAPACITY,
                    |s| {
                        s.parse::<usize>()
                            .unwrap_or(DEFAULT_RECORDS_AND_TRACES_CHANNEL_CAPACITY)
                    },
                ),
        }
    }
}

impl PicoCoreOpts {
    /// Get the default options for the recursion prover.
    #[must_use]
    pub fn recursion() -> Self {
        let mut opts = Self::default();
        opts.reconstruct_commitments = false;
        opts.chunk_size = DEFAULT_CHUNK_SIZE;
        opts
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

/// The threshold for splitting deferred events.
pub const DEFERRED_SPLIT_THRESHOLD: usize = 1 << 19;
