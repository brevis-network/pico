use crate::primitives::consts::{
    BENCH_MAX_CHUNK_BATCH_SIZE, BENCH_MAX_CHUNK_SIZE, BENCH_MAX_DEFERRED_SPLIT_THRESHOLD,
    BENCH_RECURSION_MAX_CHUNK_SIZE, MAX_LOG_NUMBER_OF_CHUNKS, TEST_CHUNK_BATCH_SIZE,
    TEST_CHUNK_SIZE, TEST_DEFERRED_SPLIT_THRESHOLD,
};
use serde::{Deserialize, Serialize};
use std::env;
use sysinfo::System;
use tracing::debug;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SnapshotMainMode {
    #[default]
    Interpreter,
    Aot,
}

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
    /// Whether or not to honor vm cycle tracking requests
    pub cycle_tracker: bool,
    /// Whether or not to track cycle prediction information
    pub cost_estimator: bool,
    /// Backend used for the snapshot-main phase of the pipeline.
    #[serde(default)]
    pub snapshot_main: SnapshotMainMode,
}

impl Default for EmulatorOpts {
    fn default() -> Self {
        let mut sys = System::new();
        sys.refresh_memory(); // only need memory info
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
            cycle_tracker: false,
            cost_estimator: false,
            snapshot_main: SnapshotMainMode::Interpreter,
        }
    }
}

/// `CHUNK_SIZE` if it names a usable chunk size, else `default_chunk_size`.
///
/// Zero is rejected with the unparseable values: `max_cycles` is derived from the chunk size, so a
/// zero would cap the run at zero cycles and every emulation would fail on its first instruction.
fn resolve_chunk_size(raw: Option<&str>, default_chunk_size: u32) -> u32 {
    raw.and_then(|s| s.parse::<u32>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(default_chunk_size)
}

impl EmulatorOpts {
    /// [`Self::default`] with `chunk_size` falling back to `default_chunk_size` rather than to the
    /// machine's RAM-derived size, and `max_cycles` re-paired with whichever one wins.
    ///
    /// `CHUNK_SIZE` still outranks the argument, but only when it parses: an empty or non-numeric
    /// value leaves `default_chunk_size` standing instead of silently reverting to the RAM-derived
    /// size. Callers that must not read the environment at all build the struct field by field.
    pub fn from_env_chunk_size(default_chunk_size: u32) -> Self {
        let chunk_size =
            resolve_chunk_size(env::var("CHUNK_SIZE").ok().as_deref(), default_chunk_size);
        Self {
            chunk_size,
            max_cycles: Some((chunk_size as u64) * (2 << MAX_LOG_NUMBER_OF_CHUNKS)),
            ..Default::default()
        }
    }

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
            snapshot_main: Self::default_snapshot_main_mode(),
            ..Default::default()
        }
    }

    fn default_snapshot_main_mode() -> SnapshotMainMode {
        #[cfg(feature = "aot-emulator")]
        if crate::emulator::aot::is_aot_factory_registered() {
            return SnapshotMainMode::Aot;
        }
        SnapshotMainMode::Interpreter
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

    pub fn with_cycle_tracker(self) -> Self {
        Self {
            cycle_tracker: true,
            ..self
        }
    }

    pub fn with_cost_estimator(self) -> Self {
        Self {
            cost_estimator: true,
            ..self
        }
    }

    pub fn with_max_cycles(self, max_cycles: u64) -> Self {
        Self {
            max_cycles: Some(max_cycles),
            ..self
        }
    }

    pub fn with_snapshot_main(self, snapshot_main: SnapshotMainMode) -> Self {
        Self {
            snapshot_main,
            ..self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_main_default_is_interpreter() {
        // Default must be Interpreter regardless of feature flags or any
        // registered AOT factory. Callers that want AOT must opt in via
        // `.with_snapshot_main(SnapshotMainMode::Aot)`.
        let opts = EmulatorOpts::default();
        assert_eq!(opts.snapshot_main, SnapshotMainMode::Interpreter);
    }

    /// An unusable `CHUNK_SIZE` leaves the caller's value standing. Falling back to the
    /// RAM-derived default instead would break the chunk_size/log_stacked_height pairing the
    /// caller stated.
    #[test]
    fn an_unusable_chunk_size_env_keeps_the_callers_value() {
        assert_eq!(resolve_chunk_size(Some("2048"), 1 << 22), 2048);
        assert_eq!(resolve_chunk_size(None, 1 << 22), 1 << 22);
        assert_eq!(resolve_chunk_size(Some(""), 1 << 22), 1 << 22);
        assert_eq!(resolve_chunk_size(Some("8M"), 1 << 22), 1 << 22);
        assert_eq!(resolve_chunk_size(Some("-1"), 1 << 22), 1 << 22);
        assert_eq!(resolve_chunk_size(Some("0"), 1 << 22), 1 << 22);
    }

    #[test]
    fn serde_backward_compat_deserializes_without_snapshot_main() {
        // Build a serialized blob from current opts, then strip the snapshot_main field
        // and confirm deserialize still succeeds with default Interpreter.
        let opts = EmulatorOpts::default();
        let value = serde_json::to_value(opts).expect("serialize");
        let mut map = value.as_object().unwrap().clone();
        map.remove("snapshot_main");
        let stripped = serde_json::Value::Object(map);
        let back: EmulatorOpts = serde_json::from_value(stripped).expect("deserialize");
        assert_eq!(back.snapshot_main, SnapshotMainMode::Interpreter);
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

/// One chunk per batch, whatever the host has.
///
/// The sequencer hands `EmulationRecord::split` the batch index it has committed, and
/// `SyscallEvent.chunk` counts chunks, so the `chunk <= committed + 1` filter admits a batch's
/// own precompile events only while a batch is a single chunk -- a larger batch would drop the
/// rest of them in silence. The sequencer asserts on what it is handed.
fn chunk_batch_size(_total_available_mem: u64) -> u32 {
    BENCH_MAX_CHUNK_BATCH_SIZE
}
