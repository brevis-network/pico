//! What each stage of a chunk's life did — bytes, counts, knobs — as one JSON line per
//! (chunk, stage), beside the time axis [`spans`](super::spans) records.
//!
//! The two instruments share one origin, which [`open_window`] sets for both, so a reader can join
//! them on time; they are kept apart so that a wall clock and a sum over workers are never read off
//! the same column. The spans say who was busy, idle or waiting, and when; the ledger says what the
//! stage did.
//!
//! In a build with the `stage-ledger` feature (below), `MLE_LEDGER=<path>` turns it on. The file is
//! appended to, so one file can hold a sitting's runs, each under its own `run` id. Unset, every
//! hook costs one `OnceLock::get`. Set, nothing is written until a driver opens a window —
//! `emulate_with_pipeline` does — so a path that never opens one (the serial interpreter, the
//! whitelist enumerator) records nothing either way.
//!
//! All of this is behind the `stage-ledger` feature, which `pico-vm` leaves off. Without it every
//! function here keeps its signature and compiles to a no-op, so the hook sites carry no `cfg` and
//! a production binary holds none of the recording code. What a hook site computes outside its
//! facts closure still runs, its clock reads most of all, so a fact that costs something to gather
//! belongs behind [`active`]. `MLE_LEDGER` or `MLE_SPANS` set on such a build makes the first
//! [`open_window`] say so on stderr and write nothing, so a run on the wrong build does not read as
//! a silent zero. The vocabulary both builds share lives in this file, the recording in `live` and
//! its no-ops in `off`; a function a hook site calls needs a twin in each.
//!
//! A window records one run: it opens with the pipeline's emulation and stops recording once that
//! emulation fails or panics or the run's records drop ([`drop_records`]), so a later prove in the
//! same process is not written into it. A process records one run at a time. A second window
//! opened while a run still emulates, has a riscv prove in flight, or has proved and not yet
//! dropped its records would mix the two runs' lines, so it stops both instruments for the rest of
//! the process and marks the open run `"overlapped": true`. A window that only emulated and never
//! closed — a test or a driver that drops the records itself — is replaced.
//!
//! A driver that times the run calls [`set_driver`] before its timer and [`finish`] after it, and
//! the span CSV and the complete envelope wait for [`finish`]. Without a driver, the CSV is written
//! when emulation ends. Either way the lines are flushed when emulation ends and when the records
//! drop, so a run killed in its prove keeps its emulation's lines.
//!
//! Granularity is per chunk or coarser, as for the spans. The two facts that cost O(data) to
//! compute, a per-chip trace digest and a replay's execution-history digest, are gated behind
//! `MLE_LEDGER_DIGESTS=1`. The instruments finer than that, a timer around every precompile a
//! pipeline core runs and around the pieces of the deferred record's assembly, are gated behind
//! `MLE_LEDGER_PRECOMPILE_TIMERS=1`, and their sums join the facts of the stage that ran them.
//!
//! Schema v2, three kinds of line, each carrying `"v": 2` and the run's id:
//! - the envelope (`"kind": "envelope"`), written when the window opens with `"complete": false`,
//!   then again by [`finish`] with `"complete": true` and the fields known only at the end;
//! - a stage: `chunk`, `batch`, `seg`, `record`, `stage`, `lane {role, idx}`, `t0_us`, `t1_us`,
//!   `dur_us` and `facts`, the times in microseconds from the window's origin (see [`At`]);
//! - a skipped stage: the same header with `"skipped": true` and no times — absent by design, which
//!   a reader must be able to tell from a hook that never ran.

use super::spans::{LaneId, Role};

#[cfg(feature = "stage-ledger")]
mod live;
#[cfg(feature = "stage-ledger")]
pub use live::*;

#[cfg(not(feature = "stage-ledger"))]
mod off;
#[cfg(not(feature = "stage-ledger"))]
pub use off::*;

pub const SCHEMA_VERSION: u64 = 2;

/// Stages named before anything measures them, so that whatever later fills one lands under its
/// own name instead of between two timers. Written as skipped for every chunk, except the `gpu.*`
/// names on a `cuda` build: its device trace generator is what they are for, so they are not
/// absent by design there and stay unwritten until a hook fills them.
pub const RESERVED_STAGES: &[&str] = &["gpu.tracegen", "history.*"];

/// Every environment variable the VM, the AOT runtime, the CUDA backend or the distributed driver
/// reads that changes what a run does or how fast, by its real name, so an envelope says what was
/// pinned. `null` when unset. `knobs_cover_every_variable_the_vm_reads` holds this list to the
/// source of every crate it scans.
pub const KNOBS: &[&str] = &[
    "RAYON_NUM_THREADS",
    "NUM_THREADS",
    "PROVER_COUNT",
    "CHUNK_SIZE",
    "CHUNK_BATCH_SIZE",
    "CHUNK_COMMIT_TAIL_HOLD_OFF",
    "CHUNK_EVENT_LIMIT_SCALE",
    "CHUNK_EVENT_LIMITS_OFF",
    "CHUNK_SPLIT_DEBUG",
    "MLE_LOG_STACKED_HEIGHT",
    "MLE_SHAPE_MARGIN",
    "MLE_FORCE_CATCH_ALL",
    "VK_VERIFICATION",
    "MLE_VK_MAP",
    "MLE_VK_ROOT",
    "PROVE_CONCURRENCY",
    "MEMORY_POOL_SIZE",
    "MEMORY_POOL_EAGER",
    "MEMORY_POOL_LOW_WATER",
    "MEMORY_RECYCLER_THREADS",
    "MLE_SPLIT_REPLAY",
    "MLE_SPLIT_CHUNKS",
    "MLE_SPLIT_FROM_CHUNK",
    "MLE_SPLIT_CHECK",
    "MLE_PRECOMPILE_LOCAL_MEM_MERGE",
    "DEFERRED_TAIL_MERGE",
    "RECURSION_EARLY_EXIT_TS",
    "MLE_REC_PARALLEL_CHILDREN",
    "MLE_WITNESS_HASH",
    "MLE_TRANSCRIPT_PROF",
    "MLE_WALKER_XCHECK",
    "MLE_REC_EMULATE_PROFILE",
    "MLE_REC_EMULATE_DUMP",
    "MLE_REC_EMULATE_DUMP_LABEL",
    "MLE_REC_EMULATE_DUMP_MAX",
    "MLE_RECORD_DIGEST",
    "MLE_LEDGER_DIGESTS",
    "MLE_LEDGER_PRECOMPILE_TIMERS",
    "MLE_SPANS",
    "CVD_FORGE_K",
    "DEBUG_MEMORY_EVENTS",
    "DEBUG_LOCAL_MEMORY",
    "LOG_SYSCALLS",
    "RUST_LOG",
    "RUST_LOGGER",
    "TCMALLOC_RELEASE_RATE",
    // The host side of the device path: the device memory pool, the recursion key and program
    // caches, and the probes and cross-checks around trace generation.
    "BENCH_TIMER",
    "BYTE_TRACE_DEBUG",
    "MLE_BYTE_TABLE_ADDITIVE",
    "MEM_POOL_RESERVE_SIZE",
    "MLE_COMBINE_OVERLAP_KEYGEN",
    "MLE_COMBINE_PK_CACHE",
    "MLE_COMB_KEYGEN_FAT",
    "MLE_CONVERT_PK_CACHE",
    "MLE_CONVERT_PREBUILD_POISON",
    "MLE_CONVERT_PROGRAM_CACHE",
    "MLE_COST_PROBE",
    "MLE_KEYGEN_CROSSCHECK",
    "MLE_PREP_PROF",
    "MLE_RECURSION_TRACE_COMPARE",
    "MLE_SHAPE_CROSSCHECK",
    "MLE_TRACE_COMPARE",
    "PICO_GPU_MEM",
    "SHAPE_PROBE_NATURAL",
    "SKIP_INITIAL_GCS",
    // The CUDA backend: its kernel paths and switches, caches, JIT settings, cross-checks and
    // profiles.
    "C1_FUSED_OFF",
    "C1_VERIFY",
    "FRAC_K2_VEC",
    "FRAC_PROF",
    "G1_DIAG",
    "G1_JIT",
    "G1_JIT_VERIFY",
    "G3_MEASURE",
    "GKR_BUF_CACHE",
    "GKR_BUF_CACHE_MIN_FREE",
    "MLE_AIR_DATA_CACHE_CAP",
    "MLE_AREA_DEBUG",
    "MLE_BREAKDOWN",
    "MLE_CUDA_GKR_PRECOMPUTE_M",
    "MLE_CUDA_GKR_PRECOMPUTE_M_MIN_BLOCKS",
    "MLE_CUDA_GKR_PRECOMPUTE_M_MIN_N",
    "MLE_CUDA_GKR_PRECOMPUTE_M_TAIL_TILE",
    "MLE_CUDA_GKR_PRECOMPUTE_M_TARGET_BLOCKS",
    "MLE_D2H_PINNED",
    "MLE_DEBUG_GKR_FRACS",
    "MLE_DEBUG_ROUND0",
    "MLE_DUMP_ZCR0",
    "MLE_GPU_ZC",
    "MLE_JIT_CACHE_DIR",
    "MLE_JIT_DUMP_DIR",
    "MLE_JIT_MAX_RULES",
    "MLE_JIT_OFAST",
    "MLE_KEYGEN_TIMING_SYNC",
    "MLE_MONO_PATH",
    "MLE_OOM_WAIT_MS",
    "MLE_POOL_RETAIN",
    "MLE_PROF",
    "MLE_PROF2",
    "MLE_R0_BUDGET_ALPHA",
    "MLE_STREAMED_OPEN_GATHER",
    "MLE_VERIFY_INPUT_EVAL",
    "MLE_VERIFY_MLE",
    "MLE_VERIFY_REVERT",
    "MLE_VERIFY_ZC_R0",
    "REDUX_PROF",
    "RS_PROF",
    "RS_STREAM_BLOCKS",
    "RS_STREAM_VERIFY",
    "STACK_GATHER_OFF",
    "STEP_PROF",
    "WHIR_PROF",
    "Z1_JIT",
    "Z1_JIT_FORCE_AIRS",
    "Z1_JIT_SEG_MIN",
    "Z1_JIT_SEG_RULES",
    "Z1_JIT_VERIFY",
    // The distributed driver: roles and peers, the inputs it takes, its pools, its replay
    // workers' engine, prewarming and the ethproofs server.
    "AGGREGATOR_DATA_ROOT",
    "BLOCK_LIST_FILE",
    "CHUNKS_PER_ROUND",
    "CORRUPT_MEMORY",
    "CPU_CHUNKS_PER_TASK_UNIT",
    "DEFERRED_INDEX",
    "DYNAMIC_CHUNK_START",
    "FRI_RISCV_ONLY",
    "GAS_THRESHOLD",
    "GLOBAL_SCHEDULER_PORT",
    "MACHINE_ROLE",
    "MLE_BLOCKS",
    "MLE_CHUNK_CHANNEL_CAPACITY",
    "MLE_CHUNK_ORDER",
    "MLE_CONNECT_ATTEMPTS",
    "MLE_CONVERT_PREBUILD",
    "MLE_CONVERT_PREBUILDERS",
    "MLE_CONVERT_PREBUILD_PK",
    "MLE_ETHPROOFS_PREWARM",
    "MLE_ETHPROOFS_PREWARM_BLOCK",
    "MLE_ETHPROOFS_RESULT_CAPACITY",
    "MLE_EVENT_POOL_SIZE",
    "MLE_HEAP_PREWARM_GB",
    "MLE_HISTORY_SLOTS",
    "MLE_INPUT_DIR",
    "MLE_PEER_WAIT_SECS",
    "MLE_PREWARM",
    "MLE_RECURSION_LANE",
    "MLE_REPLAY_WORKERS",
    "MLE_ROOT_EARLY_KEYGEN",
    "MLE_RT_THREADS",
    "MLE_STRIP_CELL_MS",
    "MLE_TWO_MACHINE",
    "MLE_VERIFY",
    "MLE_VRAM_CENSUS",
    "MLE_VRAM_POLL_MS",
    "MLE_VRAM_PROBE",
    "PEER_MACHINE_ADDR",
    "PRIMARY_IP",
    "RETH_INPUT_DIR",
    "SCHEDULER_WORKERS",
    "SCHED_WORKERS",
    "USECASE",
];

/// What the driver knows and the library does not: the arm's name and label, the files it ran, and
/// whether it proves. Set before the timed call; read when the window opens and when it finishes.
#[derive(Clone, Debug, Default)]
pub struct Driver {
    pub arm: Option<String>,
    /// The launcher's name for this run of the arm, which tells two runs of one arm under different
    /// settings apart.
    pub label: Option<String>,
    /// The launcher's repeat the run belongs to.
    pub rep: Option<String>,
    /// A warm-up run, which no comparison reads.
    pub warmup: bool,
    pub elf: Option<FileId>,
    pub input: Option<FileId>,
    /// `Some(false)` writes the prove stages as skipped for every chunk at [`finish`]; `None` says
    /// nothing about them, so a missing prove line stays visibly missing.
    pub proves: Option<bool>,
}

#[derive(Clone, Debug)]
pub struct FileId {
    pub path: String,
    pub sha256: String,
}

/// The lane a stage ran on. The span recorder's lanes, plus one it has no use for: the bundle
/// verify after the prove jobs, which runs on the caller's thread and is no prove slot's.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Lane {
    pub role: &'static str,
    pub idx: usize,
}

impl Lane {
    pub const VERIFY: Lane = Lane {
        role: "verify",
        idx: 0,
    };
    /// The driver's own thread, for what it does between the phases.
    pub const DRIVER: Lane = Lane {
        role: "driver",
        idx: 0,
    };
}

impl From<LaneId> for Lane {
    fn from(id: LaneId) -> Self {
        Self {
            role: id.role.as_str(),
            idx: id.index,
        }
    }
}

/// What a stage line is about. `chunk` is a CPU chunk's index, the same on both sides of the run:
/// it is also the chunk's snapshot batch, at the `CHUNK_BATCH_SIZE=1` the pipeline requires. A
/// split chunk's segments share a chunk and differ in `seg`. `record` is a record's index in
/// proving order, the deferred records included, and only the prove side has one. A deferred
/// record has a `record` and no `chunk`, and so does a bundle verify line, which cannot tell which
/// records are chunks; the record's prove lines name its chunk.
#[derive(Clone, Copy, Debug, Default)]
pub struct At {
    pub chunk: Option<u64>,
    pub batch: Option<u64>,
    pub seg: Option<(usize, usize)>,
    pub record: Option<u64>,
}

impl At {
    pub fn chunk(chunk: u64) -> Self {
        Self {
            chunk: Some(chunk),
            ..Self::default()
        }
    }

    /// A snapshot batch, which is also its CPU chunk.
    pub fn batch(batch: usize, seg: Option<(usize, usize)>) -> Self {
        Self {
            chunk: Some(batch as u64),
            batch: Some(batch as u64),
            seg,
            ..Self::default()
        }
    }

    /// A record in proving order, and the CPU chunk it is, if it is one.
    pub fn record(record: u64, chunk: Option<u64>) -> Self {
        Self {
            chunk,
            record: Some(record),
            ..Self::default()
        }
    }
}

/// The record a prove job is on and the concurrency slot it holds, for the hooks inside trace
/// generation, which are reached from callers that have neither.
#[derive(Clone, Copy, Debug)]
pub struct ProveSlot {
    /// The record's index in proving order.
    pub record: u64,
    /// The CPU chunk the record is, `None` for a deferred record.
    pub chunk: Option<u64>,
    pub slot: usize,
}

impl ProveSlot {
    pub fn lane(&self) -> Lane {
        LaneId::new(Role::Prove, self.slot).into()
    }

    pub fn at(&self) -> At {
        At::record(self.record, self.chunk)
    }
}

/// The lane and chunk a thread is working for, for stages reached from code that knows neither: the
/// memory-pool wait inside a snapshot batch.
#[derive(Clone, Copy, Debug)]
pub struct Context {
    pub lane: Lane,
    pub at: At,
}

/// Which pipeline core ran a timed precompile: the snapshot thread's, whose sink is off, or a replay
/// worker's. Both run the same code on threads a timer cannot tell apart, so the core carries it,
/// set where the core is built.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CoreRole {
    Snapshot,
    Worker,
}

impl CoreRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Snapshot => "snapshot",
            Self::Worker => "worker",
        }
    }
}

/// The phases of the final deferred split: taking each precompile kind's events out, sorting them,
/// building the records, and the deferred memory records; and the split's own wall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SplitPhase {
    Extract,
    Sort,
    Records,
    Memory,
    Wall,
}

impl SplitPhase {
    pub const ALL: [Self; 5] = [
        Self::Extract,
        Self::Sort,
        Self::Records,
        Self::Memory,
        Self::Wall,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Extract => "extract",
            Self::Sort => "sort",
            Self::Records => "records",
            Self::Memory => "memory",
            Self::Wall => "wall",
        }
    }
}

/// One-time setup, kept apart from runtime: moving work from runtime into setup is a gain, while
/// making setup faster is not a result, so the two are never summed.
#[derive(Clone, Copy, Debug)]
pub enum Setup {
    Keygen = 0,
    EmulatorSetup = 1,
}

// Read by the envelope, which only the recording build writes, and by the test that holds the list
// to `Cargo.toml`, which every build runs.
#[cfg(any(feature = "stage-ledger", test))]
macro_rules! built_features {
    ($($feature:literal),* $(,)?) => {
        /// Every `pico-vm` feature but `default`, each with whether this build has it.
        /// `features_name_every_feature_the_crate_declares` holds the list to `Cargo.toml`.
        const FEATURES: &[(&str, bool)] = &[$(($feature, cfg!(feature = $feature))),*];
    };
}

#[cfg(any(feature = "stage-ledger", test))]
built_features!(
    "aot-emulator",
    "bigint-rug",
    "cuda",
    "debug",
    "debug-lookups",
    "drop-ordering-edge",
    "height-witness",
    "jemalloc",
    "metrics",
    "mmap-memory",
    "multi-field-transcript",
    "parallel",
    "rayon",
    "single-threaded",
    "soundness-bchks25-optimized",
    "stage-ledger",
    "strict",
    "tcmalloc",
    "test-utils",
    "two-round-chunks",
);

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, path::Path};

    use super::*;

    #[test]
    fn features_name_every_feature_the_crate_declares() {
        let manifest = include_str!("../../Cargo.toml");
        let declared: BTreeSet<&str> = manifest
            .lines()
            .skip_while(|line| line.trim() != "[features]")
            .skip(1)
            .take_while(|line| !line.trim_start().starts_with('['))
            .filter_map(|line| {
                let line = line.trim();
                (!line.is_empty() && !line.starts_with('#'))
                    .then(|| line.split('=').next().unwrap_or_default().trim())
            })
            .filter(|&name| name != "default")
            .collect();
        let listed: BTreeSet<&str> = FEATURES.iter().map(|(name, _)| *name).collect();
        assert_eq!(listed, declared);
    }

    /// Names the scan finds that are not knobs: where the ledger and the height witness go, who
    /// held the lock or ran the process, and a default value that sits on a reader's line
    /// (`UNKNOWN`).
    const NOT_KNOBS: &[&str] = &[
        "MLE_LEDGER",
        "MLE_HEIGHTS",
        "MLE_LEDGER_LOCK_HELD",
        "GPUBENCH_LOCK_HELD_BY",
        "HOSTNAME",
        "RUN_ID",
        "WORKER_LABEL",
        "UNKNOWN",
    ];

    /// Every literal variable name read on a line that calls one of the readers this workspace
    /// uses. A name built at run time or passed on a later line escapes it.
    fn read_names(dir: &Path, names: &mut BTreeSet<String>) {
        const READERS: &[&str] = &[
            "env::var",
            "var_os(",
            "env_u32(",
            "env_flag(",
            "env_opt_out(",
            "env_usize(",
            "env_usize_or_warn(",
            "env_port(",
            "flag!(",
            "flag_on_by_default!(",
        ];
        for entry in std::fs::read_dir(dir).expect("source dir") {
            let path = entry.expect("dir entry").path();
            if path.is_dir() {
                read_names(&path, names);
                continue;
            }
            if path.extension().is_none_or(|ext| ext != "rs") {
                continue;
            }
            let text = std::fs::read_to_string(&path).expect("source file");
            for line in text.lines() {
                if line.trim_start().starts_with("//") || !READERS.iter().any(|r| line.contains(r))
                {
                    continue;
                }
                for quoted in line.split('"').skip(1).step_by(2) {
                    let is_name = quoted.len() > 2
                        && quoted.starts_with(|c: char| c.is_ascii_uppercase())
                        && quoted
                            .chars()
                            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
                    if is_name {
                        names.insert(quoted.to_string());
                    }
                }
            }
        }
    }

    #[test]
    fn knobs_cover_every_variable_the_vm_reads() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut names = BTreeSet::new();
        for dir in [
            "src",
            "../aot-runtime/src",
            "../mle-core/src",
            "../mle-cpu/src",
            "../cuda-mle/src",
            "../distributed-vm/src",
        ] {
            read_names(&root.join(dir), &mut names);
        }
        assert!(
            names.contains("CHUNK_SIZE"),
            "the scan found none of the reads it exists for"
        );
        let missing: Vec<&String> = names
            .iter()
            .filter(|name| !KNOBS.contains(&name.as_str()) && !NOT_KNOBS.contains(&name.as_str()))
            .collect();
        assert!(missing.is_empty(), "not in KNOBS: {missing:?}");
    }
}
