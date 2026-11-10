//! The golden height file, `vm/tests/natural_heights.txt`: each record's natural heights under
//! every effective value that can move a height or where a chunk ends.
//!
//! A shape is chosen from a record's natural heights and the verifying key fixes the shapes, so a
//! change to how events are produced, stored or packaged must move no natural height. A line is
//! one record of one run: the [`KEY_FIELDS`], the record's chunk index, its heights, and what they
//! were found equal to, which is always the augmented record's history; a line saying otherwise
//! is refused. The key names the program and the input by digest (the program's instructions, entry
//! and memory image, as the pipeline never sees the ELF; the input's buffers, each after its
//! length), the AOT snapshot thread's replay segmentation, and the values the emulator runs with,
//! read where it reads them and never off the variables: one unset variable means different values
//! to different drivers, and `EmulatorOpts` holds only the chunk size while the rest are cached
//! where they are read. The segmentation moves heights: each segment of a split replay writes its
//! own local-memory row, and the Global and Poseidon2 rows that go with it, for an address more
//! than one segment touches, so a split run pins heights of its own. The engines of the snapshot
//! thread and the replay workers, the cycle tracker, the cost estimate, the batch size and the
//! cycle cap move no height and stay out, so an AOT run must hit the entry an interpreter run
//! wrote. [`KEYED`] names the variables the key reflects, and a test holds it and the
//! height-neutral rest to the ledger's `KNOBS`, so a variable the VM starts to read is sorted
//! before it can slip past the key.
//!
//! The `height-witness` feature, off by default and implying `cuda`, fills two hooks.
//! [`begin_pipeline`] reads the key where the snapshot pipeline starts. [`chunk`], where
//! `prepare_chunk_shaped` has just run the GPU preparer's event counter, asserts the counter's
//! heights equal those of the augmented record's history and, with `MLE_HEIGHTS=<file>` set,
//! appends the record's line to the file. Without the feature both hooks are empty. It runs one
//! pipeline at a time: a record packaged after the next pipeline starts is written under that
//! pipeline's key.
//!
//! The `mle_height_witness` example runs a guest, adds a run's lines to the golden file and checks
//! a run's lines against it. A key the golden file lacks fails the check, never skips it.

use std::collections::{BTreeMap, BTreeSet};

use crate::{
    compiler::riscv::program::Program,
    emulator::{opts::EmulatorOpts, stdin::EmulatorStdin},
    proverchain::riscv::DeferredSplit,
};
#[cfg(feature = "cuda")]
use crate::{
    emulator::riscv::record::EmulationRecord,
    instances::{chiptype::riscv_chiptype::RiscvChipType, preparer::EventCounter},
    machine::chip::MetaChip,
    mle::machine::riscv::Kb,
};

/// What a line's key holds, in the order it holds them.
pub const KEY_FIELDS: [&str; 15] = [
    "program",
    "input",
    "segmentation",
    "chunk_size",
    "memory_rw_threshold",
    "commit_tail_reserve",
    "commit_tail_overrun",
    "event_limit_scale",
    "event_limits_off",
    "leaf_cap",
    "commit_tail_hold_off",
    "deferred_tail_merge",
    "precompile_local_mem_merge",
    "gpu_memory_tier",
    "deferred_split",
];

const PROGRAM: usize = 0;
const INPUT: usize = 1;
const SEGMENTATION: usize = 2;

/// The variables the ledger records whose values the key reflects.
pub const KEYED: &[&str] = &[
    // Off the pipeline's `EmulatorOpts`.
    "CHUNK_SIZE",
    // Through their readers.
    "CHUNK_EVENT_LIMIT_SCALE",
    "CHUNK_EVENT_LIMITS_OFF",
    "CHUNK_LEAF_CAP",
    "CHUNK_COMMIT_TAIL_HOLD_OFF",
    "MLE_PRECOMPILE_LOCAL_MEM_MERGE",
    "DEFERRED_TAIL_MERGE",
    "PICO_GPU_MEM",
    // Through the AOT snapshot thread's segmentation.
    "MLE_SPLIT_REPLAY",
    "MLE_SPLIT_CHUNKS",
    "MLE_SPLIT_FROM_CHUNK",
    "NUM_THREADS",
    "PROVER_COUNT",
    // They choose the input, which the key names by digest.
    "AGGREGATOR_DATA_ROOT",
    "BLOCK_LIST_FILE",
    "DEFERRED_INDEX",
    "GAS_THRESHOLD",
    "MLE_BLOCKS",
    "MLE_ETHPROOFS_PREWARM_BLOCK",
    "MLE_INPUT_DIR",
    "RETH_INPUT_DIR",
];

/// What every line's heights were found equal to as its record was packaged.
const COMPARED: &str = "history";

const HEADER: &str = "\
# Natural heights per record, keyed by every effective value that can move a height or where a
# chunk ends (vm/src/mle/heights.rs). compared is history on every line: the event counter's
# heights were found equal to the augmented record's, read off its history, as the record was
# packaged. A split replay moves heights, so keys differing in the segmentation alone pin heights
# of their own. Written by the mle_height_witness example, never by hand.
";

/// A run's values of [`KEY_FIELDS`].
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Key([String; KEY_FIELDS.len()]);

impl Key {
    /// Each field `self` and `other` differ in, with both values.
    fn differences(&self, (this, that): (&str, &str), other: &Key) -> Vec<String> {
        KEY_FIELDS
            .iter()
            .zip(self.0.iter().zip(&other.0))
            .filter(|(_, (a, b))| a != b)
            .map(|(field, (a, b))| format!("{field} ({this} {a}, {that} {b})"))
            .collect()
    }

    fn label(&self) -> String {
        format!(
            "program {:.12} input {:.12} {}",
            self.0[PROGRAM], self.0[INPUT], self.0[SEGMENTATION]
        )
    }
}

/// One record's natural heights, by AIR.
pub type Heights = BTreeMap<String, usize>;

/// One record of one run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub key: Key,
    pub chunk_index: usize,
    pub heights: Heights,
}

impl Entry {
    pub fn parse(line: &str) -> Result<Self, String> {
        let columns: Vec<&str> = line.split('\t').collect();
        let [chunk_index, rows, compared] = columns
            .get(KEY_FIELDS.len()..)
            .and_then(|rest| <[&str; 3]>::try_from(rest).ok())
            .ok_or_else(|| format!("{} columns, not {}", columns.len(), KEY_FIELDS.len() + 3))?;
        if compared != COMPARED {
            return Err(format!(
                "compared {compared:?}: only heights found equal to the history's are pinned"
            ));
        }
        let key = Key(std::array::from_fn(|i| columns[i].to_string()));
        let chunk_index: usize = chunk_index
            .parse()
            .map_err(|err| format!("chunk index {chunk_index:?}: {err}"))?;
        let rows: Heights = rows
            .split(',')
            .filter(|cell| !cell.is_empty())
            .map(|cell| -> Result<(String, usize), String> {
                let (air, count) = cell
                    .split_once('=')
                    .ok_or_else(|| format!("height {cell:?}"))?;
                let count = count
                    .parse::<usize>()
                    .map_err(|err| format!("height {cell:?}: {err}"))?;
                Ok((air.to_string(), count))
            })
            .collect::<Result<_, String>>()?;
        Ok(Self {
            key,
            chunk_index,
            heights: rows,
        })
    }
}

/// Each key's records by chunk index.
pub type Index = BTreeMap<Key, BTreeMap<usize, Heights>>;

fn line(key: &Key, chunk_index: usize, heights: &Heights) -> String {
    let rows: Vec<String> = heights
        .iter()
        .map(|(air, rows)| format!("{air}={rows}"))
        .collect();
    format!(
        "{}\t{chunk_index}\t{}\t{COMPARED}",
        key.0.join("\t"),
        rows.join(",")
    )
}

/// The entries of a file this module wrote.
pub fn read(text: &str) -> Result<Vec<Entry>, String> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.is_empty() && !line.starts_with('#'))
        .map(|(n, line)| Entry::parse(line).map_err(|err| format!("line {}: {err}", n + 1)))
        .collect()
}

/// `entries` by key and chunk index. A repeated run writes a record twice, at the same heights.
pub fn index(entries: impl IntoIterator<Item = Entry>) -> Result<Index, String> {
    let mut index = Index::new();
    for Entry {
        key,
        chunk_index,
        heights,
    } in entries
    {
        let label = key.label();
        let records = index.entry(key).or_default();
        match records.get(&chunk_index) {
            None => {
                records.insert(chunk_index, heights);
            }
            Some(held) if *held == heights => {}
            Some(held) => {
                return Err(format!(
                    "{label}: chunk {chunk_index} is written at two sets of heights: {}",
                    row_differences(("one", held), ("another", &heights)).join(", ")
                ));
            }
        }
    }
    Ok(index)
}

/// `index` as the golden file holds it.
pub fn render(index: &Index) -> String {
    let mut out = format!(
        "{HEADER}# {}\tchunk_index\theights\tcompared\n",
        KEY_FIELDS.join("\t")
    );
    for (key, records) in index {
        for (chunk_index, heights) in records {
            out.push_str(&line(key, *chunk_index, heights));
            out.push('\n');
        }
    }
    out
}

/// Why `run` does not match `golden`: a key the golden file lacks, a record only one of them
/// holds, a height that differs. Empty when every key of `run` is pinned with its records.
pub fn mismatches(golden: &Index, run: &Index) -> Vec<String> {
    let mut found = Vec::new();
    for (key, records) in run {
        match golden.get(key) {
            None => found.push(key_miss(golden, key)),
            Some(pinned) => found.extend(
                record_differences(("pinned", pinned), ("run", records))
                    .into_iter()
                    .map(|difference| format!("{}: {difference}", key.label())),
            ),
        }
    }
    found
}

/// `golden` with `run` added, refusing a record `golden` pins at other heights. With `replace`,
/// `golden`'s records under `run`'s keys go first, as an intended change to the heights needs.
pub fn merge(mut golden: Index, run: Index, replace: bool) -> Result<Index, String> {
    if replace {
        golden.retain(|key, _| !run.contains_key(key));
    }
    let mut found = Vec::new();
    for (key, records) in run {
        match golden.get(&key) {
            None => {
                golden.insert(key, records);
            }
            Some(pinned) => found.extend(
                record_differences(("pinned", pinned), ("run", &records))
                    .into_iter()
                    .map(|difference| format!("{}: {difference}", key.label())),
            ),
        }
    }
    if found.is_empty() {
        Ok(golden)
    } else {
        Err(found.join("\n"))
    }
}

fn key_miss(golden: &Index, key: &Key) -> String {
    let same_run: Vec<&Key> = golden
        .keys()
        .filter(|pinned| pinned.0[PROGRAM] == key.0[PROGRAM] && pinned.0[INPUT] == key.0[INPUT])
        .collect();
    match same_run
        .iter()
        .min_by_key(|pinned| pinned.differences(("pinned", "run"), key).len())
    {
        None => format!(
            "{}: no key is pinned for this program and input",
            key.label()
        ),
        Some(nearest) => format!(
            "{}: not pinned; of the {} key(s) pinned for this program and input the nearest \
             differs in {}",
            key.label(),
            same_run.len(),
            nearest.differences(("pinned", "run"), key).join(", ")
        ),
    }
}

fn record_differences(
    (this, left): (&str, &BTreeMap<usize, Heights>),
    (that, right): (&str, &BTreeMap<usize, Heights>),
) -> Vec<String> {
    let chunks: BTreeSet<&usize> = left.keys().chain(right.keys()).collect();
    chunks
        .into_iter()
        .filter_map(|chunk| match (left.get(chunk), right.get(chunk)) {
            (Some(l), Some(r)) if l == r => None,
            (Some(l), Some(r)) => Some(format!(
                "chunk {chunk}: {}",
                row_differences((this, l), (that, r)).join(", ")
            )),
            (Some(_), None) => Some(format!("chunk {chunk}: {this} only")),
            (None, _) => Some(format!("chunk {chunk}: {that} only")),
        })
        .collect()
}

fn row_differences((this, left): (&str, &Heights), (that, right): (&str, &Heights)) -> Vec<String> {
    let shown = |rows: Option<&usize>| rows.map_or("absent".to_string(), usize::to_string);
    let airs: BTreeSet<&String> = left.keys().chain(right.keys()).collect();
    airs.into_iter()
        .filter(|air| left.get(*air) != right.get(*air))
        .map(|air| {
            format!(
                "{air} ({this} {}, {that} {})",
                shown(left.get(air)),
                shown(right.get(air))
            )
        })
        .collect()
}

/// Reads the run's key where the snapshot pipeline starts, once it has refused what it cannot run.
#[inline(always)]
pub fn begin_pipeline(
    program: Option<&Program>,
    stdin: Option<&EmulatorStdin>,
    opts: &EmulatorOpts,
    deferred_split: DeferredSplit,
) {
    #[cfg(feature = "height-witness")]
    live::begin_pipeline(program, stdin, opts, deferred_split);
    #[cfg(not(feature = "height-witness"))]
    let _ = (program, stdin, opts, deferred_split);
}

/// Checks and writes the heights of a record the GPU preparer has just counted.
#[cfg(feature = "cuda")]
#[inline(always)]
pub fn chunk(
    chips: &[MetaChip<Kb, RiscvChipType<Kb>>],
    record: &EmulationRecord,
    counter: &EventCounter,
) {
    #[cfg(feature = "height-witness")]
    live::chunk(chips, record, counter);
    #[cfg(not(feature = "height-witness"))]
    let _ = (chips, record, counter);
}

#[cfg(feature = "height-witness")]
mod live {
    use std::{
        fs::{File, OpenOptions},
        io::Write,
        sync::{Mutex, Once, PoisonError},
    };

    use sha2::{Digest, Sha256};

    use super::{line, row_differences, Key, KEY_FIELDS};
    use crate::{
        compiler::riscv::program::Program,
        emulator::{
            opts::{EmulatorOpts, SnapshotMainMode},
            record::RecordBehavior,
            riscv::{
                chunk_split::{
                    commit_tail_hold_off, event_limit_scale, event_limits_off, ChunkSplitConfig,
                },
                record::{
                    deferred_tail_merge, get_prover_hardware_config,
                    precompile_local_mem_merge_enabled, EmulationRecord, GpuMemoryTier,
                },
                syscalls::{default_syscall_map, Syscall},
            },
            stdin::EmulatorStdin,
        },
        instances::{chiptype::riscv_chiptype::RiscvChipType, preparer::EventCounter},
        machine::chip::MetaChip,
        mle::machine::{
            riscv::{augmented_record, Kb},
            shape::{mle_natural_heights, mle_natural_heights_from_counter},
        },
        proverchain::riscv::DeferredSplit,
    };

    struct Run {
        key: Key,
        out: Option<File>,
    }

    static RUN: Mutex<Option<Run>> = Mutex::new(None);

    pub(super) fn begin_pipeline(
        program: Option<&Program>,
        stdin: Option<&EmulatorStdin>,
        opts: &EmulatorOpts,
        deferred_split: DeferredSplit,
    ) {
        let program = program.expect("the snapshot pipeline has no program");
        let inputs: &[Vec<u8>] = stdin.map(|stdin| &stdin.inputs[..]).unwrap_or_default();
        let key = effective_key(program, inputs, opts, deferred_split);
        let out = std::env::var_os("MLE_HEIGHTS").map(|path| {
            let name = path.to_string_lossy();
            let out = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
                .unwrap_or_else(|err| panic!("MLE_HEIGHTS={name}: {err}"));
            // Emptied by the process's first pipeline and appended to by its later ones, so an
            // earlier run's lines are never read back as a repeat of this run's.
            static EMPTIED: Once = Once::new();
            EMPTIED.call_once(|| {
                out.set_len(0)
                    .unwrap_or_else(|err| panic!("MLE_HEIGHTS={name}: {err}"))
            });
            out
        });
        if out.is_none() {
            static TOLD: Once = Once::new();
            // Not through `tracing`, whose default filter is off.
            TOLD.call_once(|| {
                eprintln!("MLE_HEIGHTS is unset: each record's heights are checked, none written")
            });
        }
        *RUN.lock().unwrap_or_else(PoisonError::into_inner) = Some(Run { key, out });
    }

    pub(super) fn chunk(
        chips: &[MetaChip<Kb, RiscvChipType<Kb>>],
        record: &EmulationRecord,
        counter: &EventCounter,
    ) {
        let rows = mle_natural_heights_from_counter(record, counter);
        let history = mle_natural_heights(&augmented_record(chips, record));
        let differing = row_differences(("counter", &rows), ("history", &history));
        assert!(
            differing.is_empty(),
            "chunk {}: the event counter's natural heights are not the history's: {}",
            record.chunk_index(),
            differing.join(", ")
        );
        let mut run = RUN.lock().unwrap_or_else(PoisonError::into_inner);
        let run = run.as_mut().expect(
            "a record reached the GPU preparer before any snapshot pipeline began, and its \
             heights are keyed by what the pipeline ran",
        );
        if let Some(out) = run.out.as_mut() {
            let text = line(&run.key, record.chunk_index(), &rows);
            out.write_all(format!("{text}\n").as_bytes())
                .unwrap_or_else(|err| panic!("MLE_HEIGHTS: {err}"));
        }
    }

    fn effective_key(
        program: &Program,
        inputs: &[Vec<u8>],
        opts: &EmulatorOpts,
        deferred_split: DeferredSplit,
    ) -> Key {
        let chunk_size = opts.chunk_size;
        // As the interpreter derives it: this call is the first, so its log line is the run's.
        let max_syscall_cycles = default_syscall_map::<Kb>()
            .values()
            .map(|syscall| Syscall::num_extra_cycles(&**syscall))
            .max()
            .unwrap_or_default();
        let split = ChunkSplitConfig::for_chunk_size(chunk_size, max_syscall_cycles);
        let tier = match get_prover_hardware_config().tier() {
            GpuMemoryTier::Tier24GB => "24gb",
            GpuMemoryTier::Tier32GB => "32gb",
        };
        let deferred_split = match deferred_split.start() {
            Some(start) => format!("from_chunk_{start}"),
            None => "after_every_chunk".to_string(),
        };
        let fields = [
            ("program", program_sha256(program)),
            ("input", input_sha256(inputs)),
            ("segmentation", segmentation(opts.snapshot_main)),
            ("chunk_size", chunk_size.to_string()),
            ("memory_rw_threshold", split.memory_rw_threshold.to_string()),
            ("commit_tail_reserve", split.commit_tail_reserve.to_string()),
            ("commit_tail_overrun", split.commit_tail_overrun.to_string()),
            ("event_limit_scale", event_limit_scale().to_string()),
            ("event_limits_off", event_limits_off().to_string()),
            ("leaf_cap", split.leaf_cap.to_string()),
            ("commit_tail_hold_off", commit_tail_hold_off().to_string()),
            ("deferred_tail_merge", deferred_tail_merge().to_string()),
            (
                "precompile_local_mem_merge",
                precompile_local_mem_merge_enabled().to_string(),
            ),
            ("gpu_memory_tier", tier.to_string()),
            ("deferred_split", deferred_split),
        ];
        for ((name, _), field) in fields.iter().zip(KEY_FIELDS) {
            assert_eq!(*name, field, "the key's fields are out of order");
        }
        Key(fields.map(|(_, value)| value))
    }

    /// How the snapshot thread cuts a chunk's replay. Only the AOT one cuts, and a cut into one
    /// segment, or of no chunk, is none.
    fn segmentation(snapshot_main: SnapshotMainMode) -> String {
        #[cfg(feature = "aot-emulator")]
        if snapshot_main == SnapshotMainMode::Aot {
            use crate::emulator::aot::{split_chunks, split_from_chunk, split_segments};
            let segments = split_segments();
            if segments > 1 {
                match split_from_chunk() {
                    Some(from) => return format!("{segments}x-from-{from}"),
                    None if split_chunks() > 0 => {
                        return format!("{segments}x-first-{}", split_chunks())
                    }
                    None => {}
                }
            }
        }
        #[cfg(not(feature = "aot-emulator"))]
        let _ = snapshot_main;
        "unsplit".to_string()
    }

    struct Hashing(Sha256);

    impl Write for Hashing {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.update(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn program_sha256(program: &Program) -> String {
        let mut hashing = Hashing(Sha256::new());
        bincode::serialize_into(
            &mut hashing,
            &(
                &*program.instructions,
                program.pc_start,
                program.pc_base,
                &*program.memory_image,
            ),
        )
        .expect("hash the program");
        hex::encode(hashing.0.finalize())
    }

    fn input_sha256(inputs: &[Vec<u8>]) -> String {
        let mut sha = Sha256::new();
        for input in inputs {
            sha.update((input.len() as u64).to_le_bytes());
            sha.update(input);
        }
        hex::encode(sha.finalize())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every other variable the ledger records: none moves a natural height or a chunk boundary.
    const HEIGHT_NEUTRAL: &[&str] = &[
        // How fast, on which replay engine and on how many threads, cards and history slots, not
        // what.
        "RAYON_NUM_THREADS",
        "PROVE_CONCURRENCY",
        "MEMORY_POOL_SIZE",
        "MEMORY_POOL_EAGER",
        "MEMORY_POOL_LOW_WATER",
        "MEMORY_RECYCLER_THREADS",
        "TCMALLOC_RELEASE_RATE",
        "MEM_POOL_MAX_SIZE",
        "MEM_POOL_RESERVE_SIZE",
        "MLE_EVENT_POOL_SIZE",
        "MLE_HISTORY_SLOTS",
        "MLE_DEFERRED_RECORDS",
        "MLE_PREWARM",
        "MLE_HEAP_PREWARM_GB",
        "MLE_ETHPROOFS_PREWARM",
        "MLE_CHUNK_CHANNEL_CAPACITY",
        "MLE_CHUNK_ORDER",
        "MLE_RT_THREADS",
        "MLE_RECURSION_LANE",
        "MLE_REPLAY_WORKERS",
        // The pipeline refuses a batch of more than one chunk.
        "CHUNK_BATCH_SIZE",
        // How the byte table reaches the card, not what it counts.
        "MLE_BYTE_TABLE_ADDITIVE",
        // The shape a record pads to from its natural heights, and the proof over it.
        "MLE_LOG_STACKED_HEIGHT",
        "MLE_SHAPE_MARGIN",
        "MLE_FORCE_CATCH_ALL",
        "VK_VERIFICATION",
        "MLE_VK_MAP",
        "MLE_VK_ROOT",
        "SKIP_INITIAL_GCS",
        "MLE_VERIFY",
        // Negative tests that tamper with values, not counts.
        "CVD_FORGE_K",
        "CORRUPT_MEMORY",
        "N11_TAMPER_PACKED_LANE",
        // The recursion layers, which run after the records exist.
        "RECURSION_EARLY_EXIT_TS",
        "MLE_REC_PARALLEL_CHILDREN",
        "MLE_REC_WAVEFRONT",
        "MLE_WITNESS_HASH",
        "MLE_TRANSCRIPT_PROF",
        "MLE_WALKER_XCHECK",
        "MLE_REC_EMULATE_PROFILE",
        "MLE_REC_EMULATE_DUMP",
        "MLE_REC_EMULATE_DUMP_LABEL",
        "MLE_REC_EMULATE_DUMP_MAX",
        "MLE_COMBINE_OVERLAP_KEYGEN",
        "MLE_COMBINE_PK_CACHE",
        "MLE_COMB_KEYGEN_FAT",
        "MLE_ROOT_EARLY_KEYGEN",
        "MLE_CONVERT_PK_CACHE",
        "MLE_CONVERT_PREBUILD_POISON",
        "MLE_CONVERT_PROGRAM_CACHE",
        "MLE_CONVERT_PREBUILD",
        "MLE_INJECT_FAILURE",
        "MLE_CONVERT_PREBUILDERS",
        "MLE_CONVERT_PREBUILD_PK",
        "MLE_RECURSION_TRACE_COMPARE",
        // Checks, probes, profiles and logs.
        "CHUNK_SPLIT_DEBUG",
        "MLE_SPLIT_CHECK",
        "MLE_RECORD_DIGEST",
        "MLE_LEDGER_DIGESTS",
        "MLE_LEDGER_PRECOMPILE_TIMERS",
        "MLE_SPANS",
        "DEBUG_MEMORY_EVENTS",
        "DEBUG_LOCAL_MEMORY",
        "LOG_SYSCALLS",
        "RUST_LOG",
        "RUST_LOGGER",
        "BENCH_TIMER",
        "BYTE_TRACE_DEBUG",
        "MLE_COST_PROBE",
        "MLE_KEYGEN_CROSSCHECK",
        "MLE_PREP_PROF",
        "MLE_SHAPE_CROSSCHECK",
        "MLE_TRACE_COMPARE",
        "SHAPE_PROBE_NATURAL",
        "MLE_STRIP_CELL_MS",
        "MLE_VRAM_CENSUS",
        "MLE_VRAM_POLL_MS",
        "MLE_VRAM_PROBE",
        // The CUDA backend's kernels, caches, JIT, cross-checks and profiles.
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
        "MLE_GKR_SEG",
        "MLE_GKR_SEG_GRANULE_LOG",
        "MLE_GKR_SEG_MAX_RATIO",
        "MLE_GKR_SEG_REPORT",
        "MLE_GKR_SEG_WINDOWED",
        "MLE_GKR_VIRTUAL_PADDING",
        "MLE_GKR_ZC_BUDGET_LOG",
        "MLE_GPU_ZC",
        "MLE_JIT_CACHE_DIR",
        "MLE_JIT_DUMP_DIR",
        "MLE_JIT_MAX_RULES",
        "MLE_JIT_OFAST",
        "MLE_KEYGEN_TIMING_SYNC",
        "MLE_MEMINFO_LAZY",
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
        // The distributed driver's roles and peers, and which machine proves a chunk.
        "CHUNKS_PER_ROUND",
        "CPU_CHUNKS_PER_TASK_UNIT",
        "DYNAMIC_CHUNK_START",
        "FRI_RISCV_ONLY",
        "GLOBAL_SCHEDULER_PORT",
        "MACHINE_ROLE",
        "MLE_CONNECT_ATTEMPTS",
        "MLE_ETHPROOFS_RESULT_CAPACITY",
        "MLE_PEER_WAIT_SECS",
        "MLE_TWO_MACHINE",
        "PEER_MACHINE_ADDR",
        "PRIMARY_IP",
        "SCHEDULER_WORKERS",
        "SCHED_WORKERS",
        "USECASE",
    ];

    #[test]
    fn every_ledger_knob_is_keyed_or_height_neutral() {
        let knobs: BTreeSet<&str> = crate::mle::ledger::KNOBS.iter().copied().collect();
        let keyed: BTreeSet<&str> = KEYED.iter().copied().collect();
        let neutral: BTreeSet<&str> = HEIGHT_NEUTRAL.iter().copied().collect();
        let both: Vec<&&str> = keyed.intersection(&neutral).collect();
        assert!(both.is_empty(), "keyed and height-neutral: {both:?}");
        let sorted: BTreeSet<&str> = keyed.union(&neutral).copied().collect();
        let unsorted: Vec<&&str> = knobs.difference(&sorted).collect();
        let stale: Vec<&&str> = sorted.difference(&knobs).collect();
        assert!(
            unsorted.is_empty() && stale.is_empty(),
            "neither keyed nor height-neutral: {unsorted:?}; sorted but not in KNOBS: {stale:?}"
        );
    }

    #[test]
    fn the_named_positions_are_the_fields_they_name() {
        assert_eq!(KEY_FIELDS[PROGRAM], "program");
        assert_eq!(KEY_FIELDS[INPUT], "input");
        assert_eq!(KEY_FIELDS[SEGMENTATION], "segmentation");
    }

    fn key(segmentation: &str, chunk_size: &str) -> Key {
        Key(std::array::from_fn(|i| match KEY_FIELDS[i] {
            "segmentation" => segmentation.to_string(),
            "chunk_size" => chunk_size.to_string(),
            field => format!("{field}-value"),
        }))
    }

    fn entry(key: &Key, chunk_index: usize, cpu: usize) -> Entry {
        Entry {
            key: key.clone(),
            chunk_index,
            heights: BTreeMap::from([("Add".to_string(), 3), ("Cpu".to_string(), cpu)]),
        }
    }

    #[test]
    fn a_written_line_reads_back() {
        let written = entry(&key("unsplit", "8388608"), 2, 5);
        let text = render(&index([written.clone()]).unwrap());
        assert_eq!(read(&text).unwrap(), vec![written]);
    }

    #[test]
    fn a_run_matches_only_the_records_pinned_under_its_key() {
        let pinned = key("unsplit", "8388608");
        let golden = index([entry(&pinned, 1, 5), entry(&pinned, 2, 6)]).unwrap();
        let same = index([entry(&pinned, 2, 6), entry(&pinned, 1, 5)]).unwrap();
        assert!(mismatches(&golden, &same).is_empty());

        let miss = mismatches(
            &golden,
            &index([entry(&key("unsplit", "4194304"), 1, 5)]).unwrap(),
        );
        assert_eq!(miss.len(), 1, "{miss:?}");
        assert!(
            miss[0].contains("chunk_size (pinned 8388608, run 4194304)"),
            "{miss:?}"
        );
        let short = index([entry(&pinned, 1, 5)]).unwrap();
        assert_eq!(
            mismatches(&golden, &short).len(),
            1,
            "a record the run lacks"
        );
        let moved = index([entry(&pinned, 1, 5), entry(&pinned, 2, 7)]).unwrap();
        assert_eq!(mismatches(&golden, &moved).len(), 1, "a height that moved");
        assert!(index([entry(&pinned, 1, 5), entry(&pinned, 1, 6)]).is_err());
    }

    #[test]
    fn each_key_pins_its_own_heights_and_an_uncompared_record_is_refused() {
        let unsplit = key("unsplit", "8388608");
        let split = key("2x-first-4", "8388608");
        let golden = index([entry(&unsplit, 1, 5)]).unwrap();
        let split_run = index([entry(&split, 1, 6)]).unwrap();
        let both = merge(golden.clone(), split_run.clone(), false).unwrap();
        assert!(mismatches(&both, &golden).is_empty());
        assert!(mismatches(&both, &split_run).is_empty());
        let moved = index([entry(&unsplit, 1, 6)]).unwrap();
        assert!(merge(golden.clone(), moved.clone(), false).is_err());
        assert_eq!(merge(golden, moved.clone(), true).unwrap(), moved);

        let written = render(&split_run);
        let uncompared = written.replace("\thistory\n", "\tnone\n");
        assert_ne!(uncompared, written);
        let refused = read(&uncompared).unwrap_err();
        assert!(refused.contains("compared \"none\""), "{refused}");
    }

    #[test]
    fn the_golden_file_pins_consistent_heights() {
        let golden = index(
            read(include_str!("../../tests/natural_heights.txt")).expect("the golden file parses"),
        )
        .expect("no record is pinned at two sets of heights");
        assert!(
            !golden.is_empty(),
            "the golden file pins nothing: record it with the mle_height_witness example"
        );
    }
}
