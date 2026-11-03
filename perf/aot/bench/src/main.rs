//! One arm of the AOT measurement per process, against the guest generated into `aot-generated/`.
//!
//! - `emulate-opts`: `riscv::emulate_with_opts`, the one interpreter the SDK proves from under
//!   `serial_emulation`.
//! - `pipeline-interp`: `emulate_with_pipeline` with the interpreter on the snapshot thread.
//! - `pipeline-aot`: the same with the generated code on the snapshot thread, so the two pipeline
//!   arms differ in that alone: the same options and the same `--workers`.
//! - `pipeline-aot-workers`: `pipeline-aot` with the replay workers running the generated code too
//!   (`replay_workers = Aot`), so it and `pipeline-aot` differ in the workers' engine alone.
//! - `execute-default`, `execute-aot`, `execute-serial`: `Prover::execute`, the emulation
//!   `prove_to` runs, from the builders the three prove arms use.
//! - `prove-default`: `Prover::prove_to` from a builder without `aot`, with
//!   `emulation_workers(--workers)` unless `--workers default`, which emulates through the
//!   pipeline with the interpreter on the snapshot thread.
//! - `prove-aot`: the same with `aot`, which puts the generated code on the snapshot thread, so the
//!   default and AOT prover arms differ in that alone.
//! - `prove-serial`: the same with `serial_emulation` in place of a worker count, which emulates
//!   through `emulate_with_opts`; `--workers` does not reach it.
//! - `prove-aot-workers`: `prove-aot` with `aot_workers`, the replay workers on the generated code
//!   too, so it and `prove-aot` differ in the workers' engine alone.
//! - `tracegen-aot`: `pipeline-aot`'s emulation, then the riscv phase's host trace generation over
//!   its records and nothing after it: the augment, shape and per-chip `generate_main` stages
//!   `prove-aot --phase riscv` writes to the stage ledger, in the same prove slots and at the same
//!   `PROVE_CONCURRENCY`, with no commit, no prove and no verify.
//! - `retained-rows`: `pipeline-aot`'s emulation, its replay workers writing the execution history
//!   alone, then, chunk by chunk, the rows its retained ECALL steps contribute, written alone and
//!   timed: each such step's row, its reads and write, its operand exceptions, its entry in the
//!   ECALL list and its syscall row, into tables reserved and touched beforehand at the largest
//!   chunk's counts. Every step in a history's ECALL list is retained. One line per chunk,
//!   `RETAINED_ROWS chunk= ecall_steps= reads= writes= exceptions= syscalls= write_ns=`; the run's
//!   line carries their sums as `retained=` and `retained_rows_us=`. The ECALL list is checked
//!   against the program: a run whose lists hold another count than its steps' ECALLs is an error.
//! - `history-census`: `retained-rows`' emulation, each chunk's census taken from its history as
//!   its record passes and the record dropped: one line per chunk, `CENSUS chunk=` then each of
//!   the sixteen history tables' rows and `after_precompile=` and `unattributed=`, its CPU memory
//!   accesses that follow an access of the same chunk to the same address by a precompile and by
//!   nothing a census can name (`census.rs` says how it tells them apart). Then, per table,
//!   `CENSUS_TABLE table= max_rows= max_block= max_chunk= row_bytes= max_bytes= capacity=
//!   run_max_rows= run_max_chunk= run_median_rows=`: over every block of the capacity table, the
//!   largest chunk's rows, the first block to hold them (its inputs' labels) and that block's first
//!   chunk to, the bytes of one row and of that chunk's, and the table's capacity; then this run's
//!   own largest chunk, its first chunk to hold it, and its lower median. `CENSUS_SLOT blocks=
//!   sum_max_bytes= slot_bytes= run_sum_max_bytes= run_sum_median_bytes=`: the capacity table's
//!   blocks, its tables' largest chunks' bytes summed, its slot, and this run's largest and median
//!   chunks' bytes summed; each sum is per table, and no single chunk need reach it. Then
//!   `CENSUS_WINDOWS chunks= of= after_precompile= unattributed= pick=`, the chunks with accesses
//!   after a precompile's, `<chunk>:<accesses>`, most first. The capacity table is this run's block
//!   alone unless `PICO_BENCH_CENSUS_FOLD` names an earlier one, taken at the same chunking, whose
//!   blocks are folded in, so every capacity is over all of them; with `PICO_BENCH_CENSUS_OUT` set,
//!   it goes to that file (format in `census.rs`), naming each block by its ELF's and inputs'
//!   digests, with the tree it was measured on, `MLE_LEDGER_COMMIT` and `MLE_LEDGER_DIRTY`, which
//!   the arm requires, and its replay split. A fold onto blocks of another tree, or replacing one,
//!   is refused before the run unless `PICO_BENCH_CENSUS_REPLACE=1`. A run with an unattributed
//!   access writes all of that, then exits 1.
//! - `history-arena`: `retained-rows`' emulation, each chunk's history copied into a slot of the
//!   host history arena as its record passes, at the committed census's capacities with
//!   `MLE_HISTORY_SLOTS` slots (64 unset) pinned outside the timer, then uploaded to device 0 in
//!   CPU slices of the default size and read back, and the record dropped. One line per chunk,
//!   `ARENA chunk= steps= bytes= spilled= upload=`: the tables that outgrew their regions (`-` for
//!   none) and `equal`, `differs:<tables>` or `error:<what>`. Then, per table, `ARENA_SPILL table=
//!   capacity= run_max_rows= spills=`, and `ARENA_SLOT slots= slot_bytes= pinned_bytes= max_in_use=
//!   blocked_takes= acquisitions= returns=`. A run with an upload that is not `equal` writes all of
//!   that, then exits 1.
//! - `replay-chunk`: the AOT snapshot thread over the input, one snapshot per chunk, and each
//!   chunk's snapshot replayed three times, one engine at a time: by the interpreter's worker
//!   (`interp`), by it again (`interp-null`, the arm that shows what two runs of one engine
//!   differ by), and by the AOT core's replay worker (`aot`), in an order rotated chunk by chunk.
//!   Each replay recovers a fresh worker so every engine pays the same recovery, unlike the
//!   pipeline's in-place reuse, and defers into a pool of its own. One line per chunk and engine,
//!   in the order they ran: `REPLAY_CHUNK chunk= engine= replay_us= recover_us= cycles= dispatches=
//!   fallback_insns= digest_equal=`. `replay_us` brackets the replay alone, its deferral and its
//!   records' hand-off included; `recover_us` is the worker's recovery, beside it; `dispatches`
//!   and `fallback_insns` are the AOT core's, 0 for the interpreters; `digest_equal` compares the
//!   chunk's record and what it deferred, field by field, with the first interpreter's of the
//!   chunk. Each chunk's memories go back to the pool before the next snapshot is taken.
//!
//! The emulation arms run under the options `pico-prover` builds for itself. The prover arms take
//! `CHUNK_SIZE`, `PROVE_CONCURRENCY`, `VK_VERIFICATION`, `MLE_VK_MAP` and `MLE_VK_ROOT` onto the
//! builder's setters as `cargo pico prove` maps them, and so prove in whitelist mode when the
//! environment says so. `tracegen-aot` maps them through the same builder and builds nothing from
//! it: the shape follows `VK_VERIFICATION`, the concurrency follows `PROVE_CONCURRENCY`, and no
//! keygen runs and no whitelist is loaded.
//!
//! The timer brackets one call, and `timed` names what that call does:
//! - `emulate_with_opts` or `emulate_with_pipeline`: the emulation, returning every record;
//! - `execute:emulate+drop-records`: the prover's emulation, which drops the records before it
//!   returns;
//! - `prove_to:emulate+prove+verify+recursion-keygen+drop-records`: emulation, proving to the phase,
//!   verifying, binding the output and dropping the records. `build` keygens the RISC-V machine
//!   and registers the AOT program, outside the timer, but the recursion machines keygen lazily per
//!   shape on the first prove that needs them, and a process here proves once: every prove past
//!   `riscv` pays its convert and combine keygen inside the bracket. A `riscv` prove has no
//!   `recursion-keygen` in its `timed`.
//! - `trace_records:emulate+augment+shape+tracegen+drop-records`: the emulation, the trace
//!   generation of every record it emitted, and the drop of the records. `prove_to`'s emulation
//!   also runs the chip-support check, the digest backfill and the precompile count, none of which
//!   this arm does, and it generates no keys.
//! - `replay_chunks:snapshot+copy+3x(recover+replay+digest)`: the whole `replay-chunk` loop, whose
//!   per-chunk timings are its `REPLAY_CHUNK` lines.
//! - `retained_rows:write`: not one call but the sum of `retained-rows`' per-chunk writes, the
//!   emulation that staged them outside it.
//! - `emulate_with_pipeline_streaming:emulate+census`: the emulation, each chunk's census taken
//!   inside it as the sequencer hands the record on.
//! - `emulate_with_pipeline_streaming:emulate+arena-fill+upload+read-back`: the emulation, each
//!   chunk's arena fill, header scan, upload and read-back inside it, as the sequencer hands the
//!   record on.
//!
//! Parsing the ELF, reading the input, `build`, the snapshot pipeline's memory pool (built up front
//! in every arm), and hashing and dropping what the call returned stay outside it.
//!
//! Prints one line, `AOT_BENCH` then space-separated `key=value` pairs, `-` where a key does not
//! apply to the arm: `arm`, `guest` (the ELF's file name), `input`, `workers` (resolved: `--workers
//! default` is the core count for the pipeline arms and the builder's default, the core count up to
//! 16, for the prover arms), `chunk_size`, `timed`, `wall_s`, `cycles`, `chunks`, `records` (for a
//! prove arm, the RISC-V chunk proofs, one per record), `committed_sha256`, `aot_elf_sha256`,
//! `aot_dispatches` (compiled blocks the snapshot thread entered; for `replay-chunk`, the AOT
//! replays), `aot_worker_dispatches` (compiled blocks the AOT replay workers entered, the
//! `*-aot-workers` arms only), `trace_source` and `branch_compares` (`history` and `indices` for
//! `tracegen-aot`), `phase`, `mode` (`dev` or `whitelist`), `verified`, `distinct_shapes`
//! (`Proof::distinct_shapes`), `traced_chunks` (CPU chunks that reached trace generation,
//! `tracegen-aot` only), `ledger` (the `MLE_LEDGER` file the run's stage ledger went to), `alloc`
//! (the global allocator this binary was built with, `tcmalloc`, `jemalloc` or `system`), `mem`
//! (the guest memory backing it was built with, `mmap` or `heap`), `bigint` (the curve
//! precompiles' big-integer backend, `rug` or `default`), `realloc`, `minor_faults`,
//! `major_faults`, and `retained` and `retained_rows_us` (`retained-rows` only).
//!
//! `realloc` is, for an emulation arm, the reallocations each table of the execution history made
//! over every record of the run, `<table>:<count>` for its sixteen vectors. A history table the
//! writer grows by `push` alone, from empty, says by its capacity how often it doubled; one whose capacity no such growth
//! reaches, as a split chunk's tables are once its segments are appended, reads `<table>:?`. A
//! table still in its arena slot's region never moved its rows and counts 0; one that spilled out
//! of the region grew from the region's size, which no such growth reaches either.
//! `minor_faults` and `major_faults` are, for an emulation arm, the process's page faults over the
//! timed call, from `getrusage`, every thread's.
//!
//! Every arm but `history-census` refuses `PICO_BENCH_CENSUS_OUT`, `PICO_BENCH_CENSUS_FOLD` and
//! `PICO_BENCH_CENSUS_REPLACE`, and every arm refuses the removed `PICO_BENCH_REPLAY_SINK`,
//! `PICO_BENCH_TRACE_SOURCE` and `MLE_RECORD_STREAMS`.
//!
//! `tracegen-aot` reads CPU chunks from their execution histories. Whitelist mode is refused;
//! trace generation runs in dev mode.
//!
//! With `MLE_LEDGER` or `MLE_SPANS` set, the arm's name, `--label`, `--rep` and `--warmup`, the ELF
//! and the inputs with their digests are handed to the ledger before the timed call, and its span
//! CSV and closing envelope are written after the result line, outside the timer.
//!
//! `RUST_LOG` filters the prover's logs on stderr, as in `cargo pico`.
//!
//! Exits 1 on an error, a proof that does not verify included, a `tracegen-aot` run in which a CPU
//! chunk reached no trace generation, a `replay-chunk` run with a chunk whose digests differ and a
//! `history-census` run with an unattributed access, and 3 when an AOT arm entered no compiled
//! block, on its snapshot thread or, in an `*-aot-workers` arm, in its replay workers: it measured
//! the interpreter under an AOT label. An AOT arm whose program is the bootstrap stub, or was
//! generated from another ELF, is an error before anything runs.

mod census;

use std::{
    fmt::{self, Display},
    mem::MaybeUninit,
    num::NonZeroUsize,
    ops::Range,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use census::{
    summarise, summary_lines, table_sizes, windows_line, Block, CapacityTable, ChunkCensus,
    Chunking, ReplaySplit, TableRows, Tree, TABLES,
};
use clap::{Parser, ValueEnum};
use pico_aot_runtime::{AotEmulatorCore, AotProgram};
use pico_prover::{
    Phase, ProveError, Prover, ProverBuilder, Stdin, ENV_NO_LONGER_READ, ENV_READ_BY_PROVER,
};
use pico_vm::{
    chips::chips::riscv_memory::event::MemoryRecord,
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{
        aot::{create_aot_emulator, split_chunks, split_from_chunk, split_segments},
        emulator::{AotReplayMetaEmulator, MetaEmulator},
        opts::{EmulatorOpts, ReplayWorkers, SnapshotMainMode},
        riscv::{
            chunk_split::ChunkSplitConfig,
            emulator::{EmulationDeferredState, SharedDeferredState},
            history::{Access, ExecutionHistory, OperandException, ReadAccess, Step},
            history_arena::{HistoryArena, HistoryCapacity, SpillPolicy, Table, TABLE_COUNT},
            history_fill::DerivedRows,
            history_view::HistoryView,
            memory::{
                init_memory_pool, memory_pool_size, ContiguousRiscvMemory, GLOBAL_MEMORY_POOL,
                GLOBAL_MEMORY_RECYCLER,
            },
            public_values::RecordFinalPvsState,
            record::EmulationRecord,
            record_digest::{field_digests, is_compared, FieldDigest},
            record_slots::{record_slots_from_env, SLOTS_VAR},
            state::RiscvEmulationState,
            syscalls::SyscallEvent,
        },
        stdin::EmulatorStdin,
    },
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::witness::ProvingWitness,
    mle::{
        env_flag, ledger,
        machine::riscv::{
            emulate_with_opts, emulate_with_pipeline, emulate_with_pipeline_streaming,
            trace_records, EmulationOutput, Kb, DEFAULT_LOG_STACKED_HEIGHT,
        },
    },
    primitives::consts::MAX_LOG_NUMBER_OF_CHUNKS,
    proverchain::riscv::{max_pipeline_workers, RiscvChips},
};
#[cfg(feature = "cuda")]
use pico_vm::instances::preparer::device_history::{plan::CPU_SLICE_STEPS, round_trip};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Arm {
    EmulateOpts,
    PipelineInterp,
    PipelineAot,
    PipelineAotWorkers,
    ExecuteDefault,
    ExecuteAot,
    ExecuteSerial,
    ProveDefault,
    ProveAot,
    ProveSerial,
    ProveAotWorkers,
    TracegenAot,
    ReplayChunk,
    RetainedRows,
    HistoryCensus,
    HistoryArena,
}

impl Arm {
    fn name(self) -> &'static str {
        match self {
            Self::EmulateOpts => "emulate-opts",
            Self::PipelineInterp => "pipeline-interp",
            Self::PipelineAot => "pipeline-aot",
            Self::PipelineAotWorkers => "pipeline-aot-workers",
            Self::ExecuteDefault => "execute-default",
            Self::ExecuteAot => "execute-aot",
            Self::ExecuteSerial => "execute-serial",
            Self::ProveDefault => "prove-default",
            Self::ProveAot => "prove-aot",
            Self::ProveSerial => "prove-serial",
            Self::ProveAotWorkers => "prove-aot-workers",
            Self::TracegenAot => "tracegen-aot",
            Self::ReplayChunk => "replay-chunk",
            Self::RetainedRows => "retained-rows",
            Self::HistoryCensus => "history-census",
            Self::HistoryArena => "history-arena",
        }
    }

    fn runs_aot(self) -> bool {
        matches!(
            self,
            Self::PipelineAot
                | Self::PipelineAotWorkers
                | Self::ExecuteAot
                | Self::ProveAot
                | Self::ProveAotWorkers
                | Self::TracegenAot
                | Self::ReplayChunk
                | Self::RetainedRows
                | Self::HistoryCensus
                | Self::HistoryArena
        )
    }

    fn aot_workers(self) -> bool {
        matches!(self, Self::PipelineAotWorkers | Self::ProveAotWorkers)
    }

    fn pipelined(self) -> bool {
        matches!(
            self,
            Self::PipelineInterp | Self::PipelineAot | Self::PipelineAotWorkers
        )
    }

    fn runs_serial(self) -> bool {
        matches!(self, Self::ExecuteSerial | Self::ProveSerial)
    }

    fn proves(self) -> bool {
        matches!(
            self,
            Self::ProveDefault | Self::ProveAot | Self::ProveSerial | Self::ProveAotWorkers
        )
    }
}

#[derive(Parser)]
struct Args {
    #[clap(long, value_enum)]
    arm: Arm,

    #[clap(long)]
    elf: PathBuf,

    /// One guest input, `u32:<n>`, `u64:<n>` or `file:<path>`, encoded as `cargo pico --input`
    /// encodes it; repeat it in the order the guest reads
    #[clap(long, value_parser = parse_input, value_name = "INPUT")]
    input: Vec<Input>,

    /// Interpreter workers beside the snapshot thread, a count or `default`: the core count for the
    /// pipeline arms, and the builder's own default for the default and AOT prover arms. Required
    /// by the arms with workers, ignored by those that emulate with one interpreter
    #[clap(long, value_parser = parse_workers)]
    workers: Option<Workers>,

    /// The phase the prove arms prove to: riscv, convert, combine, embed or wrap [default: combine];
    /// `tracegen-aot` takes riscv only
    #[clap(long, value_parser = parse_phase)]
    phase: Option<Phase>,

    /// The launcher's name for this run of the arm, for the stage ledger [default: the arm's name]
    #[clap(long)]
    label: Option<String>,

    /// The launcher's repeat this run belongs to, for the stage ledger
    #[clap(long)]
    rep: Option<String>,

    /// A warm-up run, which the stage ledger marks so no comparison reads it
    #[clap(long)]
    warmup: bool,
}

#[derive(Clone, Copy)]
enum Workers {
    Default,
    Count(NonZeroUsize),
}

fn parse_workers(s: &str) -> Result<Workers, String> {
    if s == "default" {
        return Ok(Workers::Default);
    }
    s.parse()
        .map(Workers::Count)
        .map_err(|_| format!("`{s}` is not a worker count: write a positive integer or `default`"))
}

/// One stdin element, with how the result line names it.
#[derive(Clone)]
struct Input {
    label: String,
    bytes: Vec<u8>,
}

fn parse_input(s: &str) -> Result<Input, String> {
    let (kind, value) = s.split_once(':').ok_or_else(|| {
        format!("`{s}` is not an input: write `u32:<n>`, `u64:<n>` or `file:<path>`")
    })?;
    let (label, bytes) = match kind {
        "u32" => (s.to_string(), encode(value.parse::<u32>())?),
        "u64" => (s.to_string(), encode(value.parse::<u64>())?),
        // Raw, as `read_vec()` returns it: how `cargo pico` and the reth harness pass a block.
        "file" => {
            let name = Path::new(value)
                .file_name()
                .map_or_else(|| value.into(), |name| name.to_string_lossy());
            let bytes = std::fs::read(value).map_err(|e| format!("cannot read `{value}`: {e}"))?;
            (format!("file:{name}"), bytes)
        }
        _ => {
            return Err(format!(
                "unknown input type `{kind}`: expected u32, u64 or file"
            ))
        }
    };
    Ok(Input {
        label: label.split_whitespace().collect::<Vec<_>>().join("_"),
        bytes,
    })
}

/// A typed input, encoded as the guest's `read_as` decodes it.
fn encode<T: Serialize, E: Display>(value: Result<T, E>) -> Result<Vec<u8>, String> {
    bincode::serialize(&value.map_err(|e| e.to_string())?).map_err(|e| e.to_string())
}

fn parse_phase(s: &str) -> Result<Phase, String> {
    match s {
        "riscv" => Ok(Phase::Riscv),
        "convert" => Ok(Phase::Convert),
        "combine" => Ok(Phase::Combine),
        "embed" => Ok(Phase::Embed),
        "wrap" => Ok(Phase::Wrap),
        _ => Err(format!(
            "unknown phase `{s}`: expected riscv, convert, combine, embed or wrap"
        )),
    }
}

/// The elements as both stdin types hold them: an element is the bytes the guest reads, whichever
/// way it was encoded.
fn emulator_stdin(inputs: &[Input]) -> EmulatorStdin<Program, Vec<u8>> {
    let mut builder = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    for input in inputs {
        builder.write_slice(&input.bytes);
    }
    builder.finalize()
}

fn prover_stdin(inputs: &[Input]) -> Stdin {
    let mut stdin = Stdin::new();
    for input in inputs {
        stdin.write_bytes(&input.bytes);
    }
    stdin
}

/// Reads `name`, echoed on stderr as `cargo pico` echoes the variables it maps.
fn mapped<T: fmt::Debug>(
    name: &str,
    setter: &str,
    parse: impl FnOnce(&str) -> Result<T, String>,
) -> Result<Option<T>, String> {
    let Ok(raw) = std::env::var(name) else {
        eprintln!("env: {name} not set");
        return Ok(None);
    };
    let value = parse(&raw).map_err(|e| format!("{name}={raw}: {e}"))?;
    eprintln!("env: {name}={raw} -> {setter}({value:?})");
    Ok(Some(value))
}

/// `PROVE_CONCURRENCY`, which `cargo pico` maps onto `ProverBuilder::concurrency`.
fn env_concurrency() -> Result<Option<NonZeroUsize>, String> {
    mapped("PROVE_CONCURRENCY", "concurrency", |raw| {
        raw.parse::<NonZeroUsize>().map_err(|e| e.to_string())
    })
}

/// `CHUNK_SIZE`, which `cargo pico` maps onto `ProverBuilder::chunk_size`.
fn env_chunk_size() -> Result<Option<u32>, String> {
    mapped("CHUNK_SIZE", "chunk_size", |raw| match raw.parse::<u32>() {
        Ok(n) if n > 0 => Ok(n),
        _ => Err("expected a positive integer".into()),
    })
}

/// The prover's default chunk size: `2^log_stacked_height` at the default height, capped at the
/// largest chunk the chunk clock can address.
fn default_chunk_size() -> u32 {
    (1u32 << DEFAULT_LOG_STACKED_HEIGHT).min(1 << (ChunkSplitConfig::MAX_CHUNK_CLK_BITS - 2))
}

const REMOVED_REPRESENTATION_KNOBS: [&str; 3] = [
    "PICO_BENCH_REPLAY_SINK",
    "PICO_BENCH_TRACE_SOURCE",
    "MLE_RECORD_STREAMS",
];

fn check_removed_knobs(is_set: impl Fn(&str) -> bool) -> Result<(), String> {
    for name in REMOVED_REPRESENTATION_KNOBS {
        if is_set(name) {
            return Err(format!(
                "{name} was removed; unset it before running the benchmark"
            ));
        }
    }
    Ok(())
}

fn check_tracegen_mode(bucket: bool) -> Result<(), String> {
    if bucket {
        return Err("tracing from the execution history requires dev mode".into());
    }
    Ok(())
}

/// `pico-prover`'s emulator options, every field stated so no environment variable decides one.
fn opts(chunk_size: u32) -> EmulatorOpts {
    EmulatorOpts {
        chunk_size,
        chunk_batch_size: 1,
        max_cycles: Some((chunk_size as u64) * (2 << MAX_LOG_NUMBER_OF_CHUNKS)),
        cycle_tracker: false,
        cost_estimator: false,
        snapshot_main: SnapshotMainMode::Interpreter,
        replay_workers: ReplayWorkers::Interpreter,
    }
}

/// Strict, as `cargo pico` reads it: a misspelt `true` read as `false` would prove in the other
/// mode.
fn parse_bool(raw: &str) -> Result<bool, String> {
    if raw.eq_ignore_ascii_case("true") {
        Ok(true)
    } else if raw.eq_ignore_ascii_case("false") {
        Ok(false)
    } else {
        Err("expected `true` or `false`".into())
    }
}

/// Eight limbs separated by spaces or commas, as `mle_vk_root.txt` publishes the root.
fn parse_root(raw: &str) -> Result<[u32; 8], String> {
    let limbs = raw
        .split([' ', ','])
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<u32>().map_err(|e| format!("limb `{s}`: {e}")))
        .collect::<Result<Vec<_>, _>>()?;
    limbs
        .try_into()
        .map_err(|limbs: Vec<u32>| format!("expected 8 limbs, got {}", limbs.len()))
}

/// The builder `cargo pico prove` makes from the environment: the variables it maps, onto the same
/// setters, with the two whitelist variables read only under `VK_VERIFICATION=true`.
fn builder(
    elf: &[u8],
    chunk_size: Option<u32>,
    concurrency: Option<NonZeroUsize>,
) -> Result<ProverBuilder, String> {
    let mut builder = Prover::builder(elf);
    if let Some(n) = chunk_size {
        builder = builder.chunk_size(n);
    }
    if let Some(n) = concurrency {
        builder = builder.concurrency(n);
    }
    let verify_keys = mapped("VK_VERIFICATION", "verify_keys", parse_bool)?;
    if let Some(on) = verify_keys {
        builder = builder.verify_keys(on);
    }
    if verify_keys == Some(true) {
        if let Some(path) = mapped("MLE_VK_MAP", "vk_map", |raw| Ok(PathBuf::from(raw)))? {
            builder = builder.vk_map(path);
        }
        if let Some(root) = mapped("MLE_VK_ROOT", "trusted_vk_root", parse_root)? {
            builder = builder.trusted_vk_root(root);
        }
    }
    for (name, effect) in ENV_READ_BY_PROVER {
        if let Ok(value) = std::env::var(name) {
            eprintln!(
                "warning: {name}={value} is read by the prover itself and {effect}; no option \
                 overrides it"
            );
        }
    }
    for (name, reason) in ENV_NO_LONGER_READ {
        if let Ok(value) = std::env::var(name) {
            eprintln!("warning: {name}={value} is no longer read: {reason}");
        }
    }
    Ok(builder)
}

/// Compiled blocks the AOT snapshot thread has entered.
static DISPATCHES: AtomicU64 = AtomicU64::new(0);

/// Compiled blocks the AOT replay workers have entered, over every replay.
static WORKER_DISPATCHES: AtomicU64 = AtomicU64::new(0);

/// The generated program, registered in its place: the same digest, stamp and code, reporting
/// after every batch how many compiled blocks the run has entered.
static COUNTED: AotProgram = AotProgram::stamped(
    pico_aot_dispatch::AOT.elf_sha256(),
    pico_aot_dispatch::AOT.codegen_stamp(),
    run_counted,
);

/// A replay core writes records and the snapshot thread's core does not, so the sink tells the two
/// apart.
fn run_counted(emu: &mut AotEmulatorCore) -> Result<(), String> {
    let before = emu.compiled_block_dispatches();
    let result = pico_aot_dispatch::AOT.run(emu);
    if emu.is_emitting() {
        WORKER_DISPATCHES.fetch_add(emu.compiled_block_dispatches() - before, Ordering::Relaxed);
    } else {
        DISPATCHES.store(emu.compiled_block_dispatches(), Ordering::Relaxed);
    }
    result
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Registers the generated program, refusing the stub and code generated from another ELF.
fn register(elf: &[u8], path: &Path) -> Result<(), String> {
    let generated = pico_aot_dispatch::AOT;
    if generated.is_stub() {
        return Err(
            "aot-generated/ holds the bootstrap stub, which has no compiled code; generate the \
             guest's crates first (perf/aot/aot_bench.sh does)"
                .into(),
        );
    }
    let elf_sha256: [u8; 32] = Sha256::digest(elf).into();
    if generated.elf_sha256() != elf_sha256 {
        return Err(format!(
            "aot-generated/ was generated from ELF {}, and {} is ELF {}",
            hex(&generated.elf_sha256()),
            path.display(),
            hex(&elf_sha256)
        ));
    }
    pico_aot_runtime::register(&COUNTED).map_err(|e| e.to_string())
}

/// What an arm measured; the result line's arm-specific keys.
struct Measured {
    workers: Option<NonZeroUsize>,
    chunk_size: u32,
    timed: &'static str,
    wall: Duration,
    cycles: Option<u64>,
    chunks: Option<u32>,
    records: Option<usize>,
    committed: Option<Vec<u8>>,
    phase: Option<Phase>,
    mode: Option<&'static str>,
    verified: Option<bool>,
    distinct_shapes: Option<usize>,
    traced_chunks: Option<usize>,
    /// The arm's own count of compiled blocks entered, where that is not the snapshot thread's.
    dispatches: Option<u64>,
    /// Chunks whose replays did not all digest alike.
    unequal_chunks: usize,
    /// `realloc=`'s value, an emulation arm's.
    realloc: Option<String>,
    /// Minor and major page faults over the timed call, an emulation arm's.
    faults: Option<Faults>,
    /// `retained-rows`' row counts, in [`RetainedChunk::counts`] order.
    retained: Option<[usize; 5]>,
}

fn dash<T: Display>(value: Option<T>) -> String {
    value.map_or_else(|| "-".to_string(), |value| value.to_string())
}

/// The global allocator `pico-vm` installs in this binary. Only this crate's features turn one of
/// its allocators on, and tcmalloc wins when both are (`vm/src/lib.rs`).
const ALLOC: &str = if cfg!(feature = "tcmalloc") {
    "tcmalloc"
} else if cfg!(feature = "jemalloc") {
    "jemalloc"
} else {
    "system"
};

/// The guest memory backing both emulators were built with in this binary.
const MEM: &str = if cfg!(feature = "mmap-memory") {
    "mmap"
} else {
    "heap"
};

/// The big-integer backend of the curve precompiles in this binary.
const BIGINT: &str = if cfg!(feature = "bigint-rug") {
    "rug"
} else {
    "default"
};

#[derive(Clone, Copy)]
struct Faults {
    minor: u64,
    major: u64,
}

impl Faults {
    /// The process's page faults so far, every thread's.
    fn now() -> Option<Self> {
        let mut usage = MaybeUninit::<libc::rusage>::zeroed();
        // SAFETY: `getrusage` writes the whole struct it is handed when it succeeds.
        let usage = unsafe {
            (libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) == 0)
                .then(|| usage.assume_init())
        }?;
        Some(Self {
            minor: u64::try_from(usage.ru_minflt).ok()?,
            major: u64::try_from(usage.ru_majflt).ok()?,
        })
    }

    fn since(self, before: Self) -> Self {
        Self {
            minor: self.minor - before.minor,
            major: self.major - before.major,
        }
    }
}

/// The capacity an empty `Vec<T>`'s first push gives it. The growth policy reads only the element's
/// size and alignment, which `MaybeUninit<T>` shares.
// `vec![..]` and `collect` allocate exactly one slot, not the capacity a first `push` picks.
#[allow(clippy::vec_init_then_push)]
fn first_capacity<T>() -> usize {
    let mut probe = Vec::<MaybeUninit<T>>::new();
    probe.push(MaybeUninit::uninit());
    probe.capacity()
}

/// The reallocations a vector that grew by `push` alone made to reach `capacity`, when its first
/// allocation held `first`: each later one doubles it and moves every row, and a vector that never
/// outgrew its first allocation, a reservation included, made none. `None` for a capacity that no
/// such growth reaches.
fn push_growths(capacity: usize, first: usize) -> Option<u64> {
    if capacity == 0 {
        return Some(0);
    }
    let ratio = capacity / first;
    if capacity.is_multiple_of(first) && ratio.is_power_of_two() {
        Some(u64::from(ratio.trailing_zeros()))
    } else {
        None
    }
}

/// Over a run's records: each history table's reallocations.
struct Census {
    firsts: [usize; TABLES.len()],
    tables: [u64; TABLES.len()],
    /// The tables some record held at a capacity [`push_growths`] cannot read.
    unread: [bool; TABLES.len()],
}

impl Census {
    fn new() -> Self {
        let list = first_capacity::<u32>();
        let mut firsts = [list; TABLES.len()];
        firsts[..5].copy_from_slice(&[
            first_capacity::<Step>(),
            first_capacity::<ReadAccess>(),
            first_capacity::<Access>(),
            first_capacity::<OperandException>(),
            first_capacity::<SyscallEvent>(),
        ]);
        Self {
            firsts,
            tables: [0; TABLES.len()],
            unread: [false; TABLES.len()],
        }
    }

    fn add(&mut self, record: &EmulationRecord) {
        if let Some(history) = &record.history {
            for (i, size) in table_sizes(history).into_iter().enumerate() {
                if size.in_slot {
                    continue;
                }
                match push_growths(size.capacity, self.firsts[i]) {
                    Some(growths) => self.tables[i] += growths,
                    None => self.unread[i] = true,
                }
            }
        }
    }

    /// `realloc=`'s value.
    fn line(&self) -> String {
        TABLES
            .iter()
            .zip(self.tables.iter().zip(self.unread))
            .map(|(table, (count, unread))| {
                if unread {
                    format!("{table}:?")
                } else {
                    format!("{table}:{count}")
                }
            })
            .collect::<Vec<_>>()
            .join(",")
    }
}

fn emulate(args: &Args, elf: &[u8]) -> Result<Measured, String> {
    if args.phase.is_some() {
        return Err("--phase applies to the prove arms only".into());
    }
    let program = Compiler::new(SourceType::RISCV, elf)
        .map_err(|e| format!("cannot parse `{}`: {e}", args.elf.display()))?
        .compile();
    let stdin = emulator_stdin(&args.input);
    let chunk_size = env_chunk_size()?.unwrap_or_else(default_chunk_size);
    let workers = if args.arm.pipelined() {
        Some(pipeline_workers(args)?)
    } else {
        None
    };
    let snapshot_main = if args.arm.runs_aot() {
        register(elf, &args.elf)?;
        SnapshotMainMode::Aot
    } else {
        SnapshotMainMode::Interpreter
    };
    let replay_workers = if args.arm.aot_workers() {
        ReplayWorkers::Aot
    } else {
        ReplayWorkers::Interpreter
    };
    let opts = opts(chunk_size)
        .with_snapshot_main(snapshot_main)
        .with_replay_workers(replay_workers);
    let timed = match workers {
        None => "emulate_with_opts",
        Some(_) => "emulate_with_pipeline",
    };

    let faults = Faults::now();
    let start = Instant::now();
    let output = match workers {
        None => emulate_with_opts(program, &stdin, opts),
        Some(workers) => emulate_with_pipeline(program, &stdin, opts, workers),
    };
    let wall = start.elapsed();
    let faults = Faults::now()
        .zip(faults)
        .map(|(after, before)| after.since(before));
    let output: EmulationOutput = output.map_err(|e| format!("{}: {e}", args.arm.name()))?;

    let mut census = Census::new();
    output.records.iter().for_each(|record| census.add(record));
    let records = output.records.len();
    Ok(Measured {
        workers,
        chunk_size,
        timed,
        wall,
        cycles: Some(output.cycles),
        chunks: Some(output.chunks),
        records: Some(records),
        committed: Some(output.committed_bytes),
        phase: None,
        mode: None,
        verified: None,
        distinct_shapes: None,
        traced_chunks: None,
        dispatches: None,
        unequal_chunks: 0,
        realloc: Some(census.line()),
        faults,
        retained: None,
    })
}

fn needs_workers(args: &Args) -> Result<Workers, String> {
    args.workers
        .ok_or_else(|| format!("{} needs --workers", args.arm.name()))
}

/// The replay workers a pipeline arm runs with: `--workers default` is one per core.
fn pipeline_workers(args: &Args) -> Result<NonZeroUsize, String> {
    Ok(match needs_workers(args)? {
        Workers::Count(n) => n,
        Workers::Default => NonZeroUsize::new(max_pipeline_workers()).unwrap_or(NonZeroUsize::MIN),
    })
}

/// `tracegen-aot`: `pipeline-aot`'s emulation, then every record's trace generation, with the
/// shape and concurrency a `prove-aot` run reads from the same environment.
fn tracegen(args: &Args, elf: &[u8]) -> Result<Measured, String> {
    if args.phase.is_some_and(|phase| phase != Phase::Riscv) {
        return Err("tracegen-aot stops inside the riscv phase: --phase takes riscv only".into());
    }
    let program = Compiler::new(SourceType::RISCV, elf)
        .map_err(|e| format!("cannot parse `{}`: {e}", args.elf.display()))?
        .compile();
    let stdin = emulator_stdin(&args.input);
    let env_chunk_size = env_chunk_size()?;
    let chunk_size = env_chunk_size.unwrap_or_else(default_chunk_size);
    let workers = pipeline_workers(args)?;
    register(elf, &args.elf)?;
    let opts = opts(chunk_size).with_snapshot_main(SnapshotMainMode::Aot);
    // The builder is only the environment's reader: nothing is built from it, so no keygen runs and
    // no whitelist is loaded.
    let concurrency = env_concurrency()?;
    let bucket = builder(elf, env_chunk_size, concurrency)?.whitelist_mode();
    check_tracegen_mode(bucket)?;
    let chips = RiscvChipType::<Kb>::all_chips();

    let start = Instant::now();
    let output = emulate_with_pipeline(program, &stdin, opts, workers);
    let output = output.map_err(|e| format!("{}: {e}", args.arm.name()))?;
    let traced = trace_records(&chips, &output.records, bucket, concurrency);
    ledger::drop_records(output.records);
    let wall = start.elapsed();

    // Per chunk, not per run: one CPU chunk with no trace hides inside the others' count.
    if traced.cpu_chunks == 0 || traced.cpu_chunks_traced != traced.cpu_chunks {
        return Err(format!(
            "{}: {} of {} CPU chunk(s) reached trace generation, so this run did not measure it",
            args.arm.name(),
            traced.cpu_chunks_traced,
            traced.cpu_chunks
        ));
    }
    Ok(Measured {
        workers: Some(workers),
        chunk_size,
        timed: "trace_records:emulate+augment+shape+tracegen+drop-records",
        wall,
        cycles: Some(output.cycles),
        chunks: Some(output.chunks),
        records: Some(traced.records),
        committed: Some(output.committed_bytes),
        phase: Some(Phase::Riscv),
        mode: Some(if bucket { "whitelist" } else { "dev" }),
        verified: None,
        distinct_shapes: None,
        traced_chunks: Some(traced.cpu_chunks_traced),
        dispatches: None,
        unequal_chunks: 0,
        realloc: None,
        faults: None,
        retained: None,
    })
}

fn through_prover(args: &Args, elf: &[u8]) -> Result<Measured, String> {
    let phase = match args.arm {
        arm if arm.proves() => Some(args.phase.unwrap_or(Phase::Combine)),
        _ if args.phase.is_some() => return Err("--phase applies to the prove arms only".into()),
        _ => None,
    };
    if let Some(phase) = phase {
        phase.ensure_available().map_err(|e| e.to_string())?;
    }
    let stdin = prover_stdin(&args.input);
    let env_chunk_size = env_chunk_size()?;
    let mut builder = builder(elf, env_chunk_size, env_concurrency()?)?;
    if args.arm.runs_aot() {
        builder = builder.aot(&COUNTED);
    }
    if args.arm.aot_workers() {
        builder = builder.aot_workers();
    }
    if args.arm.runs_serial() {
        builder = builder.serial_emulation();
    } else if let Workers::Count(n) = needs_workers(args)? {
        builder = builder.emulation_workers(n);
    }
    let mode = if builder.whitelist_mode() {
        "whitelist"
    } else {
        "dev"
    };
    let mut prover = builder.build().map_err(|e| e.to_string())?;
    // The emulation arms resolve the chunk size themselves; a prover arm that chunks differently
    // would not be measuring the same run.
    let chunk_size = env_chunk_size.unwrap_or_else(default_chunk_size);
    if prover.chunk_size() != chunk_size {
        return Err(format!(
            "the prover chunks at {}, and the emulation arms at {chunk_size}",
            prover.chunk_size()
        ));
    }
    DISPATCHES.store(0, Ordering::Relaxed);

    let mut measured = Measured {
        workers: prover.emulation_workers(),
        chunk_size,
        timed: "",
        wall: Duration::ZERO,
        cycles: None,
        chunks: None,
        records: None,
        committed: None,
        phase,
        mode: Some(mode),
        verified: None,
        distinct_shapes: None,
        traced_chunks: None,
        dispatches: None,
        unequal_chunks: 0,
        realloc: None,
        faults: None,
        retained: None,
    };
    let Some(phase) = phase else {
        let start = Instant::now();
        let execution = prover.execute(stdin);
        measured.wall = start.elapsed();
        let execution = execution.map_err(|e| format!("{}: {e}", args.arm.name()))?;
        measured.timed = "execute:emulate+drop-records";
        measured.cycles = Some(execution.cycles);
        measured.chunks = Some(execution.chunks);
        measured.committed = Some(execution.committed_bytes);
        return Ok(measured);
    };

    let start = Instant::now();
    let proof = prover.prove_to(stdin, phase);
    measured.wall = start.elapsed();
    measured.timed = if phase == Phase::Riscv {
        "prove_to:emulate+prove+verify+drop-records"
    } else {
        "prove_to:emulate+prove+verify+recursion-keygen+drop-records"
    };
    match proof {
        Ok(proof) => {
            measured.records = proof.chunk_count();
            measured.committed = Some(proof.committed().as_bytes().to_vec());
            measured.verified = Some(true);
            measured.distinct_shapes = proof.distinct_shapes();
        }
        Err(ProveError::Verification { message, .. }) => {
            eprintln!(
                "error: {}: the proof does not verify: {message}",
                args.arm.name()
            );
            measured.verified = Some(false);
        }
        Err(e) => return Err(format!("{}: {e}", args.arm.name())),
    }
    Ok(measured)
}

type Witness = ProvingWitness<KoalaBearPoseidon2, RiscvChips<KoalaBearPoseidon2>, Vec<u8>>;

/// The engines `replay-chunk` replays a chunk with, in its first chunk's order.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Engine {
    Interp,
    InterpNull,
    Aot,
}

impl Engine {
    const ALL: [Self; 3] = [Self::Interp, Self::InterpNull, Self::Aot];

    fn name(self) -> &'static str {
        match self {
            Self::Interp => "interp",
            Self::InterpNull => "interp-null",
            Self::Aot => "aot",
        }
    }
}

/// One engine's replay of one chunk.
struct ChunkReplay {
    engine: Engine,
    recover: Duration,
    replay: Duration,
    dispatches: u64,
    fallback_insns: u64,
    /// The chunk's record and what its replay deferred, as they are compared.
    digests: Vec<FieldDigest>,
}

/// A copy of `state` for one more replay: its accessed cells, and only those, in a block from the
/// pipeline's pool, so the copy's accessed set is the original's and it goes back to the pool as
/// the original does.
fn copy_state(state: &RiscvEmulationState) -> RiscvEmulationState {
    let mut memory = GLOBAL_MEMORY_POOL
        .1
        .recv()
        .expect("the memory pool is open");
    for (addr, value, chunk, timestamp) in state.memory.iter_accessed_entries() {
        memory.insert(
            addr,
            MemoryRecord {
                value,
                chunk,
                timestamp,
            },
        );
    }
    RiscvEmulationState {
        global_clk: state.global_clk,
        current_batch: state.current_batch,
        current_chunk: state.current_chunk,
        clk: state.clk,
        pc: state.pc,
        registers: state.registers,
        uninitialized_memory: state.uninitialized_memory.clone(),
        input_stream: state.input_stream.clone(),
        input_stream_ptr: state.input_stream_ptr,
        public_values_stream: state.public_values_stream.clone(),
        memory,
        syscall_counts: state.syscall_counts.clone(),
    }
}

/// Back to the pool, as the pipeline's workers give a snapshot's memory back.
fn release(memory: ContiguousRiscvMemory) {
    let _ = GLOBAL_MEMORY_RECYCLER.send((memory, true));
}

/// A fresh worker per replay makes every engine pay the same recovery, unlike the pipeline's
/// in-place reuse.
fn replay_chunk(
    engine: Engine,
    witness: &Witness,
    state: RiscvEmulationState,
    target: u64,
) -> Result<ChunkReplay, String> {
    let program = witness.program.clone().expect("the witness has a program");
    let deferred: SharedDeferredState =
        EmulationDeferredState::shared(program, Arc::new(RecordFinalPvsState::default()));
    let mut records = Vec::new();
    let (recover, replay, replayed, dispatches, fallback_insns) = if engine == Engine::Aot {
        let start = Instant::now();
        let mut worker =
            AotReplayMetaEmulator::recover_riscv(witness, state, deferred.clone(), target, true);
        let recover = start.elapsed();
        let start = Instant::now();
        let replayed = worker.try_next_record_batch(&mut |record| records.push(record));
        let replay = start.elapsed();
        let counts = (worker.compiled_block_dispatches(), worker.fallback_insns());
        release(worker.into_memory());
        (recover, replay, replayed, counts.0, counts.1)
    } else {
        let start = Instant::now();
        let mut worker =
            MetaEmulator::recover_riscv(witness, state, deferred.clone(), target, true);
        let recover = start.elapsed();
        let start = Instant::now();
        let replayed = worker.try_next_record_batch(&mut |record| records.push(record));
        let replay = start.elapsed();
        if let Some(emulator) = worker.emulator.take() {
            release(emulator.state.memory);
        }
        (recover, replay, replayed, 0, 0)
    };
    replayed.map_err(|e| format!("replay-chunk: the {} replay: {e}", engine.name()))?;
    // All of the pool, so what the replay deferred is compared with its record.
    records.extend(deferred.lock().take_split_records(true, u32::MAX));
    let digests = records
        .iter()
        .flat_map(field_digests)
        .filter(|(field, ..)| is_compared(field))
        .collect();
    Ok(ChunkReplay {
        engine,
        recover,
        replay,
        dispatches,
        fallback_insns,
        digests,
    })
}

/// `replay-chunk`: each chunk's snapshot from the AOT snapshot thread, replayed by every engine.
fn replay_chunks(args: &Args, elf: &[u8]) -> Result<Measured, String> {
    if args.phase.is_some() {
        return Err("--phase applies to the prove arms only".into());
    }
    let pool_size = memory_pool_size();
    let needed = Engine::ALL.len();
    if pool_size < needed {
        return Err(format!(
            "replay-chunk: MEMORY_POOL_SIZE={pool_size} is too small; need at least {needed} \
             pool blocks for the original snapshot and one copy per extra engine"
        ));
    }
    let program = Compiler::new(SourceType::RISCV, elf)
        .map_err(|e| format!("cannot parse `{}`: {e}", args.elf.display()))?
        .compile();
    let chunk_size = env_chunk_size()?.unwrap_or_else(default_chunk_size);
    register(elf, &args.elf)?;
    let opts = opts(chunk_size).with_snapshot_main(SnapshotMainMode::Aot);
    let stdin = emulator_stdin(&args.input);
    let inputs = stdin.inputs.to_vec();
    let witness = Witness::setup_for_mle_riscv(program.clone(), stdin, opts);
    let mut snapshots = create_aot_emulator(
        program,
        inputs,
        opts,
        Arc::new(RecordFinalPvsState::default()),
    )
    .ok_or("replay-chunk: no AOT program is registered")?;

    let start = Instant::now();
    let (mut chunks, mut dispatches, mut unequal_chunks) = (0u32, 0u64, 0usize);
    loop {
        let (state, batch) = snapshots
            .next_state_batch()
            .map_err(|e| format!("replay-chunk: the snapshot thread: {e}"))?;
        let target = batch.current_cycle;
        let chunk_cycles = target - state.global_clk;
        // Two copies, and the original for whichever engine runs last.
        let mut states = [
            Some(copy_state(&state)),
            Some(copy_state(&state)),
            Some(state),
        ];
        let mut replays = Vec::with_capacity(Engine::ALL.len());
        for (slot, state) in states.iter_mut().enumerate() {
            let engine = Engine::ALL[(chunks as usize + slot) % Engine::ALL.len()];
            let state = state.take().expect("one state per engine");
            replays.push(replay_chunk(engine, &witness, state, target)?);
        }
        let reference = &replays
            .iter()
            .find(|replay| replay.engine != Engine::Aot)
            .expect("two interpreters replay every chunk")
            .digests;
        let mut all_equal = true;
        for replay in &replays {
            let digest_equal = replay.digests == *reference;
            all_equal &= digest_equal;
            println!(
                "REPLAY_CHUNK chunk={} engine={} replay_us={} recover_us={} cycles={chunk_cycles} \
                 dispatches={} fallback_insns={} digest_equal={digest_equal}",
                batch.start_chunk,
                replay.engine.name(),
                replay.replay.as_micros(),
                replay.recover.as_micros(),
                replay.dispatches,
                replay.fallback_insns,
            );
            dispatches += replay.dispatches;
        }
        unequal_chunks += usize::from(!all_equal);
        chunks += 1;
        if batch.done {
            break;
        }
    }
    let wall = start.elapsed();

    Ok(Measured {
        workers: None,
        chunk_size,
        timed: "replay_chunks:snapshot+copy+3x(recover+replay+digest)",
        wall,
        cycles: Some(snapshots.cycles()),
        chunks: Some(chunks),
        records: None,
        committed: Some(snapshots.get_pv_stream()),
        phase: None,
        mode: None,
        verified: None,
        distinct_shapes: None,
        traced_chunks: None,
        dispatches: Some(dispatches),
        unequal_chunks,
        realloc: None,
        faults: None,
        retained: None,
    })
}

/// What [`RetainedChunk::counts`] counts, in order: `retained=`'s names.
const RETAINED_COUNTS: [&str; 5] = ["ecall_steps", "reads", "writes", "exceptions", "syscalls"];

/// One chunk's retained ECALL steps, staged from its history before any timer: each step's own row
/// and the rows it contributes, contiguous and in step order.
#[derive(Default)]
struct RetainedChunk {
    chunk: u32,
    steps: Vec<RetainedStep>,
    reads: Vec<ReadAccess>,
    writes: Vec<Access>,
    exceptions: Vec<OperandException>,
    syscalls: Vec<SyscallEvent>,
}

/// Where a staged step's rows sit in its [`RetainedChunk`].
struct RetainedStep {
    step: Step,
    reads: Range<usize>,
    writes: Range<usize>,
    exceptions: Range<usize>,
    syscall: Option<usize>,
}

impl RetainedChunk {
    /// The rows of every step in `history`'s ECALL list. A syscall row is its ECALL's, at the
    /// step's clock; one that no ECALL step claims is an error, since no retained step writes it.
    fn stage(history: &ExecutionHistory) -> Result<Self, String> {
        let mut staged = Self {
            chunk: history.chunk,
            ..Self::default()
        };
        let mut syscalls = history.syscalls.iter().peekable();
        let mut next_exception = 0;
        for &index in &history.chip_steps.ecall {
            let index = index as usize;
            let step = history.steps[index];
            let (reads, writes) = history.rows_of(index);
            let exceptions = &history.operand_exceptions;
            let first = next_exception
                + exceptions[next_exception..]
                    .partition_point(|exception| (exception.step as usize) < index);
            next_exception = first
                + exceptions[first..].partition_point(|exception| exception.step as usize == index);
            let syscall = syscalls
                .next_if(|syscall| syscall.clk == u64::from(step.clk))
                .map(|syscall| {
                    staged.syscalls.push(*syscall);
                    staged.syscalls.len() - 1
                });
            staged.steps.push(RetainedStep {
                step,
                reads: append(&mut staged.reads, reads),
                writes: append(&mut staged.writes, writes),
                exceptions: append(&mut staged.exceptions, &exceptions[first..next_exception]),
                syscall,
            });
        }
        if let Some(stray) = syscalls.next() {
            return Err(format!(
                "chunk {}: the syscall row at clock {} belongs to no step in the ECALL list",
                history.chunk, stray.clk
            ));
        }
        Ok(staged)
    }

    /// In [`RETAINED_COUNTS`] order.
    fn counts(&self) -> [usize; 5] {
        [
            self.steps.len(),
            self.reads.len(),
            self.writes.len(),
            self.exceptions.len(),
            self.syscalls.len(),
        ]
    }
}

fn append<T: Copy>(rows: &mut Vec<T>, more: &[T]) -> Range<usize> {
    let start = rows.len();
    rows.extend_from_slice(more);
    start..rows.len()
}

/// The tables a retained ECALL step's rows go into.
struct RetainedTables {
    steps: Vec<Step>,
    reads: Vec<ReadAccess>,
    writes: Vec<Access>,
    exceptions: Vec<OperandException>,
    ecall: Vec<u32>,
    syscalls: Vec<SyscallEvent>,
}

impl RetainedTables {
    /// Room for the largest of `chunks` in every table, each page written once.
    fn reserved(chunks: &[RetainedChunk]) -> Self {
        let most = |rows: fn(&RetainedChunk) -> usize| chunks.iter().map(rows).max().unwrap_or(0);
        Self {
            steps: touched(most(|chunk| chunk.steps.len())),
            reads: touched(most(|chunk| chunk.reads.len())),
            writes: touched(most(|chunk| chunk.writes.len())),
            exceptions: touched(most(|chunk| chunk.exceptions.len())),
            ecall: touched(most(|chunk| chunk.steps.len())),
            syscalls: touched(most(|chunk| chunk.syscalls.len())),
        }
    }

    /// Writes `chunk`'s rows as the history writer writes an ECALL step's: the step with its first
    /// read and write, its reads, its write, its exceptions renumbered to it, its index in the
    /// ECALL list and its syscall row. The time the writes took.
    ///
    /// # Panics
    ///
    /// If a table outgrew its reservation, which would time a reallocation.
    fn write(&mut self, chunk: &RetainedChunk) -> Duration {
        self.clear();
        let reserved = self.capacities();
        let start = Instant::now();
        for staged in &chunk.steps {
            let index = self.steps.len() as u32;
            self.steps.push(Step {
                first_read: self.reads.len() as u32,
                first_write: self.writes.len() as u32,
                ..staged.step
            });
            for &read in &chunk.reads[staged.reads.clone()] {
                self.reads.push(read);
            }
            for &write in &chunk.writes[staged.writes.clone()] {
                self.writes.push(write);
            }
            for &exception in &chunk.exceptions[staged.exceptions.clone()] {
                self.exceptions.push(OperandException {
                    step: index,
                    ..exception
                });
            }
            self.ecall.push(index);
            if let Some(syscall) = staged.syscall {
                self.syscalls.push(chunk.syscalls[syscall]);
            }
        }
        let took = start.elapsed();
        std::hint::black_box(&*self);
        assert_eq!(
            self.capacities(),
            reserved,
            "a retained-row table outgrew its reservation"
        );
        took
    }

    fn capacities(&self) -> [usize; 6] {
        [
            self.steps.capacity(),
            self.reads.capacity(),
            self.writes.capacity(),
            self.exceptions.capacity(),
            self.ecall.capacity(),
            self.syscalls.capacity(),
        ]
    }

    fn clear(&mut self) {
        self.steps.clear();
        self.reads.clear();
        self.writes.clear();
        self.exceptions.clear();
        self.ecall.clear();
        self.syscalls.clear();
    }
}

/// `rows` rows of room, every one written once so the timed writes take no first-touch fault. A
/// zeroed `vec!` could leave its pages unmapped.
fn touched<T: Copy + Default>(rows: usize) -> Vec<T> {
    let mut table = Vec::with_capacity(rows);
    table.resize(rows, T::default());
    std::hint::black_box(&mut table);
    table.clear();
    table
}

/// `retained-rows`: `pipeline-aot`'s emulation writing the execution history alone, each chunk's
/// retained ECALL steps staged as its record passes and the record dropped, then each chunk's rows
/// written alone into the reserved tables.
fn retained_rows(args: &Args, elf: &[u8]) -> Result<Measured, String> {
    if args.phase.is_some() {
        return Err("--phase applies to the prove arms only".into());
    }
    let program = Compiler::new(SourceType::RISCV, elf)
        .map_err(|e| format!("cannot parse `{}`: {e}", args.elf.display()))?
        .compile();
    let stdin = emulator_stdin(&args.input);
    let chunk_size = env_chunk_size()?.unwrap_or_else(default_chunk_size);
    let workers = pipeline_workers(args)?;
    register(elf, &args.elf)?;
    let opts = opts(chunk_size).with_snapshot_main(SnapshotMainMode::Aot);

    let reader = program.clone();
    let mut staged = Vec::new();
    let mut records = 0;
    // Counted from the program, not from the lists, so a list that misses an ECALL shows.
    let mut ecalls = 0;
    let output = emulate_with_pipeline_streaming(program, &stdin, opts, workers, |record| {
        records += 1;
        if let Some(history) = &record.history {
            ecalls += history
                .steps
                .iter()
                .filter(|step| reader.fetch(u64::from(step.pc)).is_ecall_instruction())
                .count();
            staged.push(RetainedChunk::stage(history));
        }
    })
    .map_err(|e| format!("{}: {e}", args.arm.name()))?;
    let chunks = staged.into_iter().collect::<Result<Vec<_>, _>>()?;
    let listed: usize = chunks.iter().map(|chunk| chunk.steps.len()).sum();
    if listed != ecalls {
        return Err(format!(
            "{}: the histories' ECALL lists hold {listed} steps, and their steps run {ecalls} \
             ECALLs",
            args.arm.name()
        ));
    }

    let mut tables = RetainedTables::reserved(&chunks);
    let mut wall = Duration::ZERO;
    let mut retained = [0; 5];
    for chunk in &chunks {
        let took = tables.write(chunk);
        wall += took;
        let counts = chunk.counts();
        for (total, count) in retained.iter_mut().zip(counts) {
            *total += count;
        }
        let [ecall_steps, reads, writes, exceptions, syscalls] = counts;
        println!(
            "RETAINED_ROWS chunk={} ecall_steps={ecall_steps} reads={reads} writes={writes} \
             exceptions={exceptions} syscalls={syscalls} write_ns={}",
            chunk.chunk,
            took.as_nanos()
        );
    }

    Ok(Measured {
        workers: Some(workers),
        chunk_size,
        timed: "retained_rows:write",
        wall,
        cycles: Some(output.cycles),
        chunks: Some(output.chunks),
        records: Some(records),
        committed: Some(output.committed_bytes),
        phase: None,
        mode: None,
        verified: None,
        distinct_shapes: None,
        traced_chunks: None,
        dispatches: None,
        unequal_chunks: 0,
        realloc: None,
        faults: None,
        retained: Some(retained),
    })
}

const CENSUS_OUT: &str = "PICO_BENCH_CENSUS_OUT";
const CENSUS_FOLD: &str = "PICO_BENCH_CENSUS_FOLD";
const CENSUS_REPLACE: &str = "PICO_BENCH_CENSUS_REPLACE";
const LEDGER_COMMIT: &str = "MLE_LEDGER_COMMIT";
const LEDGER_DIRTY: &str = "MLE_LEDGER_DIRTY";

/// Where `history-census` writes its capacity table, the earlier one it folds in, and whether
/// that fold may cross trees.
struct CensusFiles {
    out: Option<PathBuf>,
    fold: Option<PathBuf>,
    replace: bool,
}

/// [`CENSUS_OUT`], [`CENSUS_FOLD`] and [`CENSUS_REPLACE`], as [`check_census_files`] takes them.
fn env_census_files(arm: Arm) -> Result<CensusFiles, String> {
    let path = |raw: &str| Ok(PathBuf::from(raw));
    let files = CensusFiles {
        out: mapped(CENSUS_OUT, "capacity table", path)?,
        fold: mapped(CENSUS_FOLD, "capacity table to fold in", path)?,
        replace: env_flag(CENSUS_REPLACE),
    };
    check_census_files(arm, &files)?;
    Ok(files)
}

/// Refuses any of them on an arm but `history-census`, a fold with nowhere to write, which would
/// compute a table and drop it, and a switch for a fold that is not made.
fn check_census_files(arm: Arm, files: &CensusFiles) -> Result<(), String> {
    if arm != Arm::HistoryCensus && (files.out.is_some() || files.fold.is_some() || files.replace) {
        return Err(format!(
            "{CENSUS_OUT}, {CENSUS_FOLD} and {CENSUS_REPLACE} say what history-census writes and \
             folds in, and {} reads none of them",
            arm.name()
        ));
    }
    if files.fold.is_some() && files.out.is_none() {
        return Err(format!(
            "{CENSUS_FOLD} folds a capacity table into this run's: set {CENSUS_OUT} to write it"
        ));
    }
    if files.replace && files.fold.is_none() {
        return Err(format!(
            "{CENSUS_REPLACE} lets a fold cross trees: set {CENSUS_FOLD} to fold one in"
        ));
    }
    Ok(())
}

/// The tree this run measures, from the stage ledger's provenance variables, which
/// `aot_bench.sh` exports from the checkout. A copied tree is a fresh one-commit repository whose
/// own commit names nothing, so its run is told the commit; without one the census refuses
/// rather than guess.
fn env_tree() -> Result<Tree, String> {
    let commit = mapped(LEDGER_COMMIT, "tree commit", |raw| Ok(raw.to_string()))?;
    let dirty = mapped(LEDGER_DIRTY, "tree dirty", |raw| match raw {
        "0" | "false" => Ok(false),
        "1" | "true" => Ok(true),
        _ => Err("expected 0, 1, false or true".to_string()),
    })?;
    match (commit, dirty) {
        (Some(commit), Some(dirty)) => {
            Tree::new(&commit, dirty).map_err(|e| format!("{LEDGER_COMMIT}={commit}: {e}"))
        }
        _ => Err(format!(
            "history-census records the tree each block was measured on: set {LEDGER_COMMIT} and \
             {LEDGER_DIRTY}, as aot_bench.sh does"
        )),
    }
}

/// What decides where this run's chunks end, as the library reads it. The chunk split's event and
/// commit-tail thresholds do not depend on the program's syscall cycles, which only its clock
/// threshold reads. Built after the run: the first chunk split built in a process logs its
/// configuration, and this one, built without the syscall cycles, would log a clock threshold the
/// run never used.
fn chunking(chunk_size: u32) -> Chunking {
    let split = ChunkSplitConfig::for_chunk_size(chunk_size, 0);
    Chunking {
        chunk_size,
        memory_rw_threshold: split.memory_rw_threshold,
        commit_tail_reserve: split.commit_tail_reserve,
        commit_tail_overrun: split.commit_tail_overrun,
    }
}

/// How this run cuts its chunks' replays, as the library reads it.
fn replay_split() -> ReplaySplit {
    ReplaySplit {
        segments: split_segments(),
        chunks: split_chunks(),
        from_chunk: split_from_chunk(),
    }
}

/// `history-census`: `retained-rows`' emulation, each chunk's census taken as its record passes and
/// the record dropped, then the run's summary and its capacity table.
fn history_census(args: &Args, elf: &[u8], files: CensusFiles) -> Result<Measured, String> {
    if args.phase.is_some() {
        return Err("--phase applies to the prove arms only".into());
    }
    let program = Compiler::new(SourceType::RISCV, elf)
        .map_err(|e| format!("cannot parse `{}`: {e}", args.elf.display()))?
        .compile();
    let stdin = emulator_stdin(&args.input);
    let chunk_size = env_chunk_size()?.unwrap_or_else(default_chunk_size);
    let workers = pipeline_workers(args)?;
    register(elf, &args.elf)?;
    let opts = opts(chunk_size).with_snapshot_main(SnapshotMainMode::Aot);
    // Before the run, so a file that holds no capacity table, or one of another tree that was not
    // asked for, fails before the emulation is paid for; its chunking is compared after it.
    let tree = env_tree()?;
    let earlier = files.fold.as_deref().map(CapacityTable::read).transpose()?;
    if let Some(earlier) = earlier.as_ref().filter(|_| !files.replace) {
        earlier
            .check_tree(&tree)
            .map_err(|e| format!("{e}: set {CENSUS_REPLACE}=1 to fold it in anyway"))?;
    }

    let reader = program.clone();
    let mut chunks = Vec::new();
    let mut records = 0;
    let start = Instant::now();
    let output = emulate_with_pipeline_streaming(program, &stdin, opts, workers, |record| {
        records += 1;
        if let Some(history) = &record.history {
            chunks.push(ChunkCensus::of(history, &reader));
        }
    })
    .map_err(|e| format!("{}: {e}", args.arm.name()))?;
    let wall = start.elapsed();
    if chunks.len() != output.chunks as usize {
        return Err(format!(
            "{}: {} CPU chunk(s) ran and {} held a history, so the census would miss some",
            args.arm.name(),
            output.chunks,
            chunks.len()
        ));
    }

    for chunk in &chunks {
        println!("{}", chunk.line());
    }
    let summary = summarise(&chunks).ok_or("history-census: the run emitted no CPU chunk")?;
    let block = Block {
        elf_sha256: hex(&Sha256::digest(elf)),
        input_sha256: args
            .input
            .iter()
            .map(|input| hex(&Sha256::digest(&input.bytes)))
            .collect(),
        input_labels: args.input.iter().map(|input| input.label.clone()).collect(),
        tree,
        replay_split: replay_split(),
        chunks: chunks.len(),
        max_rows: TableRows::largest(&summary),
    };
    let table = CapacityTable::fold(earlier, chunking(chunk_size), block, files.replace)?;
    for line in summary_lines(&summary, &table) {
        println!("{line}");
    }
    println!("{}", windows_line(&chunks));
    if let Some(out) = &files.out {
        table.write(out)?;
        eprintln!(
            "wrote the capacity table over {} block(s) to {}",
            table.blocks.len(),
            out.display()
        );
    }
    let unattributed: usize = chunks.iter().map(|chunk| chunk.windows.unattributed).sum();
    if unattributed > 0 {
        return Err(format!(
            "{unattributed} CPU memory access(es) follow an access of their own chunk that no \
             load, store or precompile made, so the window census cannot tell what they follow"
        ));
    }

    Ok(Measured {
        workers: Some(workers),
        chunk_size,
        timed: "emulate_with_pipeline_streaming:emulate+census",
        wall,
        cycles: Some(output.cycles),
        chunks: Some(output.chunks),
        records: Some(records),
        committed: Some(output.committed_bytes),
        phase: None,
        mode: None,
        verified: None,
        distinct_shapes: None,
        traced_chunks: None,
        dispatches: None,
        unequal_chunks: 0,
        realloc: None,
        faults: None,
        retained: None,
    })
}

/// `history-arena`: `retained-rows`' emulation, each chunk's history copied into an arena slot,
/// uploaded and read back as its record passes, and the record dropped.
fn history_arena(args: &Args, elf: &[u8]) -> Result<Measured, String> {
    if args.phase.is_some() {
        return Err("--phase applies to the prove arms only".into());
    }
    let program = Compiler::new(SourceType::RISCV, elf)
        .map_err(|e| format!("cannot parse `{}`: {e}", args.elf.display()))?
        .compile();
    let stdin = emulator_stdin(&args.input);
    let chunk_size = env_chunk_size()?.unwrap_or_else(default_chunk_size);
    let workers = pipeline_workers(args)?;
    register(elf, &args.elf)?;
    let opts = opts(chunk_size).with_snapshot_main(SnapshotMainMode::Aot);
    let slots = record_slots_from_env()?;
    eprintln!("env: {SLOTS_VAR} -> HistoryArena::pin({slots})");
    let start = Instant::now();
    let capacity = HistoryCapacity::CENSUS;
    let arena = HistoryArena::pin(slots, chunk_size, capacity, SpillPolicy::Spill)
        .map_err(|e| e.to_string())?;
    let pinned = arena.stats();
    eprintln!(
        "pinned {} history slots of {} bytes, {} bytes, in {:.3}s",
        pinned.slots,
        pinned.slot_bytes,
        pinned.pinned_bytes(),
        start.elapsed().as_secs_f64()
    );

    let mut lines = Vec::new();
    let mut failed = 0;
    let mut run_max_rows = [0; TABLE_COUNT];
    let mut records = 0;
    let start = Instant::now();
    let output = emulate_with_pipeline_streaming(program, &stdin, opts, workers, |record| {
        records += 1;
        let Some(HistoryView { history, program }) = record.history_view() else {
            return;
        };
        let counts = DerivedRows::of(history, program);
        let (rows, spilled, upload) = match arena.fill(history) {
            Ok(filled) => {
                let spilled: Vec<&str> = filled.spilled().map(Table::name).collect();
                // The round trip through a card needs `cuda`; without it the fill alone is checked.
                #[cfg(feature = "cuda")]
                let upload = match round_trip(0, &filled, counts, program, CPU_SLICE_STEPS) {
                    Ok(differ) if differ.is_empty() => "equal".to_string(),
                    Ok(differ) => format!("differs:{}", differ.join(",")),
                    Err(e) => format!("error:{e}"),
                };
                #[cfg(not(feature = "cuda"))]
                let upload = {
                    let _ = (counts, program);
                    "-".to_string()
                };
                (filled.rows(), spilled, upload)
            }
            Err(e) => ([0; TABLE_COUNT], Vec::new(), format!("error:{e}")),
        };
        for (max, rows) in run_max_rows.iter_mut().zip(rows) {
            *max = rows.max(*max);
        }
        failed += usize::from(upload != "equal" && upload != "-");
        lines.push(format!(
            "ARENA chunk={} steps={} bytes={} spilled={} upload={upload}",
            history.chunk,
            history.steps.len(),
            history.bytes(),
            if spilled.is_empty() {
                "-".to_string()
            } else {
                spilled.join(",")
            },
        ));
    })
    .map_err(|e| format!("{}: {e}", args.arm.name()))?;
    let wall = start.elapsed();
    if lines.len() != output.chunks as usize {
        return Err(format!(
            "{}: {} CPU chunk(s) ran and {} held a history",
            args.arm.name(),
            output.chunks,
            lines.len()
        ));
    }

    for line in &lines {
        println!("{line}");
    }
    let stats = arena.stats();
    for table in Table::ALL {
        println!(
            "ARENA_SPILL table={} capacity={} run_max_rows={} spills={}",
            table.name(),
            capacity.rows(table),
            run_max_rows[table.index()],
            stats.spills[table.index()]
        );
    }
    println!(
        "ARENA_SLOT slots={} slot_bytes={} pinned_bytes={} max_in_use={} blocked_takes={} \
         acquisitions={} returns={}",
        stats.slots,
        stats.slot_bytes,
        stats.pinned_bytes(),
        stats.max_in_use,
        stats.blocked_takes,
        stats.acquisitions,
        stats.returns
    );
    if failed > 0 {
        return Err(format!(
            "{failed} chunk(s) did not come back from the device as they were uploaded"
        ));
    }

    Ok(Measured {
        workers: Some(workers),
        chunk_size,
        timed: "emulate_with_pipeline_streaming:emulate+arena-fill+upload+read-back",
        wall,
        cycles: Some(output.cycles),
        chunks: Some(output.chunks),
        records: Some(records),
        committed: Some(output.committed_bytes),
        phase: None,
        mode: None,
        verified: None,
        distinct_shapes: None,
        traced_chunks: None,
        dispatches: None,
        unequal_chunks: 0,
        realloc: None,
        faults: None,
        retained: None,
    })
}

fn input_labels(inputs: &[Input]) -> String {
    inputs
        .iter()
        .map(|input| input.label.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

fn run(args: Args) -> Result<ExitCode, String> {
    let elf = std::fs::read(&args.elf)
        .map_err(|e| format!("cannot read `{}`: {e}", args.elf.display()))?;
    let census_files = env_census_files(args.arm)?;
    let traces = args.arm == Arm::TracegenAot;
    // Built on first use otherwise, which only the arms that run the snapshot pipeline make: its
    // memories and threads would land inside their timer and no other arm's.
    init_memory_pool();
    if ledger::enabled() || std::env::var_os("MLE_SPANS").is_some() {
        ledger::set_driver(ledger::Driver {
            arm: Some(args.arm.name().to_string()),
            label: Some(
                args.label
                    .clone()
                    .unwrap_or_else(|| args.arm.name().to_string()),
            ),
            rep: args.rep.clone(),
            warmup: args.warmup,
            elf: Some(ledger::FileId {
                path: args.elf.display().to_string(),
                sha256: hex(&Sha256::digest(&elf)),
            }),
            input: (!args.input.is_empty()).then(|| ledger::FileId {
                path: input_labels(&args.input),
                sha256: args
                    .input
                    .iter()
                    .map(|input| hex(&Sha256::digest(&input.bytes)))
                    .collect::<Vec<_>>()
                    .join(","),
            }),
            // `None` for the arm that stops before the prove: it writes its own skipped lines for
            // the two stages it lacks, and the rest of the prove side is live.
            proves: match args.arm {
                Arm::TracegenAot => None,
                arm => Some(arm.proves()),
            },
        });
    }
    let measured = match args.arm {
        Arm::EmulateOpts | Arm::PipelineInterp | Arm::PipelineAot | Arm::PipelineAotWorkers => {
            emulate(&args, &elf)?
        }
        Arm::TracegenAot => tracegen(&args, &elf)?,
        Arm::ReplayChunk => replay_chunks(&args, &elf)?,
        Arm::RetainedRows => retained_rows(&args, &elf)?,
        Arm::HistoryCensus => history_census(&args, &elf, census_files)?,
        Arm::HistoryArena => history_arena(&args, &elf)?,
        Arm::ExecuteDefault
        | Arm::ExecuteAot
        | Arm::ExecuteSerial
        | Arm::ProveDefault
        | Arm::ProveAot
        | Arm::ProveSerial
        | Arm::ProveAotWorkers => through_prover(&args, &elf)?,
    };

    let aot = args.arm.runs_aot();
    let dispatches = measured
        .dispatches
        .unwrap_or_else(|| DISPATCHES.load(Ordering::Relaxed));
    let worker_dispatches = args
        .arm
        .aot_workers()
        .then(|| WORKER_DISPATCHES.load(Ordering::Relaxed));
    let input = if args.input.is_empty() {
        "-".to_string()
    } else {
        input_labels(&args.input)
    };
    let ledger_path = ledger::enabled()
        .then(|| std::env::var("MLE_LEDGER").ok())
        .flatten();
    let guest = args
        .elf
        .file_name()
        .map_or_else(|| "-".into(), |name| name.to_string_lossy());
    println!(
        "AOT_BENCH arm={} guest={guest} input={input} workers={} chunk_size={} timed={} \
         wall_s={:.6} cycles={} chunks={} records={} committed_sha256={} aot_elf_sha256={} \
         aot_dispatches={} aot_worker_dispatches={} trace_source={} \
         branch_compares={} phase={} mode={} verified={} distinct_shapes={} traced_chunks={} \
         ledger={} alloc={ALLOC} mem={MEM} bigint={BIGINT} realloc={} minor_faults={} \
         major_faults={} retained={} retained_rows_us={}",
        args.arm.name(),
        dash(measured.workers),
        measured.chunk_size,
        measured.timed,
        measured.wall.as_secs_f64(),
        dash(measured.cycles),
        dash(measured.chunks),
        dash(measured.records),
        dash(measured.committed.map(|bytes| hex(&Sha256::digest(bytes)))),
        dash(aot.then(|| hex(&pico_aot_dispatch::AOT.elf_sha256()))),
        dash(aot.then_some(dispatches)),
        dash(worker_dispatches),
        dash(traces.then_some("history")),
        dash(traces.then_some("indices")),
        dash(measured.phase),
        dash(measured.mode),
        dash(measured.verified),
        dash(measured.distinct_shapes),
        dash(measured.traced_chunks),
        dash(ledger_path),
        dash(measured.realloc.as_deref()),
        dash(measured.faults.map(|faults| faults.minor)),
        dash(measured.faults.map(|faults| faults.major)),
        dash(measured.retained.map(|counts| {
            RETAINED_COUNTS
                .iter()
                .zip(counts)
                .map(|(name, count)| format!("{name}:{count}"))
                .collect::<Vec<_>>()
                .join(",")
        })),
        dash(
            measured
                .retained
                .map(|_| format!("{:.3}", measured.wall.as_secs_f64() * 1e6))
        ),
    );
    ledger::finish();
    if measured.verified == Some(false) {
        return Ok(ExitCode::FAILURE);
    }
    if measured.unequal_chunks > 0 {
        eprintln!(
            "error: {} chunk(s) replayed to records that differ between engines",
            measured.unequal_chunks
        );
        return Ok(ExitCode::FAILURE);
    }
    if aot && dispatches == 0 {
        eprintln!(
            "error: the AOT snapshot thread entered no compiled block, so this run measured the \
             interpreter"
        );
        return Ok(ExitCode::from(3));
    }
    if worker_dispatches == Some(0) {
        eprintln!(
            "error: the AOT replay workers entered no compiled block, so this run measured \
             interpreting workers"
        );
        return Ok(ExitCode::from(3));
    }
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    pico_sdk::init_logger();
    check_removed_knobs(|name| std::env::var_os(name).is_some())
        .and_then(|()| run(Args::parse()))
        .unwrap_or_else(|e| {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pico_vm::emulator::riscv::history::ChipSteps;

    #[test]
    fn removed_representation_knobs_are_refused() {
        assert!(check_removed_knobs(|_| false).is_ok());
        for removed in REMOVED_REPRESENTATION_KNOBS {
            let error = check_removed_knobs(|name| name == removed).unwrap_err();
            assert!(error.contains(removed));
            assert!(error.contains("was removed"));
        }
    }

    #[test]
    fn tracegen_requires_dev_mode() {
        assert!(check_tracegen_mode(true).is_err());
        assert!(check_tracegen_mode(false).is_ok());
    }

    /// `n` pushes into an empty vector: its capacity, and how many of them moved its rows.
    fn pushed<T: Copy + Default>(n: usize) -> (usize, u64) {
        let mut rows = Vec::<T>::new();
        let mut moves = 0;
        for _ in 0..n {
            moves += u64::from(!rows.is_empty() && rows.len() == rows.capacity());
            rows.push(T::default());
        }
        (rows.capacity(), moves)
    }

    #[test]
    fn a_tables_capacity_says_how_often_push_moved_its_rows() {
        fn check<T: Copy + Default>() {
            let first = first_capacity::<T>();
            for n in [0, 1, 2, 3, 4, 5, 7, 8, 9, 100, 4097, 1 << 16] {
                let (capacity, moves) = pushed::<T>(n);
                assert_eq!(
                    push_growths(capacity, first),
                    Some(moves),
                    "{n} pushes of {} bytes",
                    size_of::<T>()
                );
            }
            assert_eq!(push_growths(3 * first, first), None);
        }
        assert_eq!(
            push_growths(100, 100),
            Some(0),
            "a reservation never outgrown"
        );
        assert_eq!(push_growths(200, 100), Some(1));
        check::<Step>();
        check::<ReadAccess>();
        check::<Access>();
        check::<OperandException>();
        check::<SyscallEvent>();
        check::<u32>();
    }

    #[test]
    fn the_census_counts_every_table_and_reads_no_growth_off_the_ladder() {
        let mut history = ExecutionHistory::default();
        for _ in 0..9 {
            history.steps.push(Step::default());
        }
        history.chip_steps.branch.push(0);
        let (steps_capacity, steps_moves) = pushed::<Step>(9);
        assert_eq!(history.steps.capacity(), steps_capacity);
        let mut record = EmulationRecord::default();
        assert!(record.history.is_none());
        record.history = Some(history);
        let mut census = Census::new();
        census.add(&record);
        census.add(&record);
        let line = census.line();
        assert!(
            line.starts_with(&format!("steps:{},reads:0,", 2 * steps_moves)),
            "{line}"
        );
        assert!(line.ends_with(",branch:0"), "{line}");
        assert_eq!(line.split(',').count(), TABLES.len(), "{line}");

        let first = first_capacity::<u32>();
        if let Some(history) = &mut record.history {
            history.chip_steps.ecall = Vec::with_capacity(3 * first).into();
        }
        let mut census = Census::new();
        census.add(&record);
        assert!(census.line().contains(",ecall:?,"), "{}", census.line());
    }

    #[test]
    fn the_census_files_are_the_census_arms_alone_and_a_fold_needs_somewhere_to_go() {
        let files = |out: bool, fold: bool, replace: bool| CensusFiles {
            out: out.then(|| PathBuf::from("out.json")),
            fold: fold.then(|| PathBuf::from("fold.json")),
            replace,
        };
        let census =
            |out, fold, replace| check_census_files(Arm::HistoryCensus, &files(out, fold, replace));
        assert!(census(false, false, false).is_ok());
        assert!(census(true, false, false).is_ok());
        assert!(census(true, true, false).is_ok());
        assert!(census(true, true, true).is_ok());
        assert!(census(false, true, false).is_err());
        assert!(census(true, false, true).is_err(), "a switch for no fold");
        for arm in [Arm::RetainedRows, Arm::PipelineAot] {
            assert!(check_census_files(arm, &files(false, false, false)).is_ok());
            assert!(check_census_files(arm, &files(true, false, false)).is_err());
            assert!(check_census_files(arm, &files(false, true, false)).is_err());
            assert!(check_census_files(arm, &files(false, false, true)).is_err());
        }
    }

    /// Three steps: an ALU step with an exception, an ECALL that sends a syscall and has an
    /// exception, and an ECALL that sends none.
    fn ecall_history() -> ExecutionHistory {
        let step = |clk: u32, first_read: u32, first_write: u32| Step {
            clk,
            pc: 0x1000 + 4 * clk,
            next_pc: 0x1004 + 4 * clk,
            first_read,
            first_write,
        };
        let read = |value: u64| ReadAccess {
            value,
            ..ReadAccess::default()
        };
        let write = |value: u64| Access {
            value,
            ..Access::default()
        };
        let exception = |step: u32| OperandException {
            step,
            slot: 1,
            value: 7,
        };
        ExecutionHistory {
            steps: vec![step(8, 0, 0), step(12, 1, 1), step(16, 3, 2)].into(),
            reads: vec![read(1), read(2), read(3), read(4), read(5)].into(),
            writes: vec![write(10), write(20), write(30)].into(),
            operand_exceptions: vec![exception(0), exception(1)].into(),
            chip_steps: ChipSteps {
                add: vec![0].into(),
                ecall: vec![1, 2].into(),
                ..ChipSteps::default()
            },
            syscalls: vec![SyscallEvent {
                clk: 12,
                syscall_id: 0x10,
                ..SyscallEvent::default()
            }]
            .into(),
            ..ExecutionHistory::default()
        }
    }

    #[test]
    fn a_split_chunks_appended_tables_are_counted_without_an_error() {
        let mut later = ExecutionHistory::default();
        for clk in 0..5 {
            later.steps.push(Step {
                clk,
                ..Step::default()
            });
        }
        let mut history = ExecutionHistory::default();
        history.append(&mut later);
        let steps = push_growths(history.steps.capacity(), first_capacity::<Step>())
            .map_or_else(|| "?".to_string(), |growths| growths.to_string());
        let mut record = EmulationRecord::default();
        assert!(record.history.is_none());
        record.history = Some(history);
        let mut census = Census::new();
        census.add(&record);
        let line = census.line();
        assert!(
            line.starts_with(&format!("steps:{steps},reads:0,")),
            "{line}"
        );
        assert_eq!(line.split(',').count(), TABLES.len(), "{line}");
    }

    /// A table in its arena slot's region never moved its rows, however full; one that spilled
    /// out of it grew from the region's size, off the push ladder, and reads `?`.
    #[test]
    fn the_census_counts_a_slot_table_unmoved_and_reads_a_spilled_one_off_the_ladder() {
        let mut history = ExecutionHistory::default();
        for _ in 0..9 {
            history.steps.push(Step::default());
        }
        let room = |steps: usize| {
            Table::ALL
                .into_iter()
                .fold(HistoryCapacity::CENSUS, |capacity, table| {
                    capacity.with_rows(table, 16)
                })
                .with_rows(Table::Steps, steps)
        };
        let census = |steps: usize| {
            let arena =
                HistoryArena::pin(NonZeroUsize::MIN, 1 << 20, room(steps), SpillPolicy::Spill)
                    .expect("an arena");
            let record = EmulationRecord {
                history: Some(arena.fill(&history).expect("a spill, not a refusal")),
                ..EmulationRecord::default()
            };
            let mut census = Census::new();
            census.add(&record);
            census.line()
        };
        let in_slot = census(16);
        assert!(in_slot.starts_with("steps:0,reads:0,"), "{in_slot}");
        assert!(!in_slot.contains('?'), "{in_slot}");
        let spilled = census(4);
        assert!(spilled.starts_with("steps:?,reads:0,"), "{spilled}");
    }

    #[test]
    fn a_retained_ecall_step_writes_its_own_rows_and_no_others() {
        let staged = RetainedChunk::stage(&ecall_history()).expect("every syscall row is claimed");
        assert_eq!(staged.counts(), [2, 4, 2, 1, 1]);
        let mut tables = RetainedTables::reserved(std::slice::from_ref(&staged));
        tables.write(&staged);
        let firsts: Vec<(u32, u32)> = tables
            .steps
            .iter()
            .map(|step| (step.first_read, step.first_write))
            .collect();
        assert_eq!(firsts, [(0, 0), (2, 1)]);
        assert_eq!(
            tables
                .reads
                .iter()
                .map(|read| read.value)
                .collect::<Vec<_>>(),
            [2, 3, 4, 5]
        );
        assert_eq!(
            tables
                .writes
                .iter()
                .map(|write| write.value)
                .collect::<Vec<_>>(),
            [20, 30]
        );
        assert_eq!(
            tables.exceptions[0].step, 0,
            "renumbered to the retained step"
        );
        assert_eq!(tables.ecall, [0, 1]);
        assert_eq!(tables.syscalls[0].clk, 12);
    }

    #[test]
    fn a_syscall_row_no_retained_step_claims_is_an_error() {
        let mut history = ecall_history();
        history.syscalls[0].clk = 8;
        assert!(RetainedChunk::stage(&history).is_err());
    }
}
