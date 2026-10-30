//! One arm of the AOT measurement per process, against the guest generated into `aot-generated/`.
//!
//! - `emulate-opts`: `riscv::emulate_with_opts`, the one interpreter the SDK proves from by default.
//! - `pipeline-interp`: `emulate_with_pipeline` with the interpreter on the snapshot thread.
//! - `pipeline-aot`: the same with the generated code on the snapshot thread, so the two pipeline
//!   arms differ in that alone: the same options and the same `--workers`.
//! - `execute-default`, `execute-aot`: `Prover::execute`, which runs the snapshot pipeline without
//!   a witness, from the builders the two prove arms use.
//! - `prove-default`: `Prover::prove_to` from a builder without `aot`, which emulates through
//!   `emulate_with_opts`.
//! - `prove-aot`: the same with `aot`, and `emulation_workers(--workers)` unless `--workers
//!   default`, which emulates through the pipeline with the generated code.
//!
//! The emulation arms run under the options `pico-prover` builds for itself. The prover arms take
//! `CHUNK_SIZE`, `PROVE_CONCURRENCY`, `VK_VERIFICATION`, `MLE_VK_MAP` and `MLE_VK_ROOT` onto the
//! builder's setters as `cargo pico prove` maps them, and so prove in whitelist mode when the
//! environment says so.
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
//!
//! Parsing the ELF, reading the input, `build`, the snapshot pipeline's memory pool (built up front
//! in every arm), and hashing and dropping what the call returned stay outside it.
//!
//! Prints one line, `AOT_BENCH` then space-separated `key=value` pairs, `-` where a key does not
//! apply to the arm: `arm`, `guest` (the ELF's file name), `input`, `workers` (resolved: `--workers
//! default` is the core count), `chunk_size`, `timed`, `wall_s`, `cycles`, `chunks`, `records` (for
//! a prove arm, the RISC-V chunk proofs, one per record), `committed_sha256`, `aot_elf_sha256`,
//! `aot_dispatches` (compiled blocks the snapshot thread entered), `phase`, `mode` (`dev` or
//! `whitelist`), `verified` and `distinct_shapes` (`Proof::distinct_shapes`).
//!
//! `RUST_LOG` filters the prover's logs on stderr, as in `cargo pico`.
//!
//! Exits 1 on an error, a proof that does not verify included, and 3 when an AOT arm entered no
//! compiled block: it measured the interpreter under an AOT label. An AOT arm whose program is the
//! bootstrap stub, or was generated from another ELF, is an error before anything runs.

use std::{
    fmt::{self, Display},
    num::NonZeroUsize,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use clap::{Parser, ValueEnum};
use pico_aot_runtime::{AotEmulatorCore, AotProgram};
use pico_prover::{
    Phase, ProveError, Prover, ProverBuilder, Stdin, ENV_NO_LONGER_READ, ENV_READ_BY_PROVER,
};
use pico_vm::{
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{
        opts::{EmulatorOpts, SnapshotMainMode, SplitOpts},
        riscv::{chunk_split::ChunkSplitConfig, memory::init_memory_pool},
        stdin::EmulatorStdin,
    },
    mle::machine::riscv::{emulate_with_opts, emulate_with_pipeline, DEFAULT_LOG_STACKED_HEIGHT},
    primitives::consts::MAX_LOG_NUMBER_OF_CHUNKS,
    proverchain::riscv::max_pipeline_workers,
};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Arm {
    EmulateOpts,
    PipelineInterp,
    PipelineAot,
    ExecuteDefault,
    ExecuteAot,
    ProveDefault,
    ProveAot,
}

impl Arm {
    fn name(self) -> &'static str {
        match self {
            Self::EmulateOpts => "emulate-opts",
            Self::PipelineInterp => "pipeline-interp",
            Self::PipelineAot => "pipeline-aot",
            Self::ExecuteDefault => "execute-default",
            Self::ExecuteAot => "execute-aot",
            Self::ProveDefault => "prove-default",
            Self::ProveAot => "prove-aot",
        }
    }

    fn runs_aot(self) -> bool {
        matches!(self, Self::PipelineAot | Self::ExecuteAot | Self::ProveAot)
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
    /// pipeline arms, and the builder's own default for the AOT prover arms. Required by the arms
    /// with workers, ignored by those that emulate with one interpreter
    #[clap(long, value_parser = parse_workers)]
    workers: Option<Workers>,

    /// The phase the prove arms prove to: riscv, convert, combine, embed or wrap [default: combine]
    #[clap(long, value_parser = parse_phase)]
    phase: Option<Phase>,
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

/// `pico-prover`'s emulator options, every field stated so no environment variable decides one.
fn opts(chunk_size: u32) -> EmulatorOpts {
    EmulatorOpts {
        chunk_size,
        chunk_batch_size: 1,
        split_opts: SplitOpts::new(chunk_size as usize >> 2),
        max_cycles: Some((chunk_size as u64) * (2 << MAX_LOG_NUMBER_OF_CHUNKS)),
        cycle_tracker: false,
        cost_estimator: false,
        snapshot_main: SnapshotMainMode::Interpreter,
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
fn builder(elf: &[u8], chunk_size: Option<u32>) -> Result<ProverBuilder, String> {
    let mut builder = Prover::builder(elf);
    if let Some(n) = chunk_size {
        builder = builder.chunk_size(n);
    }
    let concurrency = mapped("PROVE_CONCURRENCY", "concurrency", |raw| {
        raw.parse::<NonZeroUsize>().map_err(|e| e.to_string())
    })?;
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

/// The generated program, registered in its place: the same digest and the same code, reporting
/// after every batch how many compiled blocks the run has entered.
static COUNTED: AotProgram = AotProgram::new(pico_aot_dispatch::AOT.elf_sha256(), run_counted);

fn run_counted(emu: &mut AotEmulatorCore) -> Result<(), String> {
    let result = pico_aot_dispatch::AOT.run(emu);
    DISPATCHES.store(emu.compiled_block_dispatches(), Ordering::Relaxed);
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
}

fn dash<T: Display>(value: Option<T>) -> String {
    value.map_or_else(|| "-".to_string(), |value| value.to_string())
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
    let workers = match args.arm {
        Arm::PipelineInterp | Arm::PipelineAot => Some(match needs_workers(args)? {
            Workers::Count(n) => n,
            Workers::Default => {
                NonZeroUsize::new(max_pipeline_workers()).unwrap_or(NonZeroUsize::MIN)
            }
        }),
        _ => None,
    };
    let snapshot_main = if args.arm == Arm::PipelineAot {
        register(elf, &args.elf)?;
        SnapshotMainMode::Aot
    } else {
        SnapshotMainMode::Interpreter
    };
    let opts = opts(chunk_size).with_snapshot_main(snapshot_main);
    let timed = if workers.is_some() {
        "emulate_with_pipeline"
    } else {
        "emulate_with_opts"
    };

    let start = Instant::now();
    let output = match workers {
        None => emulate_with_opts(program, &stdin, opts),
        Some(workers) => emulate_with_pipeline(program, &stdin, opts, workers),
    };
    let wall = start.elapsed();
    let output = output.map_err(|e| format!("{}: {e}", args.arm.name()))?;

    Ok(Measured {
        workers,
        chunk_size,
        timed,
        wall,
        cycles: Some(output.cycles),
        chunks: Some(output.chunks),
        records: Some(output.records.len()),
        committed: Some(output.committed_bytes),
        phase: None,
        mode: None,
        verified: None,
        distinct_shapes: None,
    })
}

fn needs_workers(args: &Args) -> Result<Workers, String> {
    args.workers
        .ok_or_else(|| format!("{} needs --workers", args.arm.name()))
}

fn through_prover(args: &Args, elf: &[u8]) -> Result<Measured, String> {
    let phase = match args.arm {
        Arm::ProveDefault | Arm::ProveAot => Some(args.phase.unwrap_or(Phase::Combine)),
        _ if args.phase.is_some() => return Err("--phase applies to the prove arms only".into()),
        _ => None,
    };
    if let Some(phase) = phase {
        phase.ensure_available().map_err(|e| e.to_string())?;
    }
    let stdin = prover_stdin(&args.input);
    let env_chunk_size = env_chunk_size()?;
    let mut builder = builder(elf, env_chunk_size)?;
    if args.arm.runs_aot() {
        builder = builder.aot(&COUNTED);
        if let Workers::Count(n) = needs_workers(args)? {
            builder = builder.emulation_workers(n);
        }
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
        // `prove-default` on the CPU emulates with one interpreter; the other arms run the pipeline.
        workers: (!matches!(args.arm, Arm::ProveDefault)).then(|| prover.emulation_workers()),
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

fn run(args: Args) -> Result<ExitCode, String> {
    let elf = std::fs::read(&args.elf)
        .map_err(|e| format!("cannot read `{}`: {e}", args.elf.display()))?;
    // Built on first use otherwise, which only the pipeline arms make: its memories and threads
    // would land inside their timer and no other arm's.
    init_memory_pool();
    let measured = match args.arm {
        Arm::EmulateOpts | Arm::PipelineInterp | Arm::PipelineAot => emulate(&args, &elf)?,
        Arm::ExecuteDefault | Arm::ExecuteAot | Arm::ProveDefault | Arm::ProveAot => {
            through_prover(&args, &elf)?
        }
    };

    let aot = args.arm.runs_aot();
    let dispatches = DISPATCHES.load(Ordering::Relaxed);
    let input = if args.input.is_empty() {
        "-".to_string()
    } else {
        args.input
            .iter()
            .map(|input| input.label.as_str())
            .collect::<Vec<_>>()
            .join(",")
    };
    let guest = args
        .elf
        .file_name()
        .map_or_else(|| "-".into(), |name| name.to_string_lossy());
    println!(
        "AOT_BENCH arm={} guest={guest} input={input} workers={} chunk_size={} timed={} \
         wall_s={:.6} cycles={} chunks={} records={} committed_sha256={} aot_elf_sha256={} \
         aot_dispatches={} phase={} mode={} verified={} distinct_shapes={}",
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
        dash(measured.phase),
        dash(measured.mode),
        dash(measured.verified),
        dash(measured.distinct_shapes),
    );
    if measured.verified == Some(false) {
        return Ok(ExitCode::FAILURE);
    }
    if aot && dispatches == 0 {
        eprintln!(
            "error: the AOT snapshot thread entered no compiled block, so this run measured the \
             interpreter"
        );
        return Ok(ExitCode::from(3));
    }
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    pico_sdk::init_logger();
    run(Args::parse()).unwrap_or_else(|e| {
        eprintln!("error: {e}");
        ExitCode::FAILURE
    })
}
