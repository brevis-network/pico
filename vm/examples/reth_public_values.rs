//! What the reth guest commits, per block — dumped, and checked against another ELF's.
//!
//! `perf/bench_data/rv64/reth-elf` is a binary deliverable with no source in this repository, so a
//! rebuild has to be checked against what it *outputs*. Until 2026-09 that check was "the committed
//! value digest matches the old ELF's, block for block", which stopped working the moment rsp added
//! `config_digest` to `CommittedHeader`: the committed value legitimately grew, so digest equality
//! is now guaranteed to fail and says nothing when it does.
//!
//! This replaces it with the relation that does hold across such a change — the new stream is the
//! old one with a fixed-width tail appended — plus a pinned value for that tail. The tail is wider
//! than the digest it carries: bincode writes an 8-byte little-endian length ahead of it, so a
//! 32-byte digest arrives as 40 bytes and `--expect-tail` takes 80 hex characters.
//!
//! ```text
//! # dump a baseline from the ELF being replaced
//! cargo run -r --example reth_public_values -- --elf <old> --report old.txt --dump-only
//!
//! # check the new one against it
//! cargo run -r --example reth_public_values -- --elf <new> --report new.txt \
//!     --against old.txt --expect-tail <80 hex chars>
//!
//! # and the degenerate case: two ELFs that must commit exactly the same bytes
//! cargo run -r --example reth_public_values -- --elf <b> --report b.txt \
//!     --against a.txt --tail-bytes 0
//! ```
//!
//! Exactly one of `--dump-only` and `--against` is required, so that a command line which has lost
//! its `--against` fails instead of passing while checking nothing.
//!
//! The tail's *value* cannot be derived here: it is a keccak over a domain tag and the bincode
//! encoding of three rsp wire fields, and this workspace depends on neither rsp nor revm. It is
//! computed once on the rsp side and pinned through `--expect-tail`, with the recipe recorded in
//! the commit that introduces the value. What this example adds on top is that **every block's tail
//! is the same**: the three fields it covers are per-input configuration, so a fixture whose
//! configuration differs from the rest reddens here — which is the reason that digest exists.
//!
//! `CHUNK_SIZE` goes in the report header and a check refuses a baseline taken under a different
//! one. The committed bytes and the retired count do not depend on the chunking; the set of event
//! kinds can, because some events are chunk-boundary artefacts.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    sync::Arc,
};

use alloy_primitives::keccak256;
use clap::Parser;
use p3_koala_bear::KoalaBear;
use pico_vm::{
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{
        opts::EmulatorOpts,
        record::RecordBehavior,
        riscv::{public_values::RecordFinalPvsState, riscv_emulator::RiscvEmulator},
        stdin::EmulatorStdin,
    },
};

/// Fallback chunk size, and the default capacity of the pinned CPU and ALU event buffers.
const DEFAULT_CHUNK_SIZE: &str = "4194304";

/// Fields are tab-separated because event-kind names contain spaces (`Cpu Events`).
const SEP: char = '\t';

#[derive(Parser, Debug)]
#[clap(about = "Dump and check what the reth guest commits, per block")]
struct Args {
    /// The guest ELF to run.
    #[clap(long)]
    elf: PathBuf,

    /// Directory holding the `reth-<block>.bin` fixtures.
    #[clap(long, default_value = "perf/bench_data/rv64")]
    inputs: PathBuf,

    /// Where to write this ELF's report.
    #[clap(long)]
    report: PathBuf,

    /// Write the report and check nothing. Mutually exclusive with `--against`.
    #[clap(long)]
    dump_only: bool,

    /// A report produced by another ELF, to check this one against.
    #[clap(long)]
    against: Option<PathBuf>,

    /// How many bytes the new stream is expected to have gained over `--against`.
    ///
    /// 40 for the `config_digest` change: bincode writes the field as an 8-byte little-endian
    /// length (`0x20`) followed by the digest's 32 bytes. 0 asserts the two ELFs commit identical
    /// bytes, which is how a change that must not touch the committed value is checked.
    #[clap(long, default_value_t = 40)]
    tail_bytes: usize,

    /// Assert every block's gained tail equals this (hex, no `0x`).
    #[clap(long)]
    expect_tail: Option<String>,

    /// Only these blocks, comma-separated. Dump mode only — a checked run must cover the whole
    /// baseline, or "every fixture shares one configuration digest" becomes true by having one.
    #[clap(long)]
    blocks: Option<String>,

    /// Assert this many fixtures ran.
    ///
    /// Matching the baseline is not enough on its own: a one-block baseline and a one-block run
    /// agree with each other, and every per-fixture claim then holds over one fixture. The count
    /// an acceptance run expects is knowledge this file does not have, so the caller states it.
    #[clap(long)]
    expect_blocks: Option<usize>,
}

/// One block's outcome. Everything a rebuild is judged on that a single emulation can answer.
struct BlockReport {
    block: u64,
    /// Always 0 in practice: a `HALT` with a non-zero code surfaces as an emulation *error*
    /// (`EmulationError::HaltWithNonZeroExitCode`), which aborts the run, rather than reaching
    /// these public values. Recorded because the report should say what the run saw, not because
    /// it is a gate — the gate is that the emulation returned at all.
    exit_code: u32,
    /// Retired instructions, summed over records.
    retired: usize,
    /// The event kinds this block reached. A new ELF that makes a chip newly reachable shows up
    /// here and nowhere else in this file.
    event_kinds: BTreeSet<String>,
    /// The bytes the guest committed. Small — a header and a digest — so it is carried verbatim
    /// rather than hashed, which keeps a mismatch readable.
    public_values: Vec<u8>,
}

/// One baseline block, as far as this file compares them.
struct Baseline {
    public_values: Vec<u8>,
    event_kinds: BTreeSet<String>,
    retired: Option<usize>,
}

fn main() {
    let args = Args::parse();
    assert!(
        args.dump_only ^ args.against.is_some(),
        "pass exactly one of --dump-only and --against"
    );
    assert!(
        args.blocks.is_none() || args.dump_only,
        "--blocks is dump-only: a checked run has to cover the whole baseline"
    );
    assert!(
        !(args.dump_only && args.expect_tail.is_some()),
        "--expect-tail has nothing to act on under --dump-only"
    );
    if let Some(a) = &args.against {
        assert!(
            a != &args.report,
            "--against and --report are the same file: the baseline would be overwritten \
             with this run's own output and then compared against itself"
        );
    }

    // `EmulatorOpts::default()` derives the chunk size from host RAM, while the pinned CPU and ALU
    // event buffers are sized from `CHUNK_SIZE` alone and default to 2^22. A derived chunk larger
    // than the buffers overflows them part-way through a block — "Buffer is full", from
    // `event_pool.rs`. `mle::machine::riscv::emulate` clamps instead, using two `pub(crate)`
    // constants an example cannot see, so setting the variable is the seam that is public.
    if std::env::var_os("CHUNK_SIZE").is_none() {
        std::env::set_var("CHUNK_SIZE", DEFAULT_CHUNK_SIZE);
    }
    let chunk_size = std::env::var("CHUNK_SIZE").expect("just set");

    let elf_bytes = std::fs::read(&args.elf)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", args.elf.display()));
    let elf_digest = keccak256(&elf_bytes);
    let program = Compiler::new(SourceType::RISCV, elf_bytes.as_slice())
        .expect("failed to parse ELF")
        .compile();

    // Read before running, not after: an unreadable or mismatched baseline should cost a second
    // rather than the twenty minutes of emulation that used to precede it.
    let old = args.against.as_ref().map(|p| read_report(p, &chunk_size));

    let wanted: Option<BTreeSet<u64>> = args.blocks.as_ref().map(|s| {
        s.split(',')
            .map(|b| b.trim().parse().expect("--blocks takes block numbers"))
            .collect()
    });

    let mut reports = Vec::new();
    for (block, path) in fixtures(&args.inputs) {
        if wanted.as_ref().is_some_and(|w| !w.contains(&block)) {
            continue;
        }
        eprintln!("block {block}: running");
        let input =
            std::fs::read(&path).unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
        reports.push(run_block(block, &program, &input));
    }
    assert!(
        !reports.is_empty(),
        "no fixtures matched in {}",
        args.inputs.display()
    );
    if let Some(w) = &wanted {
        let ran: BTreeSet<u64> = reports.iter().map(|r| r.block).collect();
        assert_eq!(*w, ran, "--blocks named fixtures that are not in --inputs");
    }
    if let Some(n) = args.expect_blocks {
        assert_eq!(
            n,
            reports.len(),
            "expected {n} fixtures in {}, ran {}",
            args.inputs.display(),
            reports.len()
        );
    }
    // A block that committed nothing is not a block that agreed with the baseline, and in dump mode
    // it would become the next round's baseline unchallenged.
    for r in &reports {
        assert!(
            !r.public_values.is_empty(),
            "block {} committed no public values",
            r.block
        );
    }

    write_report(
        &args.report,
        &args.elf,
        elf_digest.as_slice(),
        &chunk_size,
        &reports,
    );
    eprintln!("wrote {}", args.report.display());

    let Some(baseline) = &args.against else {
        eprintln!("dump only: {} blocks, nothing checked", reports.len());
        return;
    };

    let old = old.expect("read above whenever --against is set");
    let tails = check_against(baseline, &old, &reports, args.tail_bytes);
    report_retired(&old, &reports);

    // Every fixture is expected to carry the same configuration, so the tails agree. A fixture that
    // does not is the case the digest was added to make visible, not a bug in this check.
    let mut by_value: BTreeMap<&[u8], Vec<u64>> = BTreeMap::new();
    for (block, tail) in &tails {
        by_value.entry(tail.as_slice()).or_default().push(*block);
    }
    assert_eq!(
        by_value.len(),
        1,
        "the fixtures do not share one configuration digest: {}",
        by_value
            .iter()
            .map(|(tail, blocks)| format!("{} <- {blocks:?}", hex::encode(tail)))
            .collect::<Vec<_>>()
            .join("; ")
    );
    let actual = hex::encode(by_value.keys().next().unwrap());
    eprintln!("tail (all {} blocks): {actual}", tails.len());
    match &args.expect_tail {
        Some(expected) => {
            assert_eq!(
                actual,
                expected
                    .trim()
                    .trim_start_matches("0x")
                    .to_ascii_lowercase(),
                "the committed tail is not the pinned value"
            );
            eprintln!("tail matches --expect-tail");
        }
        None if args.tail_bytes != 0 => {
            eprintln!("warning: no --expect-tail, so the tail's *value* is unchecked")
        }
        None => {}
    }

    eprintln!(
        "OK: {} blocks checked against {}",
        reports.len(),
        baseline.display()
    );
}

/// `reth-<block>.bin` in `dir`, ordered by block number.
fn fixtures(dir: &Path) -> Vec<(u64, PathBuf)> {
    let mut out: Vec<(u64, PathBuf)> = std::fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("cannot list {}: {e}", dir.display()))
        .filter_map(|entry| {
            let path = entry.ok()?.path();
            let name = path.file_name()?.to_str()?;
            let block = name
                .strip_prefix("reth-")?
                .strip_suffix(".bin")?
                .parse()
                .ok()?;
            Some((block, path))
        })
        .collect();
    out.sort();
    out
}

fn run_block(block: u64, program: &Arc<Program>, input: &[u8]) -> BlockReport {
    let mut builder = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    builder.write_slice(input);
    let stdin = builder.finalize::<Program>();

    let mut emulator = RiscvEmulator::new_single::<KoalaBear>(
        program.clone(),
        Arc::new(RecordFinalPvsState::default()),
        EmulatorOpts::default(),
        None,
    );
    for chunk in &*stdin.inputs {
        emulator.state.input_stream.push(chunk.clone());
    }

    let mut retired = 0usize;
    let mut event_kinds = BTreeSet::new();
    let mut exit_code = 0u32;
    loop {
        // Records are read and dropped rather than collected: a heavy block produces enough of them
        // to matter, and nothing here needs a second pass over one. A block that halts non-zero
        // returns `Err` here, which is what actually stops a bad ELF.
        let mut batch = Vec::new();
        let report = emulator
            .emulate_batch(&mut |record| batch.push(record))
            .unwrap_or_else(|e| panic!("block {block} failed to emulate: {e:?}"));
        for record in &batch {
            retired += record.cpu_events.len();
            // `stats()` already drops zero-valued entries; filtering again would say otherwise.
            event_kinds.extend(record.stats().into_keys());
            if record.public_values.exit_code != 0 {
                exit_code = record.public_values.exit_code;
            }
        }
        if report.done {
            break;
        }
    }

    BlockReport {
        block,
        exit_code,
        retired,
        event_kinds,
        public_values: emulator.state.public_values_stream.clone(),
    }
}

fn write_report(
    path: &Path,
    elf: &Path,
    elf_digest: &[u8],
    chunk_size: &str,
    reports: &[BlockReport],
) {
    let mut out = String::new();
    out.push_str(&format!("# elf {}\n", elf.display()));
    out.push_str(&format!("# elf_keccak {}\n", hex::encode(elf_digest)));
    out.push_str(&format!("# chunk_size {chunk_size}\n"));
    for r in reports {
        let events = r.event_kinds.iter().cloned().collect::<Vec<_>>().join(",");
        out.push_str(&format!(
            "block={}{SEP}rc={}{SEP}retired={}{SEP}pv_len={}{SEP}pv={}{SEP}events={}\n",
            r.block,
            r.exit_code,
            r.retired,
            r.public_values.len(),
            hex::encode(&r.public_values),
            events,
        ));
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).expect("cannot create the report's directory");
        }
    }
    std::fs::write(path, out).unwrap_or_else(|e| panic!("cannot write {}: {e}", path.display()));
}

/// Checks each block's committed bytes are the baseline's with exactly `tail_bytes` appended and
/// its event kinds unchanged, over exactly the same set of blocks. Returns the appended tails.
fn check_against(
    path: &Path,
    old: &BTreeMap<u64, Baseline>,
    reports: &[BlockReport],
    tail_bytes: usize,
) -> BTreeMap<u64, Vec<u8>> {
    let ran: BTreeSet<u64> = reports.iter().map(|r| r.block).collect();
    let based: BTreeSet<u64> = old.keys().copied().collect();
    assert_eq!(
        based,
        ran,
        "this run and {} cover different blocks",
        path.display()
    );

    let mut tails = BTreeMap::new();
    for r in reports {
        let before = &old[&r.block];
        assert_eq!(
            r.public_values.len(),
            before.public_values.len() + tail_bytes,
            "block {}: committed {} bytes against the baseline's {}, expected {tail_bytes} more",
            r.block,
            r.public_values.len(),
            before.public_values.len()
        );
        assert!(
            r.public_values.starts_with(&before.public_values),
            "block {}: the committed bytes are not the baseline's with a tail appended",
            r.block
        );
        assert_eq!(
            before.event_kinds,
            r.event_kinds,
            "block {}: the set of event kinds changed; only in the baseline {:?}, only here {:?}",
            r.block,
            before
                .event_kinds
                .difference(&r.event_kinds)
                .collect::<Vec<_>>(),
            r.event_kinds
                .difference(&before.event_kinds)
                .collect::<Vec<_>>()
        );
        tails.insert(
            r.block,
            r.public_values[before.public_values.len()..].to_vec(),
        );
    }
    tails
}

/// Prints the retired-instruction delta this run carries over its baseline.
///
/// Not a gate: a rebuild is allowed to cost instructions, and how many is a judgement someone
/// makes with the four-card figures in front of them. It is printed because a column that is
/// written to a file and never looked at is how a tenfold regression ships unnoticed.
fn report_retired(old: &BTreeMap<u64, Baseline>, reports: &[BlockReport]) {
    let (mut before, mut after) = (0usize, 0usize);
    for r in reports {
        let Some(b) = old[&r.block].retired else {
            eprintln!("baseline records no retired count; skipping the delta");
            return;
        };
        before += b;
        after += r.retired;
        eprintln!(
            "  block {:>10}  {:>15} -> {:>15}  {:+.2}%",
            r.block,
            b,
            r.retired,
            (r.retired as f64 - b as f64) / b as f64 * 100.0
        );
    }
    eprintln!(
        "  {:>16}  {:>15} -> {:>15}  {:+.2}%",
        "TOTAL",
        before,
        after,
        (after as f64 - before as f64) / before as f64 * 100.0
    );
}

fn read_report(path: &Path, chunk_size: &str) -> BTreeMap<u64, Baseline> {
    let text = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("cannot read {}: {e}", path.display()));
    let mut out: BTreeMap<u64, Baseline> = BTreeMap::new();
    let mut seen_chunk_size = None;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("# chunk_size ") {
            seen_chunk_size = Some(rest.trim().to_string());
            continue;
        }
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let mut block = None;
        let mut pv = None;
        let mut pv_len = None;
        let mut retired = None;
        let mut events = BTreeSet::new();
        for field in line.split(SEP) {
            match field.split_once('=') {
                Some(("block", v)) => block = v.parse().ok(),
                Some(("retired", v)) => retired = v.parse::<usize>().ok(),
                Some(("pv", v)) => {
                    pv = Some(hex::decode(v).unwrap_or_else(|e| {
                        panic!("{}: block {block:?} has malformed pv: {e}", path.display())
                    }))
                }
                Some(("pv_len", v)) => pv_len = v.parse::<usize>().ok(),
                Some(("events", v)) => {
                    events = v
                        .split(',')
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned)
                        .collect()
                }
                _ => {}
            }
        }
        let block = block.unwrap_or_else(|| {
            // Distinguish the two ways this happens, because they have different fixes: a report
            // in the pre-tab format parses as one giant field, and a corrupt number does not.
            let hint = if line.contains("block=") {
                "its block= did not parse as a number, or the fields are not tab-separated \
                 (a report written before this format is space-separated)"
            } else {
                "it carries no block= at all"
            };
            panic!("{}: unusable line -- {hint}: {line}", path.display())
        });
        let pv = pv.unwrap_or_else(|| panic!("{}: block {block} has no pv=", path.display()));
        // `pv_len` is redundant with `pv`, which is what makes it worth checking: a report truncated
        // in transit disagrees with itself here rather than becoming a shorter baseline.
        if let Some(n) = pv_len {
            assert_eq!(
                n,
                pv.len(),
                "{}: block {block} says pv_len={n} but carries {} bytes",
                path.display(),
                pv.len()
            );
        }
        assert!(
            out.insert(
                block,
                Baseline {
                    public_values: pv,
                    event_kinds: events,
                    retired
                }
            )
            .is_none(),
            "{}: block {block} appears twice",
            path.display()
        );
    }
    assert!(!out.is_empty(), "{} has no blocks", path.display());
    // Event kinds can move with the chunking even when the program does not, so a baseline taken
    // under a different `CHUNK_SIZE` is not comparable on that column.
    match seen_chunk_size {
        Some(s) if s == chunk_size => {}
        Some(s) => panic!(
            "{} was taken at CHUNK_SIZE={s}, this run is at {chunk_size}",
            path.display()
        ),
        None => panic!(
            "{} records no CHUNK_SIZE; regenerate it with this example",
            path.display()
        ),
    }
    out
}
