//! Two ways of emulating a guest, compared record by record. Compiled into
//! `vm/tests/pipeline_record_parity.rs`, and by path into `perf/aot/record_parity`, a crate of
//! another workspace that cannot reach this one's tests.
//!
//! [`check_guest`] runs every run of a [`Guest`] down a reference arm and a candidate arm, prints
//! every problem it finds, and then fails on any. A problem is a difference in the committed bytes,
//! cycles, chunks or reports (in `start_chunk` order); in any record, in emission order, by kind,
//! `chunk_index`, public value or `record_digest::field_digests` row; or in the final digests on
//! the last record, which the SDK's `backfill_final_digests` reads. So is any reason the
//! comparison would hold vacuously: no record compared, fewer chunks than the run is there to
//! reach, a deferred block out before the last chunk where the run pins none or the reverse, or
//! final digests that do not show what the guest commits and defers.
//!
//! Each arm's output is reduced to those digests before the other runs: the BLS12-381 field guest
//! emits gigabytes of events, and two of its outputs at once are more than a laptop has.

use std::{num::NonZeroUsize, sync::Arc};

use pico_vm::{
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        program::Program,
    },
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{
        opts::{EmulatorOpts, SnapshotMainMode, SplitOpts},
        record::RecordBehavior,
        riscv::{
            public_values::PublicValues,
            record_digest::{field_digests, is_compared},
        },
        stdin::EmulatorStdin,
    },
    machine::report::EmulationReport,
    mle::machine::riscv::{emulate_with_opts, EmulateError, EmulationOutput},
    proverchain::riscv::max_pipeline_workers,
};
use serde::Serialize;

// Relative to this file rather than `CARGO_MANIFEST_DIR`: the crates compiling it sit in
// different directories.
pub const FIB_ELF: &[u8] = include_bytes!("../../../perf/bench_data/rv64/fib-elf");
/// Decompresses, adds and multiplies Ed25519 points.
const ED25519_ELF: &[u8] = include_bytes!("../../../perf/bench_data/rv64/ed25519-elf");
/// Hashes through the Poseidon2 precompile; reads its round count.
const POSEIDON2_ELF: &[u8] = include_bytes!("../../../perf/bench_data/rv64/poseidon2-elf");
/// BLS12-381 field arithmetic, enough of it that its field additions fill a full deferred block
/// after its third chunk of `WHOLE`, long before its last.
pub const BLS12381_FP_ELF: &[u8] = include_bytes!("../../../perf/bench_data/rv64/bls12381-fp-elf");
/// Claims one deferred proof per `(program id, output)` pair it reads, then commits both lists.
const AGGREGATOR_ELF: &[u8] = include_bytes!("../../../perf/bench_data/rv64/aggregator-elf");

/// One chunk holds every run below but the BLS12-381 field guest's.
pub const WHOLE: u32 = 1 << 22;
/// A size at which fib(10)'s eight COMMIT ecalls would straddle a chunk boundary if a chunk could
/// be cut while a commit is in flight.
const COMMIT_SPLITTING_CHUNK: u32 = 9500;
/// Many more chunks than workers, so the workers finish out of order and their reports have to
/// be put back in order.
const MANY_CHUNKS: u32 = 17;

/// A guest both suites compare on. `name` is `perf/aot/record_parity.sh`'s argument, and the ELF
/// is `perf/bench_data/rv64/<name>-elf`.
pub struct Guest {
    pub name: &'static str,
    pub elf: &'static [u8],
    /// The guest claims deferred proofs, so its final deferred digest is nonzero.
    defers: bool,
    runs: fn() -> Vec<Run>,
}

/// One comparison: an input, and a chunk size small enough to reach `at_least_chunks` chunks.
struct Run {
    stdin: Vec<Vec<u8>>,
    chunk_size: u32,
    at_least_chunks: u32,
    /// A full deferred block comes out between two CPU chunks, not only after the last.
    early_block: bool,
}

pub const GUESTS: [Guest; 5] = [
    Guest {
        name: "fib",
        elf: FIB_ELF,
        defers: false,
        runs: fib_runs,
    },
    Guest {
        name: "ed25519",
        elf: ED25519_ELF,
        defers: false,
        runs: ed25519_runs,
    },
    Guest {
        name: "poseidon2",
        elf: POSEIDON2_ELF,
        defers: false,
        runs: poseidon2_runs,
    },
    Guest {
        name: "aggregator",
        elf: AGGREGATOR_ELF,
        defers: true,
        runs: aggregator_runs,
    },
    Guest {
        name: "bls12381-fp",
        elf: BLS12381_FP_ELF,
        defers: false,
        runs: bls12381_fp_runs,
    },
];

fn run(stdin: Vec<Vec<u8>>, chunk_size: u32, at_least_chunks: u32) -> Run {
    Run {
        stdin,
        chunk_size,
        at_least_chunks,
        early_block: false,
    }
}

/// The last is the commit-tail case.
fn fib_runs() -> Vec<Run> {
    vec![
        run(fib_input(10), WHOLE, 1),
        run(fib_input(10), 512, MANY_CHUNKS),
        run(fib_input(10), COMMIT_SPLITTING_CHUNK, 2),
    ]
}

fn ed25519_runs() -> Vec<Run> {
    vec![
        run(ed25519_input(), WHOLE, 1),
        run(ed25519_input(), 1 << 14, MANY_CHUNKS),
    ]
}

fn poseidon2_runs() -> Vec<Run> {
    vec![
        run(vec![element(&1u32)], WHOLE, 1),
        run(vec![element(&1u32)], 1 << 10, MANY_CHUNKS),
    ]
}

fn aggregator_runs() -> Vec<Run> {
    vec![
        run(aggregator_input(), WHOLE, 1),
        run(aggregator_input(), 1 << 14, MANY_CHUNKS),
    ]
}

/// Eight chunks, with full deferred blocks out after the third and the fifth: the candidate has
/// to emit them there too, split from the pool mid-run, not held to the end.
fn bls12381_fp_runs() -> Vec<Run> {
    vec![Run {
        early_block: true,
        ..run(Vec::new(), WHOLE, 2)
    }]
}

pub fn program(elf: &[u8]) -> Arc<Program> {
    Compiler::new(SourceType::RISCV, elf)
        .expect("parse the ELF")
        .compile()
}

pub fn stdin(elements: &[Vec<u8>]) -> EmulatorStdin<Program, Vec<u8>> {
    let mut builder = EmulatorStdin::<Program, Vec<u8>>::new_builder::<KoalaBearPoseidon2>();
    for element in elements {
        builder.write_slice(element);
    }
    builder.finalize()
}

fn element<T: Serialize>(value: &T) -> Vec<u8> {
    bincode::serialize(value).expect("serialize a stdin element")
}

/// Every field stated: `EmulatorOpts::default` reads `CHUNK_SIZE`, `CHUNK_BATCH_SIZE` and
/// `SPLIT_THRESHOLD`.
pub fn opts(chunk_size: u32) -> EmulatorOpts {
    EmulatorOpts {
        chunk_size,
        chunk_batch_size: 1,
        split_opts: SplitOpts::new(chunk_size as usize >> 2),
        max_cycles: Some(1 << 32),
        cycle_tracker: false,
        cost_estimator: false,
        snapshot_main: SnapshotMainMode::Interpreter,
    }
}

/// Several, so the workers can finish out of order: four, or the core count if lower.
pub fn workers() -> NonZeroUsize {
    NonZeroUsize::new(max_pipeline_workers().min(4)).expect("at least one core")
}

pub fn fib_input(n: u32) -> Vec<Vec<u8>> {
    vec![element(&n)]
}

/// The basepoint, its negation and two scalars, as `vm/examples/common/parse_args.rs` writes them.
fn ed25519_input() -> Vec<Vec<u8>> {
    let mut basepoint = [0x66u8; 32];
    basepoint[0] = 0x58;
    let mut negated = basepoint;
    negated[31] |= 0x80;
    let mut scalar = [0u8; 32];
    scalar[..4].copy_from_slice(&10u32.to_le_bytes());
    let mut second = scalar;
    second[4] = 1;
    vec![
        element(&basepoint),
        element(&negated),
        element(&scalar),
        element(&second),
    ]
}

/// Two claims over fib's real outputs. The program ids are made up: the ones
/// `examples/aggregator/prover` writes come from proving fib to a root, and the emulator only
/// folds them into the deferred digest, along the same path whatever their value.
fn aggregator_input() -> Vec<Vec<u8>> {
    let outputs: Vec<Vec<u8>> = [10u32, 20]
        .iter()
        .map(|&n| {
            emulate_with_opts(program(FIB_ELF), &stdin(&fib_input(n)), opts(WHOLE))
                .expect("fib")
                .committed_bytes
        })
        .collect();
    let program_ids: Vec<[u32; 8]> = vec![
        std::array::from_fn(|i| i as u32 + 1),
        std::array::from_fn(|i| i as u32 + 101),
    ];
    vec![element(&program_ids), element(&outputs)]
}

/// Every public value, by name, so a difference names its field.
fn public_value_fields(pv: &PublicValues<u32, u32>) -> Vec<(&'static str, String)> {
    vec![
        (
            "committed_value_digest",
            format!("{:?}", pv.committed_value_digest),
        ),
        (
            "deferred_proofs_digest",
            format!("{:?}", pv.deferred_proofs_digest),
        ),
        ("start_pc", format!("{:?}", pv.start_pc)),
        ("next_pc", format!("{:?}", pv.next_pc)),
        ("exit_code", format!("{}", pv.exit_code)),
        ("chunk", format!("{}", pv.chunk)),
        ("execution_chunk", format!("{}", pv.execution_chunk)),
        (
            "previous_init_addr_limbs",
            format!("{:?}", pv.previous_init_addr_limbs),
        ),
        (
            "last_init_addr_limbs",
            format!("{:?}", pv.last_init_addr_limbs),
        ),
        (
            "previous_finalize_addr_limbs",
            format!("{:?}", pv.previous_finalize_addr_limbs),
        ),
        (
            "last_finalize_addr_limbs",
            format!("{:?}", pv.last_finalize_addr_limbs),
        ),
        ("deferred_commits", format!("{}", pv.deferred_commits)),
        (
            "deferred_commit_mask",
            format!("{}", pv.deferred_commit_mask),
        ),
        ("empty", format!("{:?}", pv.empty)),
    ]
}

/// What the comparison reads off a record: its kind, `chunk_index`, public values and the rows of
/// `field_digests`.
struct RecordDigest {
    is_cpu_chunk: bool,
    chunk_index: usize,
    public_values: PublicValues<u32, u32>,
    rows: Vec<(&'static str, usize, u64)>,
}

/// An [`EmulationOutput`] with each record reduced to its [`RecordDigest`].
struct OutputDigest {
    records: Vec<RecordDigest>,
    chunks: u32,
    committed_bytes: Vec<u8>,
    cycles: u64,
    reports: Vec<EmulationReport>,
}

fn reduce(output: EmulationOutput) -> OutputDigest {
    OutputDigest {
        records: output
            .records
            .iter()
            .map(|record| RecordDigest {
                is_cpu_chunk: record.is_cpu_chunk,
                chunk_index: record.chunk_index(),
                public_values: record.public_values,
                rows: field_digests(record),
            })
            .collect(),
        chunks: output.chunks,
        committed_bytes: output.committed_bytes,
        cycles: output.cycles,
        reports: output.reports,
    }
}

/// Whether a full deferred block comes out before the last CPU chunk's record.
fn has_early_block(output: &OutputDigest) -> bool {
    let last_cpu = output.records.iter().rposition(|r| r.is_cpu_chunk);
    output.records.iter().position(|r| !r.is_cpu_chunk) < last_cpu
}

/// Every field on which two records disagree, each with both values: all of them rather than
/// `record_digest::first_difference`'s first, since nothing here says which arm built the rest
/// from a wrong one.
fn record_differences(reference: &RecordDigest, candidate: &RecordDigest) -> Vec<String> {
    let mut differences: Vec<String> = reference
        .rows
        .iter()
        .zip(&candidate.rows)
        .filter(|((field, len_r, hash_r), (_, len_c, hash_c))| {
            is_compared(field) && (len_r != len_c || hash_r != hash_c)
        })
        .map(|((field, len_r, hash_r), (_, len_c, hash_c))| {
            format!("{field}: len {len_r} vs {len_c}, digest {hash_r:#018x} vs {hash_c:#018x}")
        })
        .collect();
    if reference.chunk_index != candidate.chunk_index {
        differences.push(format!(
            "chunk_index: {} vs {}",
            reference.chunk_index, candidate.chunk_index
        ));
    }
    if reference.is_cpu_chunk != candidate.is_cpu_chunk {
        differences.push(format!(
            "is_cpu_chunk: {} vs {}",
            reference.is_cpu_chunk, candidate.is_cpu_chunk
        ));
    }
    for ((field, left), (_, right)) in public_value_fields(&reference.public_values)
        .into_iter()
        .zip(public_value_fields(&candidate.public_values))
    {
        if left != right {
            differences.push(format!("public_values.{field}: {left} vs {right}"));
        }
    }
    differences
}

/// Every difference between the two arms' outputs, the reference's value first, and every reason
/// the comparison would hold vacuously that the outputs alone show.
fn compare(guest: &Guest, reference: &OutputDigest, candidate: &OutputDigest) -> Vec<String> {
    let mut problems = Vec::new();
    if reference.committed_bytes != candidate.committed_bytes {
        let at = reference
            .committed_bytes
            .iter()
            .zip(&candidate.committed_bytes)
            .position(|(r, c)| r != c);
        problems.push(format!(
            "committed_bytes: {} vs {} byte(s), first differing byte at {at:?}",
            reference.committed_bytes.len(),
            candidate.committed_bytes.len()
        ));
    }
    if reference.cycles != candidate.cycles {
        problems.push(format!(
            "cycles: {} vs {}",
            reference.cycles, candidate.cycles
        ));
    }
    if reference.chunks != candidate.chunks {
        problems.push(format!(
            "chunks: {} vs {}",
            reference.chunks, candidate.chunks
        ));
    }
    let order = |output: &OutputDigest| -> Vec<u32> {
        output.reports.iter().map(|r| r.start_chunk).collect()
    };
    if order(reference) != order(candidate) {
        problems.push(format!(
            "report order (start_chunk): {:?} vs {:?}",
            order(reference),
            order(candidate)
        ));
    }
    for (i, (left, right)) in reference.reports.iter().zip(&candidate.reports).enumerate() {
        if left != right {
            problems.push(format!("report {i}: {left:?} vs {right:?}"));
        }
    }
    if !reference
        .reports
        .windows(2)
        .all(|w| w[0].start_chunk < w[1].start_chunk)
    {
        problems.push(format!(
            "the reference's reports are not in chunk order: {:?}",
            order(reference)
        ));
    }
    let kinds = |output: &OutputDigest| -> String {
        output
            .records
            .iter()
            .map(|r| if r.is_cpu_chunk { 'C' } else { 't' })
            .collect()
    };
    if kinds(reference) != kinds(candidate) {
        problems.push(format!(
            "record kinds in order (C: CPU chunk, t: deferred): {} vs {}",
            kinds(reference),
            kinds(candidate)
        ));
    }
    for (i, (left, right)) in reference.records.iter().zip(&candidate.records).enumerate() {
        for difference in record_differences(left, right) {
            problems.push(format!("record {i}: {difference}"));
        }
    }

    // `backfill_final_digests` gives every record carrying a digest the last record's. Both
    // digests are compared on every record above, which proves nothing if they are zero.
    let (Some(last), Some(candidate_last)) = (reference.records.last(), candidate.records.last())
    else {
        // The caller reports no record compared.
        return problems;
    };
    let (last, candidate_last) = (&last.public_values, &candidate_last.public_values);
    if last.committed_value_digest != candidate_last.committed_value_digest {
        problems.push(format!(
            "last record's committed_value_digest: {:?} vs {:?}",
            last.committed_value_digest, candidate_last.committed_value_digest
        ));
    }
    if last.deferred_proofs_digest != candidate_last.deferred_proofs_digest {
        problems.push(format!(
            "last record's deferred_proofs_digest: {:?} vs {:?}",
            last.deferred_proofs_digest, candidate_last.deferred_proofs_digest
        ));
    }
    if last.committed_value_digest.iter().all(|&w| w == 0) {
        problems.push(
            "the last record carries no committed_value_digest, so its comparison is vacuous"
                .to_string(),
        );
    }
    if last.deferred_proofs_digest.iter().any(|&w| w != 0) != guest.defers {
        problems.push(format!(
            "the last record's deferred_proofs_digest is {:?}, and the guest {} deferred proofs",
            last.deferred_proofs_digest,
            if guest.defers { "claims" } else { "claims no" }
        ));
    }
    problems
}

/// One side of a comparison: the name messages give it, and how it emulates a run.
pub struct Arm<'a> {
    pub name: &'static str,
    #[allow(clippy::type_complexity)]
    pub emulate: &'a dyn Fn(
        Arc<Program>,
        &EmulatorStdin<Program, Vec<u8>>,
        EmulatorOpts,
    ) -> Result<EmulationOutput, EmulateError>,
}

/// Runs every run of `guest` down `[reference, candidate]`, prints one line per run and every
/// problem found, and panics if there was any. A run's shape (its chunk count, and where its
/// deferred blocks come out) is read off the reference; `workers` is only printed, each arm
/// carrying its own. After both arms of a run, `audit` adds what their outputs cannot show to the
/// run's problems and returns a suffix for the run's line.
pub fn check_guest(
    guest: &Guest,
    workers: NonZeroUsize,
    arms: [Arm<'_>; 2],
    audit: impl Fn(&mut Vec<String>) -> String,
) {
    let mut failures = Vec::new();
    let mut records_compared = 0;
    let runs = (guest.runs)();
    let run_count = runs.len();
    for run in runs {
        let label = format!("{} @ chunk {}", guest.name, run.chunk_size);
        let program = program(guest.elf);
        let stdin = stdin(&run.stdin);
        let opts = opts(run.chunk_size);
        let outputs = arms
            .each_ref()
            .map(|arm| (arm.emulate)(program.clone(), &stdin, opts).map(reduce));
        let (reference, candidate) = match outputs {
            [Ok(reference), Ok(candidate)] => (reference, candidate),
            outputs => {
                for (arm, output) in arms.iter().zip(outputs) {
                    if let Err(err) = output {
                        println!("[{label}] FAIL: the {} arm: {err}", arm.name);
                        failures.push(format!("[{label}] the {} arm: {err}", arm.name));
                    }
                }
                continue;
            }
        };

        let compared = reference.records.len().min(candidate.records.len());
        records_compared += compared;
        let mut problems = compare(guest, &reference, &candidate);
        if compared == 0 {
            problems.push("no record compared".to_string());
        }
        if reference.chunks < run.at_least_chunks {
            problems.push(format!(
                "{} chunk(s), short of the {} this run is there to reach",
                reference.chunks, run.at_least_chunks
            ));
        }
        let early = has_early_block(&reference);
        if early != run.early_block {
            problems.push(format!(
                "a deferred block comes out before the last chunk: {early}, where this run pins {}",
                run.early_block
            ));
        }
        let suffix = audit(&mut problems);
        println!(
            "[{label}] {compared} record(s) compared ({} vs {} emitted), {} chunk(s), {} \
             cycle(s), {workers} worker(s){suffix}",
            reference.records.len(),
            candidate.records.len(),
            reference.chunks,
            reference.cycles,
        );
        for problem in problems {
            println!("[{label}] FAIL: {problem}");
            failures.push(format!("[{label}] {problem}"));
        }
    }
    println!(
        "[{}] {run_count} run(s), {records_compared} record(s) compared, {} problem(s)",
        guest.name,
        failures.len()
    );
    let [reference, candidate] = arms.map(|arm| arm.name);
    assert!(
        failures.is_empty(),
        "the {candidate} arm and the {reference} arm disagree, or the comparison is vacuous; {} \
         problem(s), each giving the {reference} arm's value first:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
