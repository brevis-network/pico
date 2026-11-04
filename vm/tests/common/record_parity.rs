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
//! Each arm hands its records over one at a time, and each is reduced to those digests as it comes
//! and dropped: a whole run of the sha2 or BLS12-381 field guest's records is gigabytes, more than
//! a CI runner has.

use std::{num::NonZeroUsize, sync::Arc};

use pico_vm::{
    compiler::riscv::{
        compiler::{Compiler, SourceType},
        opcode::Opcode,
        program::Program,
    },
    configs::stark_config::KoalaBearPoseidon2,
    emulator::{
        opts::{EmulatorOpts, ReplayWorkers, SnapshotMainMode},
        record::RecordBehavior,
        riscv::{
            public_values::PublicValues,
            record::EmulationRecord,
            record_digest::{field_digests, is_compared},
            syscalls::SyscallCode,
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
/// Chains SHA-256 66 000 times from the bytes it reads.
const SHA2_ELF: &[u8] = include_bytes!("../../../perf/bench_data/rv64/sha2-elf");
/// SHA3-256 of the bytes it reads.
const SHA3_ELF: &[u8] = include_bytes!("../../../perf/bench_data/rv64/sha3-elf");
/// Keccak-256 of the bytes it reads.
const TINY_KECCAK_ELF: &[u8] = include_bytes!("../../../perf/bench_data/rv64/tiny-keccak-elf");
/// secp256k1 point adds and doubles, and one Keccak; reads nothing.
const K256_ELF: &[u8] = include_bytes!("../../../perf/bench_data/rv64/k256-elf");
/// BN254 base and quadratic field arithmetic; reads nothing.
const BN254_FP_ELF: &[u8] = include_bytes!("../../../perf/bench_data/rv64/bn254-fp-elf");
/// A BLS12-381 point decompress, add and doubles; reads nothing.
const BLS12381_WS_ELF: &[u8] =
    include_bytes!("../../../perf/bench_data/rv64/bls12381-elf-ws-add-double-decompress");
/// A BN254 point add and doubles; reads nothing.
const BN254_WS_ELF: &[u8] = include_bytes!("../../../perf/bench_data/rv64/bn254-elf-ws-add-double");

/// One chunk holds every run below but the BLS12-381 field, BN254 field and SHA-256 guests'.
pub const WHOLE: u32 = 1 << 22;
/// A size at which fib(10)'s eight COMMIT ecalls would straddle a chunk boundary if a chunk could
/// be cut while a commit is in flight.
const COMMIT_SPLITTING_CHUNK: u32 = 9500;
/// Many more chunks than workers, so the workers finish out of order and their reports have to
/// be put back in order.
const MANY_CHUNKS: u32 = 17;
/// A size at which the event limit closes six of the Poseidon2 guest's chunks right after a
/// `POSEIDON2_PERMUTE`, each only because the permute topped the chunk's split budget up by the
/// words it reads and writes beyond the dwords covering them (`add_syscall_memory_events`, 8 + 8):
/// without the top-up those cuts land later. Two of them, late in the run, leave the global-lookup
/// count exactly at its threshold, so a top-up short by one event moves them.
const POSEIDON2_BUDGET_CHUNK: u32 = 952;

/// A guest both suites compare on. `name` is `perf/aot/record_parity.sh`'s argument, and the ELF
/// is `perf/bench_data/rv64/<name>-elf` but for the two `-ws` guests, whose constants name theirs
/// (and `record_parity.sh`'s `elf_of`).
pub struct Guest {
    pub name: &'static str,
    pub elf: &'static [u8],
    /// The guest claims deferred proofs, so its final deferred digest is nonzero.
    defers: bool,
    runs: fn() -> Vec<Run>,
}

/// One comparison: an input, and a chunk size small enough to reach `at_least_chunks` chunks.
pub struct Run {
    pub stdin: Vec<Vec<u8>>,
    pub chunk_size: u32,
    at_least_chunks: u32,
    /// A full deferred block comes out between two CPU chunks, not only after the last.
    early_block: bool,
    /// The run is there to put a `POSEIDON2_PERMUTE` at a cut, and fails unless some CPU chunk
    /// ends on one.
    permute_at_cut: bool,
}

impl Guest {
    /// Every run both suites compare this guest on, in order.
    pub fn runs(&self) -> Vec<Run> {
        (self.runs)()
    }
}

pub const GUESTS: [Guest; 12] = [
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
    Guest {
        name: "sha2",
        elf: SHA2_ELF,
        defers: false,
        runs: sha2_runs,
    },
    Guest {
        name: "sha3",
        elf: SHA3_ELF,
        defers: false,
        runs: sha3_runs,
    },
    Guest {
        name: "tiny-keccak",
        elf: TINY_KECCAK_ELF,
        defers: false,
        runs: tiny_keccak_runs,
    },
    Guest {
        name: "k256",
        elf: K256_ELF,
        defers: false,
        runs: k256_runs,
    },
    Guest {
        name: "bn254-fp",
        elf: BN254_FP_ELF,
        defers: false,
        runs: bn254_fp_runs,
    },
    Guest {
        name: "bls12381-ws",
        elf: BLS12381_WS_ELF,
        defers: false,
        runs: bls12381_ws_runs,
    },
    Guest {
        name: "bn254-ws",
        elf: BN254_WS_ELF,
        defers: false,
        runs: bn254_ws_runs,
    },
];

/// The guests a suite whose one test walks every guest runs: all of [`GUESTS`], narrowed to the
/// comma-separated names `PARITY_GUESTS` lists and stripped of those `PARITY_SKIP_GUESTS` lists,
/// either unset or empty meaning no narrowing. CI splits such a suite across jobs by guest. A name
/// that is no guest panics, and so does a selection left empty: neither may pass as a run that
/// compared nothing.
// The suites with a test per guest select by test name and never call it.
#[allow(dead_code)]
pub fn selected_guests() -> Vec<&'static Guest> {
    let listed = |var: &str| -> Vec<String> {
        let value = std::env::var(var).unwrap_or_default();
        let names: Vec<String> = value
            .split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(str::to_string)
            .collect();
        for name in &names {
            assert!(
                GUESTS.iter().any(|guest| guest.name == name),
                "{var} names {name}, which is none of {:?}",
                GUESTS.map(|guest| guest.name)
            );
        }
        names
    };
    let (only, skip) = (listed("PARITY_GUESTS"), listed("PARITY_SKIP_GUESTS"));
    let selected: Vec<&Guest> = GUESTS
        .iter()
        .filter(|guest| only.is_empty() || only.iter().any(|name| name == guest.name))
        .filter(|guest| !skip.iter().any(|name| name == guest.name))
        .collect();
    assert!(
        !selected.is_empty(),
        "PARITY_GUESTS and PARITY_SKIP_GUESTS leave no guest to run"
    );
    selected
}

fn run(stdin: Vec<Vec<u8>>, chunk_size: u32, at_least_chunks: u32) -> Run {
    Run {
        stdin,
        chunk_size,
        at_least_chunks,
        early_block: false,
        permute_at_cut: false,
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
        Run {
            permute_at_cut: true,
            ..run(vec![element(&1u32)], POSEIDON2_BUDGET_CHUNK, MANY_CHUNKS)
        },
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

/// One run: at `WHOLE` its 66 000 rounds already cut into many more chunks than workers, with
/// full deferred blocks out mid-run, and a second, smaller size would emulate all of them again
/// for no shape this one lacks.
fn sha2_runs() -> Vec<Run> {
    vec![Run {
        early_block: true,
        ..run(sha_input(), WHOLE, MANY_CHUNKS)
    }]
}

fn sha3_runs() -> Vec<Run> {
    vec![
        run(sha_input(), WHOLE, 1),
        run(sha_input(), 512, MANY_CHUNKS),
    ]
}

fn tiny_keccak_runs() -> Vec<Run> {
    vec![
        run(keccak_input(), WHOLE, 1),
        run(keccak_input(), 512, MANY_CHUNKS),
    ]
}

fn k256_runs() -> Vec<Run> {
    vec![
        run(Vec::new(), WHOLE, 1),
        run(Vec::new(), 1 << 10, MANY_CHUNKS),
    ]
}

fn bn254_fp_runs() -> Vec<Run> {
    vec![
        run(Vec::new(), WHOLE, 1),
        run(Vec::new(), 1 << 17, MANY_CHUNKS),
    ]
}

fn bls12381_ws_runs() -> Vec<Run> {
    vec![
        run(Vec::new(), WHOLE, 1),
        run(Vec::new(), 1 << 10, MANY_CHUNKS),
    ]
}

fn bn254_ws_runs() -> Vec<Run> {
    vec![run(Vec::new(), WHOLE, 1), run(Vec::new(), 512, MANY_CHUNKS)]
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

/// Every field stated: `EmulatorOpts::default` reads `CHUNK_SIZE` and `CHUNK_BATCH_SIZE`.
pub fn opts(chunk_size: u32) -> EmulatorOpts {
    EmulatorOpts {
        chunk_size,
        chunk_batch_size: 1,
        max_cycles: Some(1 << 32),
        cycle_tracker: false,
        cost_estimator: false,
        snapshot_main: SnapshotMainMode::Interpreter,
        replay_workers: ReplayWorkers::Interpreter,
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

/// 32 bytes of 3, as `vm/examples/patch-testing/patches/{sha2,sha3}` feed their guests.
fn sha_input() -> Vec<Vec<u8>> {
    vec![element(&[3u8; 32])]
}

/// The string `vm/examples/common/parse_args.rs` writes for `--elf keccak` at its default `--n`.
fn keccak_input() -> Vec<Vec<u8>> {
    vec![element(&"x".repeat(10))]
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
    ends_on_permute: bool,
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

impl RecordDigest {
    fn of(record: &EmulationRecord) -> Self {
        Self {
            is_cpu_chunk: record.is_cpu_chunk,
            ends_on_permute: ends_on_permute(record),
            chunk_index: record.chunk_index(),
            public_values: record.public_values,
            rows: field_digests(record),
        }
    }
}

/// `output` with `records`, the digests of the records its arm handed over, or of the records it
/// returned when it handed none over.
fn reduce(output: EmulationOutput, mut records: Vec<RecordDigest>) -> OutputDigest {
    assert!(
        records.is_empty() || output.records.is_empty(),
        "an arm both handed records over and returned some"
    );
    records.extend(output.records.iter().map(RecordDigest::of));
    OutputDigest {
        records,
        chunks: output.chunks,
        committed_bytes: output.committed_bytes,
        cycles: output.cycles,
        reports: output.reports,
    }
}

/// Whether the record's last CPU step is a `POSEIDON2_PERMUTE` ecall: the syscall that ecall sent
/// is the record's last, at the same clk.
fn ends_on_permute(record: &EmulationRecord) -> bool {
    let steps = record.cpu_steps();
    steps.len().checked_sub(1).is_some_and(|index| {
        let last = steps.get(index);
        last.instruction.opcode == Opcode::ECALL
            && record.syscalls().last().is_some_and(|event| {
                event.clk == last.clk
                    && event.syscall_id == SyscallCode::POSEIDON2_PERMUTE.syscall_id()
            })
    })
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
    /// Emulates a run, handing each record to the callback in emission order and returning an
    /// output with none, or, for an arm that has to hold the run whole anyway, returning them all
    /// and calling the callback never.
    #[allow(clippy::type_complexity)]
    pub emulate: &'a dyn Fn(
        Arc<Program>,
        &EmulatorStdin<Program, Vec<u8>>,
        EmulatorOpts,
        &mut (dyn FnMut(EmulationRecord) + Send),
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
    let runs = guest.runs();
    let run_count = runs.len();
    for run in runs {
        let label = format!("{} @ chunk {}", guest.name, run.chunk_size);
        let program = program(guest.elf);
        let stdin = stdin(&run.stdin);
        let opts = opts(run.chunk_size);
        let outputs = arms.each_ref().map(|arm| {
            let mut records = Vec::new();
            let output = (arm.emulate)(program.clone(), &stdin, opts, &mut |record| {
                records.push(RecordDigest::of(&record))
            });
            output.map(|output| reduce(output, records))
        });
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
        if run.permute_at_cut
            && !reference
                .records
                .iter()
                .any(|r| r.is_cpu_chunk && r.ends_on_permute)
        {
            problems.push(
                "no CPU chunk ends on a POSEIDON2_PERMUTE ecall, which this run is there to put at \
                 a cut: the guest or the split thresholds moved it, so pick its chunk size again"
                    .to_string(),
            );
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
