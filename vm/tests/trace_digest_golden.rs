//! Every chip's main trace on five record-parity guests, pinned to `trace_digests.txt`, from the
//! execution history.
//!
//! The local-memory windows, the chunk's and each precompile event's, are sorted first, as
//! `record_digest_golden` sorts them: they are drained from hash maps, whose layout is not the same
//! on every target. With that, and LessThan digested as a row multiset, the file holds on any
//! machine.
//!
//! To rewrite the file after an intended change to a trace:
//!   TRACE_DIGESTS_REWRITE=1 cargo test --release -p pico-vm --test trace_digest_golden

use std::path::PathBuf;

use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use pico_vm::{
    chips::chips::riscv_memory::event::MemoryLocalEvent,
    emulator::riscv::{
        record::EmulationRecord, record_digest::digest_words,
        syscalls::precompiles::PrecompileEvent,
    },
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::chip::MetaChip,
    mle::machine::riscv::{air_id, air_name, build_ctx, Kb},
};

// Only the guests and their runs: the comparison in there is between two emulation paths.
#[allow(dead_code)]
#[path = "common/record_parity.rs"]
mod record_parity;
#[path = "common/trace_source.rs"]
mod trace_source;
use record_parity::GUESTS;
use trace_source::history_records;

const DIGESTS: &str = "trace_digests.txt";
const REWRITE: &str = "TRACE_DIGESTS_REWRITE";
const PINNED_GUESTS: [&str; 5] = ["fib", "ed25519", "poseidon2", "aggregator", "bls12381-fp"];

/// A run's differing lines past this many are counted, not listed.
const LISTED: usize = 16;

const HEADER: &str = "\
# Every chip's main trace on five record-parity guests, from the execution history, with the
# local-memory windows sorted first.
# guest\tchunk_size\trecord\tchip\trows\tcols\tdigest_of\tdigest
# digest_of is `cells` (every cell in row order) or, for LessThan, `row_multiset` (its rows
# sorted, then every cell). Rewrite with TRACE_DIGESTS_REWRITE=1, never by hand.
";

type Chips = [MetaChip<Kb, RiscvChipType<Kb>>];

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join(DIGESTS)
}

/// Windows in a total order: the maps they are drained from iterate in no fixed one.
fn sort_windows(windows: &mut [MemoryLocalEvent]) {
    windows.sort_unstable_by_key(|w| {
        let (i, f) = (w.initial_mem_access, w.final_mem_access);
        (
            w.addr,
            i.chunk,
            i.timestamp,
            i.value,
            f.chunk,
            f.timestamp,
            f.value,
        )
    });
}

fn local_mem_access_mut(event: &mut PrecompileEvent) -> &mut Vec<MemoryLocalEvent> {
    match event {
        PrecompileEvent::ShaExtend(e) => &mut e.local_mem_access,
        PrecompileEvent::ShaCompress(e) => &mut e.local_mem_access,
        PrecompileEvent::KeccakPermute(e) => &mut e.local_mem_access,
        PrecompileEvent::EdDecompress(e) => &mut e.local_mem_access,
        PrecompileEvent::EdAdd(e)
        | PrecompileEvent::Secp256k1Add(e)
        | PrecompileEvent::Secp256r1Add(e)
        | PrecompileEvent::Bn254Add(e)
        | PrecompileEvent::Bls12381Add(e) => &mut e.local_mem_access,
        PrecompileEvent::Secp256k1Double(e)
        | PrecompileEvent::Secp256r1Double(e)
        | PrecompileEvent::Bn254Double(e)
        | PrecompileEvent::Bls12381Double(e) => &mut e.local_mem_access,
        PrecompileEvent::Secp256k1Decompress(e)
        | PrecompileEvent::Secp256r1Decompress(e)
        | PrecompileEvent::K256Decompress(e)
        | PrecompileEvent::Bls12381Decompress(e) => &mut e.local_mem_access,
        PrecompileEvent::Bn254Fp(e)
        | PrecompileEvent::Bls12381Fp(e)
        | PrecompileEvent::Secp256k1Fp(e) => &mut e.local_mem_access,
        PrecompileEvent::Bn254Fp2AddSub(e) | PrecompileEvent::Bls12381Fp2AddSub(e) => {
            &mut e.local_mem_access
        }
        PrecompileEvent::Bn254Fp2Mul(e) | PrecompileEvent::Bls12381Fp2Mul(e) => {
            &mut e.local_mem_access
        }
        PrecompileEvent::Uint256Mul(e) => &mut e.local_mem_access,
        PrecompileEvent::Poseidon2Permute(e) => &mut e.local_mem_access,
    }
}

fn with_windows_sorted(mut record: EmulationRecord) -> EmulationRecord {
    sort_windows(&mut record.cpu_local_memory_access);
    for events in record.precompile_events.events.values_mut() {
        for (_, event) in events.iter_mut() {
            sort_windows(local_mem_access_mut(event));
        }
    }
    record
}

fn canonical(trace: &RowMajorMatrix<Kb>) -> impl Iterator<Item = u32> + '_ {
    trace.values.iter().map(|cell| cell.as_canonical_u32())
}

/// Every cell in row order.
fn cells_digest(trace: &RowMajorMatrix<Kb>) -> u64 {
    digest_words(canonical(trace))
}

/// The rows sorted, then every cell. LessThan's rows follow the CPU chip's runs, whose length
/// follows the core count, so only their multiset is the same on every machine.
fn row_multiset_digest(trace: &RowMajorMatrix<Kb>) -> u64 {
    let cells: Vec<u32> = canonical(trace).collect();
    let mut rows: Vec<&[u32]> = cells.chunks(trace.width.max(1)).collect();
    rows.sort_unstable();
    digest_words(rows.into_iter().flatten().copied())
}

/// One line per active chip of `record`, traced as the prover traces it in dev mode.
fn trace_lines(chips: &Chips, prefix: &str, record: &EmulationRecord) -> Vec<String> {
    build_ctx(chips, record, false)
        .per_trace
        .into_iter()
        .map(|(id, air)| {
            let trace = air.common_main;
            let (digest_of, digest) = if id == air_id::LT {
                ("row_multiset", row_multiset_digest(&trace))
            } else {
                ("cells", cells_digest(&trace))
            };
            format!(
                "{prefix}\t{}\t{}\t{}\t{digest_of}\t{digest:016x}",
                air_name(id).unwrap_or("an unnamed air"),
                trace.values.len() / trace.width.max(1),
                trace.width
            )
        })
        .collect()
}

#[test]
fn every_chip_traces_to_its_pinned_digest_from_history() {
    let rewrite = std::env::var(REWRITE).is_ok_and(|value| value == "1");
    let chips = RiscvChipType::<Kb>::all_chips();
    let mut actual = Vec::new();
    let mut problems = Vec::new();
    for name in PINNED_GUESTS {
        let guest = GUESTS
            .iter()
            .find(|guest| guest.name == name)
            .unwrap_or_else(|| panic!("no guest {name}"));
        let (mut cpu_chunks, mut deferred) = (0, 0);
        for run in guest.runs() {
            let mut index = 0;
            history_records(guest.elf, &run, |record| {
                let prefix = format!("{name}\t{}\t{index}", run.chunk_size);
                index += 1;
                let record = with_windows_sorted(record);
                if record.is_cpu_chunk {
                    assert!(record.history.is_some(), "a CPU chunk has a history");
                    cpu_chunks += 1;
                } else {
                    assert!(record.history.is_none(), "a deferred record has no history");
                    deferred += 1;
                }
                actual.extend(trace_lines(&chips, &prefix, &record));
            });
        }
        println!("{name}: {cpu_chunks} CPU chunk(s) from history, {deferred} deferred");
        if cpu_chunks == 0 {
            problems.push(format!("{name}: no CPU chunk"));
        }
    }

    if rewrite {
        std::fs::write(path(), format!("{HEADER}{}\n", actual.join("\n")))
            .expect("write the trace digests");
        println!("wrote {} line(s) to {DIGESTS}", actual.len());
    } else {
        let pinned = std::fs::read_to_string(path()).expect("read the trace digests");
        let pinned: Vec<&str> = pinned
            .lines()
            .filter(|line| !line.starts_with('#'))
            .collect();
        let differing: Vec<String> = pinned
            .iter()
            .zip(&actual)
            .filter(|(left, right)| *left != right)
            .map(|(left, right)| format!("pinned {left}, now {right}"))
            .collect();
        if pinned.len() != actual.len() {
            problems.push(format!(
                "{} pinned line(s), {} now",
                pinned.len(),
                actual.len()
            ));
        }
        let unlisted = differing.len().saturating_sub(LISTED);
        problems.extend(differing.into_iter().take(LISTED));
        if unlisted > 0 {
            problems.push(format!("and {unlisted} more differing line(s)"));
        }
        println!("{} line(s) compared", actual.len());
    }

    for problem in &problems {
        println!("FAIL: {problem}");
    }
    assert!(
        problems.is_empty(),
        "{} problem(s):\n{}",
        problems.len(),
        problems.join("\n")
    );
}
