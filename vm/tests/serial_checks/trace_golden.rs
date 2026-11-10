//! Every chip's main trace on five record-parity guests, pinned to `trace_digests.txt`, from the
//! execution history.
//!
//! The local-memory windows, the chunk's and each precompile event's, are sorted first, as the
//! record golden sorts them: they are drained from hash maps, whose layout is not the same on every
//! target. With that, and LessThan digested as a row multiset, the file holds on any machine.

use std::path::PathBuf;

use p3_field::PrimeField32;
use p3_matrix::dense::RowMajorMatrix;
use pico_vm::{
    emulator::riscv::{record::EmulationRecord, record_digest::digest_words},
    instances::chiptype::riscv_chiptype::RiscvChipType,
    machine::chip::MetaChip,
    mle::machine::riscv::{air_id, air_name, build_ctx_augmented, Kb},
};

use crate::golden::{in_order, rewrite_section, section};

const DIGESTS: &str = "trace_digests.txt";
const REWRITE: &str = "TRACE_DIGESTS_REWRITE";
/// `bls12381-fp`'s are the only pinned traces of the BLS12-381 field, quadratic-field multiply,
/// point add and double, and 256-bit modular multiply chips, and no other record-parity guest
/// reaches the quadratic-field multiply.
const PINNED_GUESTS: [&str; 5] = ["fib", "ed25519", "poseidon2", "aggregator", "bls12381-fp"];

/// A guest's differing lines past this many are counted, not listed.
const LISTED: usize = 16;

const HEADER: &str = "\
# Every chip's main trace on five record-parity guests, from the execution history, with the
# local-memory windows sorted first.
# guest\tchunk_size\trecord\tchip\trows\tcols\tdigest_of\tdigest
# digest_of is `cells` (every cell in row order) or, for LessThan, `row_multiset` (its rows
# sorted, then every cell). Rewrite with TRACE_DIGESTS_REWRITE=1, never by hand.
";

pub type Chips = [MetaChip<Kb, RiscvChipType<Kb>>];

fn path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join(DIGESTS)
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

/// One line per active chip of `augmented`, traced as the prover traces it in dev mode.
fn trace_lines(chips: &Chips, prefix: &str, augmented: EmulationRecord) -> Vec<String> {
    build_ctx_augmented(chips, augmented, false)
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

/// One pinned guest's traces against its lines of `trace_digests.txt`.
pub struct Check {
    guest: &'static str,
    lines: Vec<String>,
    problems: Vec<String>,
    cpu_chunks: usize,
    deferred: usize,
}

impl Check {
    /// The check of `guest`, if its traces are pinned.
    pub fn of(guest: &'static str) -> Option<Self> {
        PINNED_GUESTS.contains(&guest).then(|| Self {
            guest,
            lines: Vec::new(),
            problems: Vec::new(),
            cpu_chunks: 0,
            deferred: 0,
        })
    }

    /// Before the record is augmented: a CPU chunk carries its history, and a deferred record
    /// none.
    pub fn history(&mut self, record: &EmulationRecord) {
        if record.is_cpu_chunk {
            if record.history.is_none() {
                self.problems.push("a CPU chunk has no history".to_string());
            }
            self.cpu_chunks += 1;
        } else {
            if record.history.is_some() {
                self.problems
                    .push("a deferred record has a history".to_string());
            }
            self.deferred += 1;
        }
    }

    /// The traces of a record the extra-record pass has augmented, its windows already sorted.
    pub fn record(&mut self, chips: &Chips, prefix: &str, augmented: EmulationRecord) {
        self.lines.extend(trace_lines(chips, prefix, augmented));
    }

    pub fn finish(mut self) -> Vec<String> {
        let guest = self.guest;
        println!(
            "{guest}: {} CPU chunk(s) from history, {} deferred",
            self.cpu_chunks, self.deferred
        );
        if self.cpu_chunks == 0 {
            self.problems.push(format!("{guest}: no CPU chunk"));
        }
        if std::env::var(REWRITE).is_ok_and(|value| value == "1") {
            rewrite_section(&path(), HEADER, &PINNED_GUESTS, guest, &self.lines);
            println!("wrote {} line(s) of {guest} to {DIGESTS}", self.lines.len());
            return self.problems;
        }
        let file = std::fs::read_to_string(path()).expect("read the trace digests");
        let pinned: Vec<&str> = section(&file, guest).map(|(_, line)| line).collect();
        let differing: Vec<String> = pinned
            .iter()
            .zip(&self.lines)
            .filter(|(left, right)| *left != right)
            .map(|(left, right)| format!("pinned {left}, now {right}"))
            .collect();
        if pinned.len() != self.lines.len() {
            self.problems.push(format!(
                "{guest}: {} pinned line(s), {} now",
                pinned.len(),
                self.lines.len()
            ));
        }
        let unlisted = differing.len().saturating_sub(LISTED);
        self.problems.extend(differing.into_iter().take(LISTED));
        if unlisted > 0 {
            self.problems
                .push(format!("and {unlisted} more differing line(s)"));
        }
        println!("{guest}: {} trace line(s) compared", self.lines.len());
        self.problems
    }
}

/// `trace_digests.txt` holds only the pinned guests' lines, in the order the guests run: what a
/// rewrite of every pinned guest writes, but for its comment lines.
pub fn check_file_layout() {
    let file = std::fs::read_to_string(path()).expect("read the trace digests");
    let body = |text: &str| -> Vec<String> {
        text.lines()
            .filter(|line| !line.starts_with('#'))
            .map(str::to_owned)
            .collect()
    };
    let (pinned, rebuilt) = (body(&file), body(&in_order(&file, HEADER, &PINNED_GUESTS)));
    if let Some((n, (pinned, rebuilt))) = pinned
        .iter()
        .zip(&rebuilt)
        .enumerate()
        .find(|(_, (pinned, rebuilt))| pinned != rebuilt)
    {
        panic!(
            "{DIGESTS} line {} past its comments: {pinned:?}, where each pinned guest's lines in \
             turn give {rebuilt:?}. Rewrite it with {REWRITE}=1.",
            n + 1
        );
    }
    assert_eq!(
        pinned.len(),
        rebuilt.len(),
        "{DIGESTS}'s lines past its comments, and each pinned guest's lines in turn"
    );
}
