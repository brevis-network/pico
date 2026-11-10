//! The byte chip's trace, built by writing each lookup into its row, against the trace the
//! per-row scan of every lookup builds: over every record of the record-parity guests that carries
//! a byte lookup, the way the prover reads it, after the chips' `extra_record` pass has raised the
//! byte lookups; over a hand-built lookup set that reaches every opcode, every `BitRange` width and
//! the edges of the table; and over no lookup at all.

use std::borrow::{Borrow, BorrowMut};

use hashbrown::HashMap;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::{IndexedParallelIterator, ParallelIterator, ParallelSliceMut};
use pico_vm::{
    chips::chips::byte::{
        columns::{
            ByteMultCols, BytePreprocessedCols, NUM_BYTE_MULT_COLS, NUM_BYTE_PREPROCESSED_COLS,
        },
        event::ByteLookupEvent,
        traces::{byte_lookup_row, NUM_ROWS},
        ByteChip,
    },
    compiler::riscv::opcode::ByteOpcode,
    emulator::riscv::record::EmulationRecord,
    machine::chip::ChipBehavior,
    mle::machine::riscv::Kb,
};

type Lookups = HashMap<ByteLookupEvent, usize>;

/// The rule the scan tested every row against, kept as it was written.
fn scan_row(lookup: &ByteLookupEvent) -> usize {
    if lookup.opcode == ByteOpcode::BitRange && lookup.a2 == 16 {
        ((lookup.b as usize) << 8) + lookup.c as usize
    } else if lookup.opcode == ByteOpcode::BitRange && lookup.a2 < 16 {
        let base = 1usize << 16;
        base + ((lookup.b as usize) << 8) + lookup.c as usize + (1usize << lookup.a2 as usize)
    } else {
        ((lookup.b as usize) << 8) + lookup.c as usize
    }
}

/// Every row tests every lookup.
fn scanned_trace(lookups: &Lookups) -> RowMajorMatrix<Kb> {
    let mut values = vec![Kb::ZERO; NUM_BYTE_MULT_COLS * NUM_ROWS];
    let lookups: Vec<_> = lookups.iter().collect();
    values
        .par_chunks_mut(NUM_BYTE_MULT_COLS)
        .enumerate()
        .for_each(|(row_idx, row)| {
            for (lookup, mult) in lookups.iter() {
                if row_idx == scan_row(lookup) {
                    let cols: &mut ByteMultCols<Kb> = row.borrow_mut();
                    cols.multiplicities[lookup.opcode as usize] += Kb::from_usize(**mult);
                }
            }
        });
    RowMajorMatrix::new(values, NUM_BYTE_MULT_COLS)
}

fn scattered_trace(record: &EmulationRecord) -> RowMajorMatrix<Kb> {
    ByteChip::<Kb>::default().generate_main(record, &mut EmulationRecord::default())
}

/// A record holding only `lookups`.
fn record_with_lookups(lookups: Lookups) -> EmulationRecord {
    EmulationRecord {
        byte_lookups: lookups,
        ..Default::default()
    }
}

/// The first differing cell, if any, rather than 1.4 million field elements.
fn trace_difference(
    what: &str,
    scattered: &RowMajorMatrix<Kb>,
    scanned: &RowMajorMatrix<Kb>,
) -> Option<String> {
    if (scattered.width, scattered.values.len()) != (scanned.width, scanned.values.len()) {
        return Some(format!(
            "{what}: width and cells {:?} scattered, {:?} scanned",
            (scattered.width, scattered.values.len()),
            (scanned.width, scanned.values.len())
        ));
    }
    let at = scattered
        .values
        .iter()
        .zip(&scanned.values)
        .position(|(got, want)| got != want)?;
    Some(format!(
        "{what}: row {} column {}: scattered {}, scanned {}",
        at / NUM_BYTE_MULT_COLS,
        at % NUM_BYTE_MULT_COLS,
        scattered.values[at],
        scanned.values[at]
    ))
}

fn assert_same_trace(what: &str, scattered: &RowMajorMatrix<Kb>, scanned: &RowMajorMatrix<Kb>) {
    if let Some(difference) = trace_difference(what, scattered, scanned) {
        panic!("{difference}");
    }
}

fn cell_sum(trace: &RowMajorMatrix<Kb>) -> u64 {
    trace
        .values
        .iter()
        .map(|cell| cell.as_canonical_u32() as u64)
        .sum()
}

/// One guest's byte traces, over every record of every run.
#[derive(Default)]
pub struct Check {
    problems: Vec<String>,
    /// The run in progress: records, those carrying a lookup, which are the ones compared, and
    /// lookups.
    records: usize,
    with_lookups: usize,
    lookups_seen: usize,
}

impl Check {
    /// The byte trace of a record the extra-record pass has augmented. Its lookups are taken out
    /// for the comparison and put back. A record with none is counted and not traced: both of its
    /// traces are the table's height of zeros, which `scatter_matches_scan_on_no_lookups` compares.
    pub fn record(&mut self, run: &str, augmented: &mut EmulationRecord) {
        let at = format!("{run} record {}", self.records);
        self.records += 1;
        if augmented.byte_lookups.is_empty() {
            return;
        }
        let record = record_with_lookups(std::mem::take(&mut augmented.byte_lookups));
        let scattered = scattered_trace(&record);
        self.problems.extend(trace_difference(
            &at,
            &scattered,
            &scanned_trace(&record.byte_lookups),
        ));

        // Independent of the scan: no lookup falls off the table, so the trace holds every
        // multiplicity once.
        let total: usize = record.byte_lookups.values().sum();
        let cells = cell_sum(&scattered);
        if cells != total as u64 {
            self.problems.push(format!(
                "{at}: multiplicities: the trace's cells add to {cells}, the lookups' to {total}"
            ));
        }

        self.with_lookups += 1;
        self.lookups_seen += record.byte_lookups.len();
        augmented.byte_lookups = record.byte_lookups;
    }

    pub fn end_run(&mut self, run: &str) {
        let (records, with_lookups, lookups_seen) = (
            std::mem::take(&mut self.records),
            std::mem::take(&mut self.with_lookups),
            std::mem::take(&mut self.lookups_seen),
        );
        if records == 0 {
            self.problems.push(format!("{run}: no record"));
        }
        if with_lookups == 0 {
            self.problems.push(format!(
                "{run}: no record carried a byte lookup, so no trace was compared"
            ));
        }
        eprintln!(
            "{run}: {records} records, {with_lookups} with a byte lookup and compared, \
             {lookups_seen} lookups"
        );
    }

    pub fn finish(self) -> Vec<String> {
        self.problems
    }
}

fn bit_range(a2: u8, value: u16) -> ByteLookupEvent {
    ByteLookupEvent::new(ByteOpcode::BitRange, 0, a2, (value >> 8) as u8, value as u8)
}

/// Lookups that share a table cell, sit on its corners and its seams, or fall past its end.
fn hand_built_lookups() -> (Lookups, Vec<ByteLookupEvent>) {
    let mut lookups = Lookups::new();
    let mut dropped = Vec::new();
    let corners = [(0u8, 0u8), (0, 255), (255, 0), (255, 255), (1, 1), (7, 200)];

    for opcode in ByteOpcode::all() {
        if opcode == ByteOpcode::BitRange {
            continue;
        }
        for (b, c) in corners {
            // Distinct keys on one cell: the multiplicities must add.
            for (a1, mult) in [(0u16, 3usize), (1, 5), (2, 7)] {
                lookups.insert(ByteLookupEvent::new(opcode, a1, 0, b, c), mult);
            }
        }
    }

    // `a2` is the width: 16 reads the full table, 0..16 the rows after it, and anything wider is
    // read as a plain byte pair.
    for a2 in (0u8..=16).chain([17, 200]) {
        let widest = if a2 >= 16 { u16::MAX } else { (1u16 << a2) - 1 };
        for value in [0, widest] {
            lookups.insert(bit_range(a2, value), a2 as usize + 1);
        }
    }

    // The value is wider than its width says: row 65536 + 65535 + 2^15 is past the table.
    for (a2, value) in [(15u8, u16::MAX), (15, 1 << 15), (14, u16::MAX)] {
        let lookup = bit_range(a2, value);
        assert!(
            scan_row(&lookup) >= NUM_ROWS,
            "{lookup:?} should be past the table"
        );
        lookups.insert(lookup, 11);
        dropped.push(lookup);
    }

    // The value is wider than its width but the row exists: it lands on another width's row,
    // which is the same cell in both traces.
    lookups.insert(bit_range(3, 9), 13);

    (lookups, dropped)
}

#[test]
fn scatter_matches_scan_on_hand_built_lookups() {
    crate::before_any_emulation();
    let (lookups, dropped) = hand_built_lookups();
    let record = record_with_lookups(lookups.clone());
    let scattered = scattered_trace(&record);
    assert_same_trace("hand-built", &scattered, &scanned_trace(&lookups));

    let kept: usize = lookups
        .iter()
        .filter(|(lookup, _)| !dropped.contains(lookup))
        .map(|(_, mult)| mult)
        .sum();
    assert_eq!(
        cell_sum(&scattered),
        kept as u64,
        "a lookup past the table is dropped and every other one is counted once"
    );

    // The last table row is the widest 15-bit value: a row the scan and the scatter both reach.
    let last = bit_range(15, 0x7fff);
    assert_eq!(scan_row(&last), NUM_ROWS - 1);
    let cols: &ByteMultCols<Kb> = scattered.values
        [(NUM_ROWS - 1) * NUM_BYTE_MULT_COLS..NUM_ROWS * NUM_BYTE_MULT_COLS]
        .borrow();
    assert_eq!(
        cols.multiplicities[ByteOpcode::BitRange as usize],
        Kb::from_usize(16)
    );
}

#[test]
fn scatter_matches_scan_on_no_lookups() {
    crate::before_any_emulation();
    let none = Lookups::new();
    let scattered = scattered_trace(&record_with_lookups(none.clone()));
    assert_same_trace("no lookup", &scattered, &scanned_trace(&none));
    assert_eq!(cell_sum(&scattered), 0);
}

/// The scattered row is the scan's row for every operand pair, at the widths that change the rule.
#[test]
fn the_row_rule_is_the_scans() {
    crate::before_any_emulation();
    for opcode in ByteOpcode::all() {
        for a2 in [0u8, 1, 7, 8, 15, 16, 17, 255] {
            for b in 0..=u8::MAX {
                for c in 0..=u8::MAX {
                    let lookup = ByteLookupEvent::new(opcode, 0, a2, b, c);
                    assert_eq!(byte_lookup_row(&lookup), scan_row(&lookup), "{lookup:?}");
                }
            }
        }
    }
}

/// A lookup's row is the row of the preprocessed table that holds its operands, so the trace and
/// the table the byte bus is balanced against cannot drift apart.
#[test]
fn a_lookups_row_holds_its_operands_in_the_preprocessed_table() {
    crate::before_any_emulation();
    let table = ByteChip::<Kb>::preprocess();
    let (lookups, dropped) = hand_built_lookups();
    let mut checked = 0;
    for lookup in lookups.keys().filter(|lookup| !dropped.contains(lookup)) {
        let value = ((lookup.b as u32) << 8) + lookup.c as u32;
        if lookup.opcode == ByteOpcode::BitRange && lookup.a2 < 16 && value >= 1 << lookup.a2 {
            continue;
        }
        let row = byte_lookup_row(lookup);
        let cols: &BytePreprocessedCols<Kb> = table.values
            [row * NUM_BYTE_PREPROCESSED_COLS..(row + 1) * NUM_BYTE_PREPROCESSED_COLS]
            .borrow();
        match lookup.opcode {
            ByteOpcode::BitRange if lookup.a2 <= 16 => {
                assert_eq!(cols.value_u16, Kb::from_u32(value), "{lookup:?}");
                assert_eq!(cols.bits, Kb::from_u8(lookup.a2), "{lookup:?}");
            }
            _ => {
                assert_eq!(cols.b, Kb::from_u8(lookup.b), "{lookup:?}");
                assert_eq!(cols.c, Kb::from_u8(lookup.c), "{lookup:?}");
            }
        }
        checked += 1;
    }
    assert!(checked > 0, "no lookup was checked against the table");
}
